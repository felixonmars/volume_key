/* LUKS volume handling.

Copyright (C) 2009, 2010, 2011 Red Hat, Inc. All rights reserved.
This copyrighted material is made available to anyone wishing to use, modify,
copy, or redistribute it subject to the terms and conditions of the GNU General
Public License v.2.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
Street, Fifth Floor, Boston, MA 02110-1301, USA.

Author: Miloslav Trmač <mitr@redhat.com> */
#include <config.h>

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <glib/gi18n-lib.h>
#include <libcryptsetup.h>

#include "kmip.h"
#include "ui.h"
#include "volume.h"
#include "volume_luks.h"

/* LUKS - specific code */

/* Return an error message for ERR_NO, for g_free (). */
static char *
my_strerror (int err_no)
{
  char *buf;
  size_t size;

  size = 256;
  buf = NULL;
  for (;;)
    {
      int r;

      buf = g_realloc (buf, size);
      r = strerror_r (err_no, buf, size);
      if (r == 0)
	break;
      if (r != ERANGE)
	{
	  g_free (buf);
	  return g_strdup_printf (_("Unknown error %d"), err_no);
	}
      size *= 2;
      g_return_val_if_fail (size != 0, NULL);
    }
  return buf;
}

/* Set ERROR based on libcryptsetup error state after returning RES.
   Use CODE and LAST_LOG_ENTRY. */
static void
error_from_cryptsetup (GError **error, LIBVKError code, int res,
		       char *last_log_entry)
{
  if (last_log_entry != NULL && last_log_entry[0] != '\0')
    g_set_error (error, LIBVK_ERROR, code, "%s", last_log_entry);
  else
    {
      char *s;

      s = my_strerror (-res);
      g_set_error (error, LIBVK_ERROR, code, "%s", s);
      g_free (s);
    }
}

static void
record_cryptsetup_log_entry (int level, const char *msg, void *usrptr)
{
  char **last_log_entry = usrptr;

  if (level == CRYPT_LOG_ERROR)
    {
      g_free (*last_log_entry);
      *last_log_entry = g_strdup (msg);
    }
}

/* Open volume PATH and load its header.
   Set up *LAST_LOG_ENTRY to be updated to the last logged message for the
   device.  The caller must g_free(*LAST_LOG_ENTRY) after closing the device.
   Return the volume, or NULL on error. */
static struct crypt_device *
open_crypt_device (const char *path, char **last_log_entry, GError **error)
{
  struct crypt_device *cd;
  int r;

  *last_log_entry = NULL;
  r = crypt_init (&cd, path);
  if (r < 0)
    goto err;
  crypt_set_log_callback(cd, record_cryptsetup_log_entry, last_log_entry);
  r = crypt_load (cd, CRYPT_LUKS1, NULL);
  if (r < 0)
    goto err_cd;
  return cd;

 err_cd:
  crypt_free (cd);
 err:
  error_from_cryptsetup (error, LIBVK_ERROR_VOLUME_UNKNOWN_FORMAT, r,
			 *last_log_entry);
  g_prefix_error (error, _("Error getting information about volume `%s': "),
		  path);
  g_free (*last_log_entry);
  *last_log_entry = NULL;
  return NULL;
}

/* Clear PASSPHRASE and g_free () it. */
static void
g_free_passphrase (char *passphrase)
{
  memset (passphrase, 0, strlen (passphrase));
  g_free (passphrase);
}

/* Clear KEY with SIZE and g_free () it. */
static void
g_free_key (void *key, size_t size)
{
  memset (key, 0, size);
  g_free (key);
}

/* Replace the key in VOL, if any, by KEY (with size VOL->v.luks->key_bytes) */
static void
luks_replace_key (struct libvk_volume *vol, const void *key)
{
  struct luks_volume *luks;

  luks = vol->v.luks;
  if (luks->key != NULL)
    {
      memset (luks->key, 0, luks->key_bytes);
      g_free (luks->key);
    }
  luks->key = g_memdup (key, luks->key_bytes);
}

/* Replace the passphrase in VOL, if any, by PASSPHRASE */
static void
luks_replace_passphrase (struct libvk_volume *vol, const char *passphrase)
{
  struct luks_volume *luks;

  luks = vol->v.luks;
  if (luks->passphrase != NULL)
    g_free_passphrase (luks->passphrase);
  luks->passphrase = g_strdup (passphrase);
}

/* g_free() LUKS and everything it points to. */
void
luks_volume_free (struct luks_volume *luks)
{
  g_free (luks->cipher_name);
  g_free (luks->cipher_mode);
  if (luks->key != NULL)
    {
      memset (luks->key, 0, luks->key_bytes);
      g_free (luks->key);
    }
  if (luks->passphrase != NULL)
    g_free_passphrase (luks->passphrase);
  g_free (luks);
}

/* Open a LUKS VOL at PATH.
   Return LUKS volume information, or NULL on error. */
struct luks_volume *
luks_volume_open (struct libvk_volume *vol, const char *path, GError **error)
{
  struct luks_volume *luks;
  struct crypt_device *cd;
  char *last_log_entry;
  const char *uuid;

  (void)vol;
  cd = open_crypt_device (path, &last_log_entry, error);
  if (cd == NULL)
    return NULL;
  /* A bit of paranoia */
  uuid = crypt_get_uuid (cd);
  if (strcmp (vol->uuid, uuid) != 0)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_FAILED,
		   _("UUID mismatch between libblkid and libcryptsetup: `%s' "
		     "vs. `%s'"), vol->uuid, uuid);
      crypt_free (cd);
      g_free (last_log_entry);
      return NULL;
    }

  luks = g_new (struct luks_volume, 1);
  luks->cipher_name = g_strdup (crypt_get_cipher (cd));
  luks->cipher_mode = g_strdup (crypt_get_cipher_mode (cd));
  luks->key_bytes = crypt_get_volume_key_size (cd);
  crypt_free (cd);
  g_free (last_log_entry);

  luks->key = NULL;
  luks->passphrase = NULL;
  luks->passphrase_slot = -1;
  return luks;
}

/* Add properties of LUKS, including "secrets" if WITH_SECRETS != 0, to LIST.
   Return an updated list. */
GSList *
luks_volume_dump_properties (GSList *res, const struct luks_volume *luks,
			     int with_secrets)
{
  if (luks->cipher_name != NULL)
    res = add_vp (res, _("LUKS cipher name"), "luks/cipher_name",
		  LIBVK_VP_CONFIGURATION, g_strdup (luks->cipher_name));
  if (luks->cipher_mode != NULL)
    res = add_vp (res, _("LUKS cipher mode"), "luks/cipher_mode",
		  LIBVK_VP_CONFIGURATION, g_strdup (luks->cipher_mode));
  if (luks->key_bytes != 0)
    res = add_vp (res, _("Key size (bits)"), "luks/key_bits",
		  LIBVK_VP_CONFIGURATION,
		  g_strdup_printf ("%zu", 8 * luks->key_bytes));
  if (with_secrets != 0 && luks->key != NULL)
    {
      static const char hex[16] = "0123456789ABCDEF";

      char *s;
      size_t i;

      s = g_malloc (luks->key_bytes * 2 + 1);
      for (i = 0; i < luks->key_bytes; i++)
	{
	  unsigned char b;

	  b = ((unsigned char *)luks->key)[i];
	  s[i * 2] = hex[b >> 4];
	  s[i * 2 + 1] = hex[b & 0x0F];
	}
      s[2 * i] = '\0';
      res = add_vp (res, _("Data encryption key"), "luks/key", LIBVK_VP_SECRET,
		    s);
    }
  if (with_secrets != 0 && luks->passphrase != NULL)
    res = add_vp (res, _("Passphrase"), "luks/passphrase", LIBVK_VP_SECRET,
		  g_strdup (luks->passphrase));
  if (luks->passphrase_slot != -1)
    res = add_vp (res, _("Passphrase slot"), "luks/passphrase_slot",
		  LIBVK_VP_IDENTIFICATION,
		  g_strdup_printf ("%d", luks->passphrase_slot));
  return res;
}

/* Get a "secret" of SECRET_TYPE for LUKS VOL, interacting with the user using
   the provided UI.
   Return 0 if OK, -1 on error. */
int
luks_get_secret (struct libvk_volume *vol, enum libvk_secret secret_type,
		 const struct libvk_ui *ui, GError **error)
{
  struct crypt_device *cd;
  char *last_log_entry, *passphrase;
  void *key;
  size_t key_length;
  int slot;
  unsigned failed;
  char *prompt;

  /* We gather all secrets in any case.  This should be invisible to
     correct callers. */
  switch (secret_type)
    {
    case LIBVK_SECRET_DEFAULT:
    case LIBVK_SECRET_DATA_ENCRYPTION_KEY:
    case LIBVK_SECRET_PASSPHRASE:
      break;
    default:
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_VOLUME_UNSUPPORTED_SECRET,
		   _("Encryption information type unsupported in LUKS"));
      goto err;
    }
  cd = open_crypt_device (vol->path, &last_log_entry, error);
  if (cd == NULL)
    goto err;
  key_length = crypt_get_volume_key_size (cd);
  key = g_malloc (key_length);
  prompt = g_strdup_printf (_("Passphrase for `%s'"), vol->path);
  /* Our only real concern is overflow of the failed counter; limit the
     number of iterations just in case the application programmer is always
     returning the same passphrase from the callback, regardless of the
     failed counter. */
  for (failed = 0; failed < 64; failed++)
    {
      int r;

      passphrase = ui_get_passphrase (ui, prompt, failed, error);
      if (passphrase == NULL)
	goto err_prompt;
      r = crypt_volume_key_get (cd, CRYPT_ANY_SLOT, key, &key_length,
				passphrase, strlen (passphrase));
      if (r >= 0)
	{
	  slot = r;
	  goto got_passphrase;
	}
      g_free_passphrase (passphrase);
      if (r != -EPERM)
	{
	  error_from_cryptsetup (error, LIBVK_ERROR_FAILED, r, last_log_entry);
	  g_prefix_error (error, _("Error getting LUKS data encryption key: "));
	  goto err_prompt;
	}
    }
  g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_FAILED,
	       _("Too many attempts to get a valid passphrase"));
  goto err_prompt;

 got_passphrase:
  vol->v.luks->key_bytes = key_length;
  luks_replace_key (vol, key);
  g_free_key (key, key_length);

  luks_replace_passphrase (vol, passphrase);
  g_free_passphrase (passphrase);
  vol->v.luks->passphrase_slot = slot;
  g_free (prompt);
  crypt_free (cd);
  g_free (last_log_entry);
  return 0;

 err_prompt:
  g_free (prompt);
  g_free_key (key, key_length);
  crypt_free (cd);
  g_free (last_log_entry);
 err:
  return -1;
}

/* Check if PACKET matches VOL, modifying previous comparison result RES.
   Return the comparison result:
   On LIBVK_PACKET_MATCH_MISMATCH set an error message.
   On LIBVK_PACKET_MATCH_UNSURE, if WARNINGS is not NULL, add warning messages
   (char *, for g_free ()) to it. */
enum libvk_packet_match_result
luks_packet_match_volume (const struct libvk_volume *packet,
			  const struct libvk_volume *vol,
			  enum libvk_packet_match_result res,
			  GPtrArray *warnings, GError **error)
{
  const struct luks_volume *p, *v;

  (void)warnings;
  p = packet->v.luks;
  v = vol->v.luks;
  if (p->cipher_name != NULL && strcmp (p->cipher_name, v->cipher_name) != 0)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_PACKET_VOLUME_MISMATCH,
		   _("Cipher name mismatch (packet `%s', volume `%s')"),
		   p->cipher_name, v->cipher_name);
      return LIBVK_PACKET_MATCH_ERROR;
    }
  if (p->cipher_mode != NULL && strcmp (p->cipher_mode, v->cipher_mode) != 0)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_PACKET_VOLUME_MISMATCH,
		   _("Cipher mode mismatch (packet `%s', volume `%s')"),
		   p->cipher_mode, v->cipher_mode);
      return LIBVK_PACKET_MATCH_ERROR;
    }
  if (p->key_bytes != 0 && p->key_bytes != v->key_bytes)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_PACKET_VOLUME_MISMATCH,
		   _("Key size mismatch (packet %zu, volume %zu)"),
		   p->key_bytes, v->key_bytes);
      return LIBVK_PACKET_MATCH_ERROR;
    }
  /* Don't verify the key or passphrase here, it takes a lot of time and it
     will be verified when the key or passphrase will be used. */
  return res;
}

/* Load "secrets" from PACKET, verify them if possible and store them with VOL.
   Return 0 if OK, -1 on error. */
int
luks_load_packet (struct libvk_volume *vol, const struct libvk_volume *packet,
		  GError **error)
{
  if (packet->v.luks->key != NULL)
    {
      struct crypt_device *cd;
      char *last_log_entry;
      int r;

      g_return_val_if_fail (vol->v.luks->key_bytes == packet->v.luks->key_bytes,
			    -1);
      cd = open_crypt_device (vol->path, &last_log_entry, error);
      if (cd == NULL)
	return -1;
      r = crypt_volume_key_verify (cd, packet->v.luks->key,
				   packet->v.luks->key_bytes);
      crypt_free (cd);
      if (r < 0)
	{
	  error_from_cryptsetup (error, LIBVK_ERROR_PACKET_VOLUME_MISMATCH, r,
				 last_log_entry);
	  g_prefix_error (error, _("LUKS data encryption key in packet is "
				   "invalid: "));
	  g_free (last_log_entry);
	  return -1;
	}
      g_free (last_log_entry);
      luks_replace_key (vol, packet->v.luks->key);
    }
  if (packet->v.luks->passphrase != NULL)
    {
      struct crypt_device *cd;
      char *last_log_entry;
      void *key;
      size_t key_size;
      int r;

      cd = open_crypt_device (vol->path, &last_log_entry, error);
      if (cd == NULL)
	return -1;
      key_size = crypt_get_volume_key_size (cd);
      key = g_malloc (key_size);
      r = crypt_volume_key_get (cd, CRYPT_ANY_SLOT, key, &key_size,
				packet->v.luks->passphrase,
				strlen (packet->v.luks->passphrase));
      crypt_free (cd);
      if (r < 0)
	{
	  error_from_cryptsetup (error, LIBVK_ERROR_PACKET_VOLUME_MISMATCH, r,
				 last_log_entry);
	  g_prefix_error (error, _("LUKS passphrase in packet is invalid: "));
	  g_free (last_log_entry);
	  return -1;
	}
      g_free (last_log_entry);
      luks_replace_passphrase (vol, packet->v.luks->passphrase);
      vol->v.luks->passphrase_slot = r;
      if (packet->v.luks->key == NULL)
	{
	  g_return_val_if_fail (vol->v.luks->key_bytes == key_size, -1);
	  luks_replace_key (vol, key);
	}
      g_free_key (key, key_size);
    }
  return 0;
}

/* Apply the "secret" of SECRET_TYPE in PACKET to restore conventional access
   to VOL, using UI to gather more information.
   Return 0 if OK, -1 on error.
   "Restore conventional access" usually means "prompt for a new passphrase". */
int
luks_apply_secret (struct libvk_volume *vol, const struct libvk_volume *packet,
		   enum libvk_secret secret_type, const struct libvk_ui *ui,
		   GError **error)
{
  struct crypt_device *cd;
  char *last_log_entry, *prompt, *prompt2, *error_prompt, *passphrase;
  unsigned failed;
  int res;

  if (secret_type != LIBVK_SECRET_DEFAULT
      && secret_type != LIBVK_SECRET_DATA_ENCRYPTION_KEY)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_VOLUME_UNSUPPORTED_SECRET,
		   _("Encryption information type unsupported in LUKS"));
      goto err;
    }
  if (packet->v.luks->key == NULL)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNEXPECTED_FORMAT,
		   _("Escrow packet does not contain the LUKS data encryption "
		     "key"));
      goto err;
    }

  prompt = g_strdup_printf (_("New passphrase for `%s'"), vol->path);
  prompt2 = g_strdup_printf (_("Repeat new passphrase for `%s'"), vol->path);
  error_prompt = g_strdup_printf (_("Passphrases do not match.  New passphrase "
				    "for `%s'"), vol->path);
  /* Our only real concern is overflow of the failed counter; limit the
     number of iterations just in case the application programmer is always
     returning the same passphrase from the callback, regardless of the
     failed counter. */
  for (failed = 0; failed < 64; failed++)
    {
      char *passphrase2;
      int passphrase_ok;

      passphrase = ui_get_passphrase (ui, failed == 0 ? prompt : error_prompt,
				      failed, error);
      if (passphrase == NULL)
	goto err_prompts;
      /* The repeated passphrase is always considered a first attempt -
	 otherwise src/volume_key.c would prepend "Error, try again". */
      passphrase2 = ui_get_passphrase (ui, prompt2, 0, error);
      if (passphrase2 == NULL)
	goto err_passphrase;
      passphrase_ok = strcmp (passphrase, passphrase2) == 0;
      g_free_passphrase (passphrase2);
      if (passphrase_ok)
	goto got_passphrase;
      g_free_passphrase (passphrase);
    }
  g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_FAILED,
	       _("Too many attempts to get a passphrase"));
  goto err_prompts;

 got_passphrase:
  cd = open_crypt_device (vol->path, &last_log_entry, error);
  if (cd == NULL)
    goto err_passphrase;
  res = crypt_keyslot_add_by_volume_key (cd, CRYPT_ANY_SLOT,
					 packet->v.luks->key,
					 packet->v.luks->key_bytes, passphrase,
					 strlen (passphrase));
  crypt_free (cd);
  if (res < 0)
    {
      error_from_cryptsetup (error, LIBVK_ERROR_FAILED, res, last_log_entry);
      g_prefix_error (error, _("Error adding a LUKS passphrase"));
      g_free (last_log_entry);
      goto err_passphrase;
    }
  g_free (last_log_entry);

  g_return_val_if_fail (vol->v.luks->key_bytes == packet->v.luks->key_bytes,
			-1);
  luks_replace_key (vol, packet->v.luks->key);
  luks_replace_passphrase (vol, passphrase);
  vol->v.luks->passphrase_slot = res;

  g_free_passphrase (passphrase);
  g_free (error_prompt);
  g_free (prompt2);
  g_free (prompt);
  return 0;

 err_passphrase:
  g_free_passphrase (passphrase);
 err_prompts:
  g_free (error_prompt);
  g_free (prompt2);
  g_free (prompt);
 err:
  return -1;
}

/* Add SECRET with SIZE and SECRET_TYPE to LUKS VOLUME.
   Return 0 if OK, -1 on error. */
int
luks_add_secret (struct libvk_volume *vol, enum libvk_secret secret_type,
		 const void *secret, size_t size, GError **error)
{
  struct crypt_device *cd;
  char *last_log_entry;
  int res;

  if (secret_type != LIBVK_SECRET_PASSPHRASE)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_VOLUME_UNSUPPORTED_SECRET,
		   _("Can not add a secret of this type"));
      return -1;
    }
  if (vol->v.luks->key == NULL)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_VOLUME_NEED_SECRET,
		   _("Data encryption key unknown"));
      return -1;
    }
  if (memchr (secret, '\0', size) != NULL)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_VOLUME_INVALID_SECRET,
		   _("The passphrase must be a string"));
      return -1;
    }
  cd = open_crypt_device (vol->path, &last_log_entry, error);
  if (cd == NULL)
    return -1;
  res = crypt_keyslot_add_by_volume_key (cd, CRYPT_ANY_SLOT, vol->v.luks->key,
					 vol->v.luks->key_bytes, secret, size);
  crypt_free (cd);
  if (res < 0)
    {
      error_from_cryptsetup (error, LIBVK_ERROR_FAILED, res, last_log_entry);
      g_prefix_error (error, _("Error adding a LUKS passphrase"));
      g_free (last_log_entry);
      return -1;
    }
  g_free (last_log_entry);

  luks_replace_passphrase (vol, secret);
  vol->v.luks->passphrase_slot = res;
  return 0;
}

/* Add KMIP_ATTR_CRYPTO_ALGORITHM for algorithm NAME to KEY_VALUE if known. */
static void
add_attribute_luks_crypto_algorithm (struct kmip_key_value *key_value,
				     const char *name)
{
  if (strcmp (name, "aes") == 0)
    {
      struct kmip_attribute *a;

      a = g_new (struct kmip_attribute, 1);
      a->name = g_strdup (KMIP_ATTR_CRYPTO_ALGORITHM);
      a->tag = KMIP_TAG_CRYPTO_ALGORITHM;
      a->v.enum_value = KMIP_ALGORITHM_AES;
      g_ptr_array_add (key_value->attributes, a);
    }
  /* Other defined algorithms: "twofish", "serpent", "cast5", "cast6". */
}

/* Add KMIP_ATTR_CRYPTO_PARAMS for LUKS mode NAME to KEY_VALUE if known. */
static void
add_attribute_luks_crypto_params (struct kmip_key_value *key_value,
				  const char *name)
{
  guint32 mode, hash;

  mode = KMIP_LIBVK_ENUM_NONE;
  hash = KMIP_LIBVK_ENUM_NONE;
  if (strcmp (name, "ecb") == 0)
    mode = KMIP_MODE_ECB;
  else if (strcmp (name, "cbc-plain") == 0)
    mode = KMIP_MODE_CBC;
  else if (strncmp (name, "cbc-essiv:", 10) == 0)
    {
      mode = KMIP_MODE_CBC;
      if (strcmp (name + 10, "sha1") == 0)
	hash = KMIP_HASH_SHA_1;
      else if (strcmp (name + 10, "sha256") == 0)
	hash = KMIP_HASH_SHA_256;
      else if (strcmp (name + 10, "sha512") == 0)
	hash = KMIP_HASH_SHA_512;
      /* Another defined algorithm: "ripemd160" */
    }
  if (mode != KMIP_LIBVK_ENUM_NONE || hash != KMIP_LIBVK_ENUM_NONE)
    {
      struct kmip_attribute *a;

      a = g_new (struct kmip_attribute, 1);
      a->name = g_strdup (KMIP_ATTR_CRYPTO_PARAMS);
      a->tag = KMIP_TAG_CRYPTO_PARAMS;
      a->v.crypto_params = g_new (struct kmip_crypto_params, 1);
      a->v.crypto_params->cipher_mode = mode;
      a->v.crypto_params->padding_method = KMIP_LIBVK_ENUM_NONE;
      a->v.crypto_params->hash_algorithm = hash;
      g_ptr_array_add (key_value->attributes, a);
    }
}

/* Create a KMIP packet structure for SECRET in VOL.
   Return the KMIP data on success, NULL no error. */
struct kmip_libvk_packet *
luks_create_escrow_packet (const struct libvk_volume *vol,
			   enum libvk_secret secret_type, GError **error)
{
  struct kmip_libvk_packet *pack;
  struct kmip_key_value *key_value;

  switch (secret_type)
    {
    case LIBVK_SECRET_DEFAULT:
    case LIBVK_SECRET_DATA_ENCRYPTION_KEY:
      if (vol->v.luks->key_bytes == 0 || vol->v.luks->key == NULL)
	{
	  g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_VOLUME_NEED_SECRET,
		       _("Data encryption key unknown"));
	  return NULL;
	}
      pack = volume_create_data_encryption_key_packet (&key_value, vol,
						       vol->v.luks->key,
						       vol->v.luks->key_bytes,
						       error);
      if (pack == NULL)
	return NULL;
      add_attribute_strings (key_value, KMIP_ATTR_LIBVK_LUKS_CIPHER,
			     KMIP_ATTR_LIBVK_LUKS_CIPHER_NAME,
			     vol->v.luks->cipher_name);
      add_attribute_luks_crypto_algorithm (key_value, vol->v.luks->cipher_name);
      add_attribute_strings (key_value, KMIP_ATTR_LIBVK_LUKS_MODE,
			     KMIP_ATTR_LIBVK_LUKS_MODE_NAME,
			     vol->v.luks->cipher_mode);
      add_attribute_luks_crypto_params (key_value, vol->v.luks->cipher_mode);
      break;

    case LIBVK_SECRET_PASSPHRASE:
      if (vol->v.luks->passphrase == NULL)
	{
	  g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_VOLUME_NEED_SECRET,
		       _("Passphrase unknown"));
	  return NULL;
	}
      pack = volume_create_passphrase_packet (&key_value, vol,
					      vol->v.luks->passphrase,
					      strlen (vol->v.luks->passphrase));
      if (vol->v.luks->passphrase_slot != -1)
	{
	  char *s;

	  s = g_strdup_printf ("%d", vol->v.luks->passphrase_slot);
	  add_attribute_strings (key_value, KMIP_ATTR_APP_SPECIFIC,
				 KMIP_AS_LIBVK_PASSPHRASE_SLOT, s);
	  g_free (s);
	}
      break;

    default:
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_VOLUME_UNSUPPORTED_SECRET,
		   _("Encryption information type unsupported in LUKS"));
      return NULL;
    }
  return pack;
}

/* Load volume information from PACK its component KEY_VALUE.
   Return 0 if OK, -1 on error. */
int
luks_parse_escrow_packet (struct libvk_volume *vol,
			  const struct kmip_libvk_packet *pack,
			  const struct kmip_key_value *key_value,
			  GError **error)
{
  const struct kmip_attribute *a;
  const char *s;

  vol->v.luks = g_new0 (struct luks_volume, 1);
  vol->v.luks->passphrase_slot = -1;
  switch (pack->type)
    {
    case KMIP_OBJECT_SYMMETRIC_KEY:
      /* Ignore KMIP_ATTR_CRYPTO_ALGORITHM, KMIP_ATTR_CRYPTO_PARAMS - they can
	 only represent some of the values. */
      s = get_attribute_strings (key_value, KMIP_ATTR_LIBVK_LUKS_CIPHER,
				 KMIP_ATTR_LIBVK_LUKS_CIPHER_NAME, error);
      if (s == NULL)
	goto err;
      vol->v.luks->cipher_name = g_strdup (s);
      s = get_attribute_strings (key_value, KMIP_ATTR_LIBVK_LUKS_MODE,
				 KMIP_ATTR_LIBVK_LUKS_MODE_NAME, error);
      if (s == NULL)
	goto err;
      vol->v.luks->cipher_mode = g_strdup (s);
      a = get_attribute (key_value, KMIP_TAG_CRYPTO_LENGTH,
			 KMIP_ATTR_CRYPTO_LENGTH, error);
      if (a == NULL)
	goto err;
      if (a->v.int32_value <= 0 || a->v.int32_value % 8 != 0)
	{
	  gchar num[sizeof (a->v.int32_value) * CHAR_BIT + 1];

	  g_snprintf (num, sizeof (num), "%" G_GINT32_FORMAT, a->v.int32_value);
	  g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNSUPPORTED_VALUE,
		       _("Unsupported key length %s"), num);
	  goto err;
	}
      {
	G_STATIC_ASSERT (sizeof (gint32) <= sizeof (size_t));
      }
      vol->v.luks->key_bytes = a->v.int32_value / 8;
      if (key_value->v.key != NULL)
	{
	  if (key_value->v.key->len != vol->v.luks->key_bytes)
	    {
	      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_INVALID_INPUT,
			   _("Key length mismatch"));
	      goto err;
	    }
	  vol->v.luks->key = g_memdup (key_value->v.key->data,
				       key_value->v.key->len);
	}
      break;

    case KMIP_OBJECT_SECRET_DATA:
      g_return_val_if_fail (pack->v.secret_data->type
			    == KMIP_SECRET_DATA_PASSWORD, -1);

      s = get_attribute_strings (key_value, KMIP_ATTR_APP_SPECIFIC,
				 KMIP_AS_LIBVK_PASSPHRASE_SLOT, NULL);
      if (s != NULL)
	{
	  char *p;
	  long slot;

	  errno = 0;
	  slot = strtol (s, &p, 10);
	  if (errno != 0 || *p != 0 || p == s || slot < 0 || (int)slot != slot)
	    {
	      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_INVALID_INPUT,
			   _("Invalid slot number `%s'"), s);
	      goto err;
	    }
	  vol->v.luks->passphrase_slot = slot;
	}
      if (key_value->v.bytes.data != NULL)
	{
	  if (memchr (key_value->v.bytes.data, '\0',
		      key_value->v.bytes.len) != 0)
	    {
	      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_INVALID_INPUT,
			   _("NUL byte in passphrase"));
	      goto err;
	    }
	  vol->v.luks->passphrase = g_malloc (key_value->v.bytes.len + 1);
	  memcpy (vol->v.luks->passphrase, key_value->v.bytes.data,
		  key_value->v.bytes.len);
	  vol->v.luks->passphrase[key_value->v.bytes.len] = '\0';
	}
      break;

    default:
      {
	gchar num[sizeof (pack->type) * CHAR_BIT + 1];

	g_snprintf (num, sizeof (num), "%" G_GUINT32_FORMAT, pack->type);
	g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNSUPPORTED_VALUE,
		     _("Unsupported packet type %s"), num);
	goto err;
      }
    }
  return 0;

 err:
  return -1;
}

/* Open VOL using volume format-specific NAME, using "secrets" from PACKET.
   Return 0 if OK, -1 on error.

   NAME is currently always a device-mapper name, please try not to rely on
   it. */
int
luks_open_with_packet (struct libvk_volume *vol,
		       const struct libvk_volume *packet, const char *name,
		       GError **error)
{
  struct crypt_device *cd;
  char *last_log_entry;
  void *to_free;
  const void *key;
  int r;
  size_t key_size;

  cd = open_crypt_device (vol->path, &last_log_entry, error);
  if (cd == NULL)
    goto err;
  if (packet->v.luks->key != NULL)
    {
      key = packet->v.luks->key;
      key_size = vol->v.luks->key_bytes;
      to_free = NULL;
    }
  else if (packet->v.luks->passphrase != NULL)
    {
      key_size = crypt_get_volume_key_size (cd);
      to_free = g_malloc (key_size);
      r = crypt_volume_key_get (cd, CRYPT_ANY_SLOT, to_free, &key_size,
				packet->v.luks->passphrase,
				strlen (packet->v.luks->passphrase));
      if (r < 0)
	{
	  error_from_cryptsetup (error, LIBVK_ERROR_FAILED, r, last_log_entry);
	  g_prefix_error (error, _("Error getting LUKS data encryption key: "));
	  goto err_to_free;
	}
      key = to_free;
    }
  else
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_VOLUME_NEED_SECRET,
		   _("Data encryption key unknown"));
      goto err_cd;
    }

  r = crypt_activate_by_volume_key (cd, name, key, key_size, 0);
  if (r < 0)
    {
      error_from_cryptsetup (error, LIBVK_ERROR_FAILED, r, last_log_entry);
      g_prefix_error (error, _("Error opening LUKS volume: "));
      goto err_to_free;
    }

  if (to_free != NULL)
    g_free_key (to_free, key_size);
  crypt_free (cd);
  g_free (last_log_entry);
  return 0;

 err_to_free:
  if (to_free != NULL)
    g_free_key (to_free, key_size);
 err_cd:
  crypt_free (cd);
  g_free (last_log_entry);
 err:
  return -1;
}
