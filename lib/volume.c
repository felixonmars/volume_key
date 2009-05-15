/* Volume information gathering.

Copyright (C) 2009 Red Hat, Inc. All rights reserved.
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

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <blkid/blkid.h>
#include <glib.h>
#include <glib/gi18n-lib.h>
#include <libcryptsetup.h>

#include "kmip.h"
#include "libvolume_key.h"
#include "ui.h"
#include "volume.h"

/* Utilities */

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
   Use CODE. */
static void
error_from_cryptsetup (GError **error, LIBVKError code, int res)
{
  /* It's not possible to get the error message length from libcryptsetup, just
     guess. */
  char crypt_msg[4096];

  crypt_get_error (crypt_msg, sizeof (crypt_msg));
  if (crypt_msg[0] != '\0')
    g_set_error (error, LIBVK_ERROR, code, "%s", crypt_msg);
  else
    {
      char *s;

      s = my_strerror (-res);
      g_set_error (error, LIBVK_ERROR, code, "%s", s);
      g_free (s);
    }
}

 /* Common KMIP code */

/* Add a "strings" attribute using ATTR_NAME, NAME and VALUE to KEY_VALUE */
static void
add_attribute_strings (struct kmip_key_value *key_value, const char *attr_name,
		       const char *name, const char *value)
{
  struct kmip_attribute *a;

  a = g_new (struct kmip_attribute, 1);
  a->name = g_strdup (attr_name);
  a->tag = KMIP_TAG_APP_SPECIFIC;
  a->v.strings.name = g_strdup (name);
  a->v.strings.value = g_strdup (value);
  g_ptr_array_add (key_value->attributes, a);
}

/* Add volume-format-independent atributes of VOL to KEY_VALUE. */
static void
add_common_volume_attributes (struct kmip_key_value *key_value,
			      const struct libvk_volume *vol)
{
  add_attribute_strings (key_value, KMIP_ATTR_APP_SPECIFIC,
			 KMIP_AS_LIBVK_HOST_NAME, vol->hostname);
  if (vol->uuid != NULL)
    add_attribute_strings (key_value, KMIP_ATTR_APP_SPECIFIC,
			   KMIP_AS_LIBVK_VOLUME_UUID, vol->uuid);
  if (vol->label != NULL)
    add_attribute_strings (key_value, KMIP_ATTR_APP_SPECIFIC,
			   KMIP_AS_LIBVK_VOLUME_LABEL, vol->label);
  add_attribute_strings (key_value, KMIP_ATTR_APP_SPECIFIC,
			 KMIP_AS_LIBVK_VOLUME_FILE, vol->path);
  add_attribute_strings (key_value, KMIP_ATTR_APP_SPECIFIC,
			 KMIP_AS_LIBVK_VOLUME_FORMAT, vol->format);
}

/* Create a KMIP packet structure for VOL that contains a data encryption KEY
   of KEY_BYTES.
   On success return the KMIP data, store the kmip_key_value component to KV.
   Return NULL on error. */
static struct kmip_libvk_packet *
volume_create_data_encryption_key_packet (struct kmip_key_value **kv,
					  const struct libvk_volume *vol,
					  const void *key, size_t key_bytes,
					  GError **error)
{
  struct kmip_libvk_packet *pack;
  struct kmip_key_value *key_value;
  struct kmip_attribute *a;

  key_value = g_new (struct kmip_key_value, 1);
  key_value->type = KMIP_KEY_VALUE_SYMMETRIC_KEY;
  key_value->v.key = g_new (struct kmip_symmetric_key, 1);
  key_value->v.key->data = g_memdup (key, key_bytes);
  key_value->v.key->len = key_bytes;
  key_value->attributes = g_ptr_array_new ();
  add_common_volume_attributes (key_value, vol);
  if (key_bytes > G_MAXINT32 / 8)
    {
      g_set_error(error, LIBVK_ERROR, LIBVK_ERROR_INPUT_OVERFLOW,
		  _("The key is too long"));
      kmip_key_value_free (key_value);
      return NULL;
    }
  a = g_new (struct kmip_attribute, 1);
  a->name = g_strdup (KMIP_ATTR_CRYPTO_LENGTH);
  a->tag = KMIP_TAG_CRYPTO_LENGTH;
  a->v.int32_value = key_bytes * 8;
  g_ptr_array_add (key_value->attributes, a);

  pack = g_new (struct kmip_libvk_packet, 1);
  pack->version = g_new (struct kmip_protocol_version, 1);
  pack->version->major = KMIP_VERSION_MAJOR;
  pack->version->minor = KMIP_VERSION_MINOR;
  pack->type = KMIP_OBJECT_SYMMETRIC_KEY;
  pack->v.symmetric = g_new (struct kmip_object_symmetric_key, 1);
  pack->v.symmetric->block = g_new (struct kmip_key_block, 1);
  pack->v.symmetric->block->type = KMIP_KEY_TRANSPARENT_SYMMETRIC;
  pack->v.symmetric->block->value = key_value;
  *kv = key_value;
  return pack;
}

/* Create a KMIP packet structure for VOL that contains PASSPHRASE of SIZE.
   On success return the KMIP data, store the kmip_key_value component to KV.
   Return NULL on error. */
static struct kmip_libvk_packet *
volume_create_passphrase_packet (struct kmip_key_value **kv,
				 const struct libvk_volume *vol,
				 const void *passphrase, size_t size)
{
  struct kmip_libvk_packet *pack;
  struct kmip_key_value *key_value;

  key_value = g_new (struct kmip_key_value, 1);
  key_value->type = KMIP_KEY_VALUE_BYTES;
  key_value->v.bytes.data = g_memdup (passphrase, size);
  key_value->v.bytes.len = size;
  key_value->attributes = g_ptr_array_new ();
  add_common_volume_attributes (key_value, vol);

  pack = g_new (struct kmip_libvk_packet, 1);
  pack->version = g_new (struct kmip_protocol_version, 1);
  pack->version->major = KMIP_VERSION_MAJOR;
  pack->version->minor = KMIP_VERSION_MINOR;
  pack->type = KMIP_OBJECT_SECRET_DATA;
  pack->v.secret_data = g_new (struct kmip_object_secret_data, 1);
  pack->v.secret_data->type = KMIP_SECRET_DATA_PASSWORD;
  pack->v.secret_data->block = g_new (struct kmip_key_block, 1);
  pack->v.secret_data->block->type = KMIP_KEY_OPAQUE;
  pack->v.secret_data->block->value = key_value;
  *kv = key_value;
  return pack;
}

/* Find an KMIP_TAG_APP_SPECIFIC attribute with ATTR_NAME and NAME.
   Return attribute value if found, NULL otherwise (reporting it in ERROR). */
static const char *
get_attribute_strings (const struct kmip_key_value *key_value,
		       const char *attr_name, const char *name, GError **error)
{
  size_t i;

  for (i = 0; i < key_value->attributes->len; i++)
    {
      const struct kmip_attribute *a;

      a = g_ptr_array_index (key_value->attributes, i);
      if (a->tag == KMIP_TAG_APP_SPECIFIC && strcmp (a->name, attr_name) == 0
	  && strcmp (a->v.strings.name, name) == 0)
	return a->v.strings.value;
    }
  g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNEXPECTED_FORMAT,
	       _("Required attribute \"%s\" not found"), name);
  return NULL;
}

/* Find an attribute with TAG and NAME.
   Return attribute if found, NULL otherwise (reporting it in ERROR). */
static const struct kmip_attribute *
get_attribute (const struct kmip_key_value *key_value, guint32 tag,
	       const char *name, GError **error)
{
  size_t i;

  for (i = 0; i < key_value->attributes->len; i++)
    {
      const struct kmip_attribute *a;

      a = g_ptr_array_index (key_value->attributes, i);
      if (a->tag == tag && strcmp (a->name, name) == 0)
	return a;
    }
  g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNEXPECTED_FORMAT,
	       _("Required attribute \"%s\" not found"), name);
  return NULL;
}

 /* Volume property handling */

struct libvk_volume_property
{
  const char *label, *name;
  enum libvk_vp_type type;
  char *value;			/* For g_free (). */
};

/* Free PROP. */
void
libvk_vp_free (struct libvk_volume_property *prop)
{
  g_return_if_fail (prop != NULL);

  if (prop->type == LIBVK_VP_SECRET)
    memset (prop->value, 0, strlen (prop->value));
  g_free (prop->value);
  g_free (prop);
}

/* Get a label of PROP (user-readable, in current locale encoding).
   Return property label, for g_free (). */
char *
libvk_vp_get_label (const struct libvk_volume_property *prop)
{
  g_return_val_if_fail (prop != NULL, NULL);

  return g_strdup (prop->label);
}

/* Get an invariant name of PROP (useful for programs).
   Return property name, for g_free (). */
char *
libvk_vp_get_name (const struct libvk_volume_property *prop)
{
  g_return_val_if_fail (prop != NULL, NULL);

  return g_strdup (prop->name);
}

/* Return type of PROP.
   Make sure the caller can handle unknown values! */
enum libvk_vp_type
libvk_vp_get_type (const struct libvk_volume_property *prop)
{
  g_return_val_if_fail (prop != NULL, 0); /* Return whatever. */

  return prop->type;
}

/* Get the value of PROP.
   Return property value, for g_free ().
   The caller might want to zero the memory of LIBVK_VP_SECRET values before
   freeing them. */
char *
libvk_vp_get_value (const struct libvk_volume_property *prop)
{
  g_return_val_if_fail (prop != NULL, NULL);

  return g_strdup (prop->value);
}

/* Add NAME (constant) and VALUE (for g_free ()) to start of LIST, return
   new list. */
static GSList *
add_vp (GSList *list, const char *label, const char *name,
	enum libvk_vp_type type, char *value)
{
  struct libvk_volume_property *prop;

  prop = g_new (struct libvk_volume_property, 1);
  prop->label = label;
  prop->name = name;
  prop->type = type;
  prop->value = value;
  return g_slist_prepend (list, prop);
}

 /* LUKS - specific code */

/* g_free() LUKS and everything it points to. */
static void
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
    {
      memset (luks->passphrase, 0, strlen (luks->passphrase));
      g_free (luks->passphrase);
    }
  g_free (luks);
}

/* Open a LUKS VOL at PATH.
   Return LUKS volume information, or NULL on error. */
static struct luks_volume *
luks_volume_open (struct libvk_volume *vol, const char *path, GError **error)
{
  struct luks_volume *luks;
  struct crypt_luks_volume_info *vi;
  char *c;
  int r;

  (void)vol;
  r = crypt_luks_get_volume_info (&vi, path);
  if (r < 0)
    {
      error_from_cryptsetup (error, LIBVK_ERROR_VOLUME_UNKNOWN_FORMAT, r);
      g_prefix_error (error,
		      _("Error getting information about volume \"%s\": "),
		      path);
      return NULL;
    }
  /* A bit of paranoia */
  c = crypt_luks_vi_get_uuid (vi);
  if (strcmp (vol->uuid, c) != 0)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_FAILED,
		   _("UUID mismatch between libblkid and libcryptsetup: \"%s\" "
		     "vs. \"%s\""), vol->uuid, c);
      free (c);
      crypt_luks_vi_free (vi);
      return NULL;
    }
  free (c);

  luks = g_new (struct luks_volume, 1);
  c = crypt_luks_vi_get_cipher_name (vi);
  luks->cipher_name = g_strdup (c);
  free (c);
  c = crypt_luks_vi_get_cipher_mode (vi);
  luks->cipher_mode = g_strdup (c);
  free (c);
  luks->key_bytes = crypt_luks_vi_get_key_bytes (vi);
  crypt_luks_vi_free (vi);

  luks->key = NULL;
  luks->passphrase = NULL;
  luks->passphrase_slot = -1;
  return luks;
}

/* Add properties of LUKS, including "secrets" if WITH_SECRETS != 0, to LIST.
   Return an updated list. */
static GSList *
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
  if (luks->passphrase != NULL && luks->passphrase_slot != -1)
    res = add_vp (res, _("Passphrase slot"), "luks/passphrase_slot",
		  LIBVK_VP_IDENTIFICATION,
		  g_strdup_printf ("%d", luks->passphrase_slot));
  return res;
}

/* Just swallow a LUKS message. */
static void
dummy_luks_log (int class, char *msg)
{
  (void)class;
  (void)msg;
}

/* Get a "secret" of SECRET_TYPE for LUKS VOL, interacting with the user using
   the provided UI.
   Return 0 if OK, -1 on error. */
static int
luks_get_secret (struct libvk_volume *vol, enum libvk_secret secret_type,
		 const struct libvk_ui *ui, GError **error)
{
  char *passphrase;
  unsigned char *key;
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
      return -1;
    }
  prompt = g_strdup_printf (_("Passphrase for \"%s\""), vol->path);
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
      r = crypt_luks_get_master_key (&key, &key_length, vol->path,
				     (const unsigned char *)passphrase,
				     strlen (passphrase), dummy_luks_log);
      if (r >= 0)
	{
	  slot = r;
	  goto got_passphrase;
	}
      memset (passphrase, 0, strlen (passphrase));
      g_free (passphrase);
      if (r != -EPERM)
	{
	  error_from_cryptsetup (error, LIBVK_ERROR_FAILED, r);
	  g_prefix_error (error, _("Error getting LUKS data encryption key: "));
	  goto err_prompt;
	}
    }
  g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_FAILED,
	       _("Too many attempts to get a valid passphrase"));
  goto err_prompt;

 got_passphrase:
  vol->v.luks->key_bytes = key_length;
  if (vol->v.luks->key != NULL)
    {
      memset (vol->v.luks->key, 0, vol->v.luks->key_bytes);
      g_free (vol->v.luks->key);
    }
  vol->v.luks->key = g_memdup (key, key_length);
  memset (key, 0, key_length);
  free (key);

  if (vol->v.luks->passphrase != NULL)
    {
      memset (vol->v.luks->passphrase, 0, strlen (vol->v.luks->passphrase));
      g_free (vol->v.luks->passphrase);
    }
  vol->v.luks->passphrase = passphrase;
  vol->v.luks->passphrase_slot = slot;
  g_free (prompt);
  return 0;

 err_prompt:
  g_free (prompt);
  return -1;
}

/* Check if PACKET matches VOL, modifying previous comparison result RES.
   Return the comparison result:
   On LIBVK_PACKET_MATCH_MISMATCH set an error message.
   On LIBVK_PACKET_MATCH_UNSURE, if WARNINGS is not NULL, add warning messages
   (char *, for g_free ()) to it. */
static enum libvk_packet_match_result
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
		   _("Cipher name mismatch (packet \"%s\", volume \"%s\")"),
		   p->cipher_name, v->cipher_name);
      return LIBVK_PACKET_MATCH_ERROR;
    }
  if (p->cipher_mode != NULL && strcmp (p->cipher_mode, v->cipher_mode) != 0)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_PACKET_VOLUME_MISMATCH,
		   _("Cipher mode mismatch (packet \"%s\", volume \"%s\")"),
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

/* Apply the "secret" of SECRET_TYPE in PACKET to restore conventional access
   to VOL, using UI to gather more information.
   Return 0 if OK, -1 on error.
   "Restore conventional access" usually means "prompt for a new passphrase". */

static int
luks_apply_secret (struct libvk_volume *vol, const struct libvk_volume *packet,
		   enum libvk_secret secret_type, const struct libvk_ui *ui,
		   GError **error)
{
  char *prompt, *prompt2, *error_prompt, *passphrase;
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

  prompt = g_strdup_printf (_("New passphrase for \"%s\""), vol->path);
  prompt2 = g_strdup_printf (_("Repeat new passphrase for \"%s\""), vol->path);
  error_prompt = g_strdup_printf (_("Passphrases do not match.  New passphrase "
				    "for \"%s\""), vol->path);
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
      passphrase2 = ui_get_passphrase (ui, prompt2, failed, error);
      if (passphrase2 == NULL)
	goto err_passphrase;
      passphrase_ok = strcmp (passphrase, passphrase2) == 0;
      memset (passphrase2, 0, strlen (passphrase2));
      g_free (passphrase2);
      if (passphrase_ok)
	goto got_passphrase;
      memset (passphrase, 0, strlen (passphrase));
      g_free (passphrase);
    }
  g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_FAILED,
	       _("Too many attempts to get a passphrase"));
  goto err_prompts;

 got_passphrase:
  res = crypt_luks_add_passphrase_by_master_key (vol->path,
						 packet->v.luks->key,
						 packet->v.luks->key_bytes, -1,
						 (unsigned char *)passphrase,
						 strlen (passphrase),
						 dummy_luks_log);
  if (res < 0)
    {
      error_from_cryptsetup (error, LIBVK_ERROR_FAILED, res);
      g_prefix_error (error, _("Error adding a LUKS passphrase"));
      goto err_passphrase;
    }

  if (vol->v.luks->key != NULL)
    {
      memset (vol->v.luks->key, 0, vol->v.luks->key_bytes);
      g_free (vol->v.luks->key);
    }
  vol->v.luks->key = g_memdup (packet->v.luks->key, packet->v.luks->key_bytes);
  if (vol->v.luks->passphrase != NULL)
    {
      memset (vol->v.luks->passphrase, 0, strlen (vol->v.luks->passphrase));
      g_free (vol->v.luks->passphrase);
    }
  vol->v.luks->passphrase = passphrase;
  vol->v.luks->passphrase_slot = res;

  /* don't free "passphrase" */
  g_free (error_prompt);
  g_free (prompt2);
  g_free (prompt);
  return 0;

 err_passphrase:
  memset (passphrase, 0, strlen (passphrase));
  g_free (passphrase);
 err_prompts:
  g_free (error_prompt);
  g_free (prompt2);
  g_free (prompt);
 err:
  return -1;
}

/* Add SECRET with SIZE and SECRET_TYPE to LUKS VOLUME.
   Return 0 if OK, -1 on error. */
static int
luks_add_secret (struct libvk_volume *vol, enum libvk_secret secret_type,
		 const void *secret, size_t size, GError **error)
{
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
  if (size == 0 || memchr (secret, '\0', size) !=
      (const unsigned char *)secret + size - 1)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_VOLUME_INVALID_SECRET,
		   _("The passphrase must be a string"));
      return -1;
    }
  res = crypt_luks_add_passphrase_by_master_key (vol->path, vol->v.luks->key,
						 vol->v.luks->key_bytes, -1,
						 secret, size - 1,
						 dummy_luks_log);
  if (res < 0)
    {
      error_from_cryptsetup (error, LIBVK_ERROR_FAILED, res);
      g_prefix_error (error, _("Error adding a LUKS passphrase"));
      return -1;
    }

  if (vol->v.luks->passphrase != NULL)
    {
      memset (vol->v.luks->passphrase, 0, strlen (vol->v.luks->passphrase));
      g_free (vol->v.luks->passphrase);
    }
  vol->v.luks->passphrase = g_strdup (secret);
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
      a->v.crypto_params.cipher_mode = mode;
      a->v.crypto_params.hash_algorithm = hash;
      g_ptr_array_add (key_value->attributes, a);
    }
}

/* Create a KMIP packet structure for SECRET in VOL.
   Return the KMIP data on success, NULL no error. */
static struct kmip_libvk_packet *
luks_create_escrow_packet (const struct libvk_volume *vol,
			   enum libvk_secret secret_type, GError **error)
{
  struct kmip_libvk_packet *pack;
  struct kmip_key_value *key_value;

  switch (secret_type)
    {
    case LIBVK_SECRET_DEFAULT:
    case LIBVK_SECRET_DATA_ENCRYPTION_KEY:
      if (vol->v.luks->key == NULL)
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
		       _("Passphrase key unknown"));
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
static int
luks_parse_escrow_packet (struct libvk_volume *vol,
			  const struct kmip_libvk_packet *pack,
			  const struct kmip_key_value *key_value,
			  GError **error)
{
  const struct kmip_attribute *a;
  const char *s;

  vol->v.luks = g_new0 (struct luks_volume, 1);
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
	  g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNSUPPORTED_VALUE,
		       _("Unsupported key length %" G_GINT32_FORMAT),
		       a->v.int32_value);
	  goto err;
	}
      {
	/* FIXME: GLib 2.19 will support compile-time assertions natively. */
	typedef char assertion__[sizeof (gint32) <= sizeof (size_t) ? 1 : -1];
      }
      vol->v.luks->key_bytes = a->v.int32_value / 8;
      if (key_value->v.key->len != vol->v.luks->key_bytes)
	{
	  g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_INVALID_INPUT,
		       _("Key length mismatch"));
	  goto err;
	}
      vol->v.luks->key = g_memdup (key_value->v.key->data,
				   key_value->v.key->len);
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
			   _("Invalid slot number \"%s\""), s);
	      goto err;
	    }
	  vol->v.luks->passphrase_slot = slot;
	}
      if (memchr (key_value->v.bytes.data, '\0', key_value->v.bytes.len) != 0)
	{
	  g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_INVALID_INPUT,
		       _("NUL byte in passphrase"));
	  goto err;
	}
      vol->v.luks->passphrase = g_malloc (key_value->v.bytes.len + 1);
      memcpy (vol->v.luks->passphrase, key_value->v.bytes.data,
	      key_value->v.bytes.len);
      vol->v.luks->passphrase[key_value->v.bytes.len] = '\0';
      break;

    default:
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNSUPPORTED_VALUE,
		   _("Unsupported packet type %" G_GUINT32_FORMAT), pack->type);
      goto err;
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
  unsigned char *to_free;
  const unsigned char *key;
  int r;
  size_t key_size;

  // FIXME: use passphrase?
  if (packet->v.luks->key != NULL)
    {
      key = packet->v.luks->key;
      key_size = vol->v.luks->key_bytes;
      to_free = NULL;
    }
  else if (packet->v.luks->passphrase != NULL)
    {
      r = crypt_luks_get_master_key (&to_free, &key_size, vol->path,
				     (const unsigned char *)
				     packet->v.luks->passphrase,
				     strlen (packet->v.luks->passphrase),
				     dummy_luks_log);
      if (r < 0)
	{
	  error_from_cryptsetup (error, LIBVK_ERROR_FAILED, r);
	  g_prefix_error (error, _("Error getting LUKS data encryption key: "));
	  goto err;
	}
      key = to_free;
    }
  else
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_VOLUME_NEED_SECRET,
		   _("Data encryption key unknown"));
      goto err;
    }

  r = crypt_luks_open_by_master_key (name, vol->path, key, key_size, 0,
				     dummy_luks_log);
  if (r < 0)
    {
      error_from_cryptsetup (error, LIBVK_ERROR_FAILED, r);
      g_prefix_error (error, _("Error opening LUKS volume: "));
      goto err_to_free;
    }

  if (to_free != NULL)
    {
      memset (to_free, 0, key_size);
      free (to_free);
    }
  return 0;

 err_to_free:
  if (to_free != NULL)
    {
      memset (to_free, 0, key_size);
      free (to_free);
    }
 err:
  return -1;
}

 /* Volume format-independent code */

/* Free VOL and everything it points to. */
void
libvk_volume_free (struct libvk_volume *vol)
{
  g_return_if_fail (vol != NULL);

  if (strcmp (vol->format, LIBVK_VOLUME_FORMAT_LUKS) == 0
      && vol->v.luks != NULL)
    luks_volume_free (vol->v.luks);
  g_free (vol->hostname);
  g_free (vol->uuid);
  g_free (vol->label);
  g_free (vol->path);
  g_free (vol->format);
  g_free (vol);
}

/* Open PATH and gather general information (format, attributes) about it.
   Return volume information if OK, NULL on error.
   This does not usually get encryption keys nor passphrases.  No user
   interaction is necessary. */
struct libvk_volume *
libvk_volume_open (const char *path, GError **error)
{
  gboolean got_cache;
  blkid_cache cache;
  struct libvk_volume *vol;
  char *c;

  g_return_val_if_fail (path != NULL, NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);

  got_cache = (blkid_get_cache (&cache, NULL) == 0);
  c = blkid_get_tag_value (cache, "TYPE", path);
  if (c == NULL)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_FAILED,
		   _("Cannot get attributes of \"%s\""), path);
      vol = NULL;
      goto out;
    }
  vol = g_new (struct libvk_volume, 1);
  vol->source = VOLUME_SOURCE_LOCAL;
  vol->format = g_strdup (c);
  free (c);

  vol->hostname = g_strdup (g_get_host_name ());
  c = blkid_get_tag_value (cache, "UUID", path); /* May be NULL */
  vol->uuid = g_strdup (c);
  free (c);
  c = blkid_get_tag_value (cache, "LABEL", path); /* May be NULL */
  vol->label = g_strdup (c);
  free (c);
  vol->path = g_strdup (path); /* FIXME? a canonical path? */

  if (strcmp (vol->format, LIBVK_VOLUME_FORMAT_LUKS) == 0)
    {
      vol->v.luks = luks_volume_open (vol, path, error);
      if (vol->v.luks == NULL)
	{
	  libvk_volume_free (vol);
	  vol = NULL;
	  goto out;
	}
    }

 out:
  if (got_cache)
    blkid_put_cache (cache);
  return vol;
}

/* Get host name associated with the volume.
   Return host name, for g_free (). */
char *
libvk_volume_get_hostname (const struct libvk_volume *vol)
{
  g_return_val_if_fail (vol != NULL, NULL);

  return g_strdup (vol->hostname);
}

/* Get UUID associated with the volume.
   Return UUID in ASCII, for g_free (), if available, NULL otherwise. */
char *
libvk_volume_get_uuid (const struct libvk_volume *vol)
{
  g_return_val_if_fail (vol != NULL, NULL);

  return g_strdup (vol->uuid);
}

/* Get a label associated with the volume.
   Return volume label, for g_free (), if available, NULL otherwise. */
char *
libvk_volume_get_label (const struct libvk_volume *vol)
{
  g_return_val_if_fail (vol != NULL, NULL);

  return g_strdup (vol->label);
}

/* Get a path associated with the volume.
   Return path, for g_free ().
   Note that the path need not be canonical, there may be more than one path
   pointing to the same volume. */
char *
libvk_volume_get_path (const struct libvk_volume *vol)
{
  g_return_val_if_fail (vol != NULL, NULL);

  return g_strdup (vol->path);
}

/* Get format of the volume.
   Return the format, for g_free ().
   See LIBVK_VOLUME_FORMAT_* below.
   A volume format will always be returned, even if it is not supported by
   libvolume_key. */
char *
libvk_volume_get_format (const struct libvk_volume *vol)
{
  g_return_val_if_fail (vol != NULL, NULL);

  return g_strdup (vol->format);
}

/* Return a list of all properties of VOL, including "secrets" if WITH_SECRETS
   != 0.
   Each element of the list is a two-member GPtrArray, with
   [0] == property description and [1] == property value.
   Be careful with the secrets! */
GSList *
libvk_volume_dump_properties (const struct libvk_volume *vol, int with_secrets)
{
  GSList *res;

  g_return_val_if_fail (vol != NULL, NULL);

  res = NULL;
  res = add_vp (res, _("Host name"), "hostname", LIBVK_VP_IDENTIFICATION,
		g_strdup (vol->hostname));
  res = add_vp (res, _("Volume format"), "volume_format",
		LIBVK_VP_IDENTIFICATION, g_strdup (vol->format));
  if (vol->uuid != NULL)
    res = add_vp (res, _("Volume UUID"), "volume_uuid", LIBVK_VP_IDENTIFICATION,
		  g_strdup (vol->uuid));
  if (vol->label != NULL)
    res = add_vp (res, _("Volume label"), "volume_label",
		  LIBVK_VP_IDENTIFICATION, g_strdup (vol->label));
  res = add_vp (res, _("Volume path"), "volume_path",
		LIBVK_VP_IDENTIFICATION, g_strdup (vol->path));
  if (strcmp (vol->format, LIBVK_VOLUME_FORMAT_LUKS) == 0)
    res = luks_volume_dump_properties (res, vol->v.luks, with_secrets);
  return g_slist_reverse (res);
}

/* Get a "secret" of SECRET_TYPE for VOL, interacting with the user using the
   provided UI.
   Return 0 if OK, -1 on error. */
int
libvk_volume_get_secret (struct libvk_volume *vol,
			 enum libvk_secret secret_type,
			 const struct libvk_ui *ui, GError **error)
{
  g_return_val_if_fail (vol != NULL, -1);
  g_return_val_if_fail (vol->source == VOLUME_SOURCE_LOCAL, -1);
  g_return_val_if_fail (secret_type < LIBVK_SECRET_END__, -1);
  g_return_val_if_fail (ui != NULL, -1);
  g_return_val_if_fail (error == NULL || *error == NULL, -1);

  if (strcmp (vol->format, LIBVK_VOLUME_FORMAT_LUKS) == 0)
    return luks_get_secret (vol, secret_type, ui, error);
  else
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_VOLUME_UNKNOWN_FORMAT,
		   _("Volume \"%s\" has unsupported format"), vol->path);
      return -1;
    }
}

/* Check if PACKET matches VOL.
   Return the comparison result:
   On LIBVK_PACKET_MATCH_ERROR set an error message.
   On LIBVK_PACKET_MATCH_UNSURE, if WARNINGS is not NULL, add warning messages
   (char *, for g_free ()) to it. */
enum libvk_packet_match_result
libvk_packet_match_volume (const struct libvk_volume *packet,
			   const struct libvk_volume *vol, GPtrArray *warnings,
			   GError **error)
{
  enum libvk_packet_match_result res;

  g_return_val_if_fail (packet != NULL, LIBVK_PACKET_MATCH_ERROR);
  g_return_val_if_fail (packet->source == VOLUME_SOURCE_PACKET,
			LIBVK_PACKET_MATCH_ERROR);
  g_return_val_if_fail (vol != NULL, LIBVK_PACKET_MATCH_ERROR);
  g_return_val_if_fail (vol->source == VOLUME_SOURCE_LOCAL,
			LIBVK_PACKET_MATCH_ERROR);
  g_return_val_if_fail (error == NULL || *error == NULL,
			LIBVK_PACKET_MATCH_ERROR);

  /* The only really reliable indicators */
  if (strcmp (packet->format, vol->format) != 0)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_PACKET_VOLUME_MISMATCH,
		   _("Volume format mismatch (packet \"%s\", volume \"%s\")"),
		   packet->format, vol->format);
      return LIBVK_PACKET_MATCH_ERROR;
    }
  res = LIBVK_PACKET_MATCH_UNSURE;
  if (packet->uuid != NULL && vol->uuid != NULL
      && strcmp (packet->uuid, vol->uuid) == 0)
    /* This is good enough for a match, but we still want to make sure
       format-specific encryption parameters match. */
    res = LIBVK_PACKET_MATCH_OK;

  /* Let format-specific code confirm or reject the match, or if unsure, to
     start adding warnings. */
  if (strcmp (packet->format, LIBVK_VOLUME_FORMAT_LUKS) == 0)
    res = luks_packet_match_volume (packet, vol, res, warnings, error);
  if (res != LIBVK_PACKET_MATCH_UNSURE)
    return res;

  /* Only add warnings in the format-specific code or below, to make sure we
     do not add warnings if the result is unambiguous. */
  if (warnings != NULL)
    {
      char *s;

      if (strcmp (packet->hostname, vol->hostname) != 0)
	{
	  s = g_strdup_printf (_("Host name mismatch (packet \"%s\", volume "
				 "\"%s\")"), packet->hostname, vol->hostname);
	  g_ptr_array_add (warnings, s);
	}
      if (packet->label != NULL && vol->label != NULL
	  && strcmp (packet->label, vol->label) != 0)
	{
	  s = g_strdup_printf (_("Volume label mismatch (packet \"%s\", volume "
				 "\"%s\")"), packet->label, vol->label);
	  g_ptr_array_add (warnings, s);
	}
      if (packet->path != NULL && vol->path != NULL
	  && strcmp (packet->path, vol->path) != 0)
	{
	  s = g_strdup_printf (_("Volume path mismatch (packet \"%s\", volume "
				 "\"%s\")"), packet->path, vol->path);
	  g_ptr_array_add (warnings, s);
	}
    }
  return LIBVK_PACKET_MATCH_UNSURE;
}

/* Apply the "secret" of SECRET_TYPE in PACKET to restore conventional access
   to VOL, using UI to gather more information.
   Return 0 if OK, -1 on error.
   "Restore conventional access" usually means "prompt for a new passphrase". */
int
libvk_volume_apply_packet (struct libvk_volume *vol,
			   const struct libvk_volume *packet,
			   enum libvk_secret secret_type,
			   const struct libvk_ui *ui, GError **error)
{
  g_return_val_if_fail (vol != NULL, -1);
  g_return_val_if_fail (vol->source == VOLUME_SOURCE_LOCAL, -1);
  g_return_val_if_fail (packet != NULL, -1);
  g_return_val_if_fail (packet->source == VOLUME_SOURCE_PACKET, -1);
  g_return_val_if_fail (ui != NULL, -1);
  g_return_val_if_fail (error == NULL || *error == NULL, -1);

  if (libvk_packet_match_volume (packet, vol, NULL, error)
      == LIBVK_PACKET_MATCH_ERROR)
    return -1;

  if (strcmp (vol->format, LIBVK_VOLUME_FORMAT_LUKS) == 0)
    return luks_apply_secret (vol, packet, secret_type, ui, error);
  else
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_VOLUME_UNKNOWN_FORMAT,
		   _("Volume \"%s\" has unsupported format"), vol->path);
      return -1;
    }
}

/* Add SECRET with SIZE and SECRET_TYPE to VOLUME.
   Return 0 if OK, -1 on error.
   This operation should not be destructive.  Details are format-specific;
   for example, this may allow adding a LIBVK_SECRET_PASSPHRASE, assuming
   LIBVK_SECRET_DEFAULT was obtained before. */
int
libvk_volume_add_secret (struct libvk_volume *vol,
			 enum libvk_secret secret_type, const void *secret,
			 size_t size, GError **error)
{
  g_return_val_if_fail (vol != NULL, -1);
  g_return_val_if_fail (vol->source == VOLUME_SOURCE_LOCAL, -1);
  g_return_val_if_fail (secret_type <= LIBVK_SECRET_END__, -1);
  g_return_val_if_fail (secret != NULL, -1);
  g_return_val_if_fail (error == NULL || *error == NULL, -1);

  if (strcmp (vol->format, LIBVK_VOLUME_FORMAT_LUKS) == 0)
    return luks_add_secret (vol, secret_type, secret, size, error);
  else
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_VOLUME_UNKNOWN_FORMAT,
		   _("Volume \"%s\" has unsupported format"), vol->path);
      return -1;
    }
}

/* Create a key escrow packet for SECRET in VOL, set SIZE to its size.
   Return packet data (for g_free ()) if OK, NULL on error. */
void *
volume_create_escrow_packet (const struct libvk_volume *vol, size_t *size,
			     enum libvk_secret secret_type, GError **error)
{
  struct kmip_encoding_state kmip;
  struct kmip_libvk_packet *pack;

  if (strcmp (vol->format, LIBVK_VOLUME_FORMAT_LUKS) == 0)
    pack = luks_create_escrow_packet (vol, secret_type, error);
  else
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_VOLUME_UNKNOWN_FORMAT,
		   _("Volume \"%s\" has unsupported format"), vol->path);
      return NULL;
    }
  if (pack == NULL)
    return NULL;

  kmip.data = NULL;
  kmip.offset = 0;
  kmip.size = SIZE_MAX;
  if (kmip_encode_packet (&kmip, KMIP_TAG_LIBVK_PACKET, pack, error) != 0)
    {
      kmip_libvk_packet_free (pack);
      return NULL;
    }
  kmip.data = g_malloc (kmip.offset);
  kmip.size = kmip.offset;
  kmip.offset = 0;
  if (kmip_encode_packet (&kmip, KMIP_TAG_LIBVK_PACKET, pack, error) != 0)
    g_return_val_if_reached(NULL);
  kmip_libvk_packet_free (pack);
  *size = kmip.size;
  return kmip.data;
}

/* Open VOL using volume format-specific NAME, using "secrets" from PACKET.
   Return 0 if OK, -1 on error.

   NAME is currently always a device-mapper name, please try not to rely on
   it. */
int
libvk_volume_open_with_packet (struct libvk_volume *vol,
			       const struct libvk_volume *packet,
			       const char *name, GError **error)
{
  g_return_val_if_fail (vol != NULL, -1);
  g_return_val_if_fail (vol->source == VOLUME_SOURCE_LOCAL, -1);
  g_return_val_if_fail (packet != NULL, -1);
  g_return_val_if_fail (packet->source == VOLUME_SOURCE_PACKET, -1);
  g_return_val_if_fail (name != NULL, -1);
  g_return_val_if_fail (error == NULL || *error == NULL, -1);

  if (strcmp (vol->format, LIBVK_VOLUME_FORMAT_LUKS) == 0)
    return luks_open_with_packet (vol, packet, name, error);
  else
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_VOLUME_UNKNOWN_FORMAT,
		   _("Volume \"%s\" has unsupported format"), vol->path);
      return -1;
    }
}

 /* KMIP interaction */

/* Load volume information from PACKET of SIZE.
   Return volume information if OK, NULL on error.
   Note that the data in the packet might be obsolete! */
struct libvk_volume *
volume_load_escrow_packet (const void *packet, size_t size, GError **error)
{
  struct kmip_decoding_state kmip;
  struct kmip_libvk_packet *pack;
  const struct kmip_key_value *key_value;
  const char *s;
  struct libvk_volume *vol;

  kmip.data = packet;
  kmip.left = size;
  if (kmip_decode_packet (&kmip, &pack, KMIP_TAG_LIBVK_PACKET, error) != 0)
    return NULL;
  if (kmip.left != 0)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNEXPECTED_FORMAT,
		   _("Unexpected data after packet"));
      goto err;
    }
  if (pack->version->major != KMIP_VERSION_MAJOR
      || pack->version->minor != KMIP_VERSION_MINOR)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNSUPPORTED_VALUE,
		   _("Unsupported KMIP version %" G_GINT32_FORMAT ".%"
		     G_GINT32_FORMAT), pack->version->major,
		   pack->version->minor);
      goto err;
    }
  switch (pack->type)
    {
    case KMIP_OBJECT_SYMMETRIC_KEY:
      key_value = pack->v.symmetric->block->value;
      break;

    case KMIP_OBJECT_SECRET_DATA:
      key_value = pack->v.secret_data->block->value;
      break;

    default:
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNSUPPORTED_VALUE,
		   _("Unsupported packet type %" G_GUINT32_FORMAT), pack->type);
      goto err;
    }
  vol = g_new0 (struct libvk_volume, 1);
  vol->source = VOLUME_SOURCE_PACKET;
  s = get_attribute_strings (key_value, KMIP_ATTR_APP_SPECIFIC,
			     KMIP_AS_LIBVK_HOST_NAME, error);
  if (s == NULL)
    goto err_vol;
  vol->hostname = g_strdup (s);
  s = get_attribute_strings (key_value, KMIP_ATTR_APP_SPECIFIC,
			     KMIP_AS_LIBVK_VOLUME_UUID, NULL);
  vol->uuid = g_strdup (s);
  s = get_attribute_strings (key_value, KMIP_ATTR_APP_SPECIFIC,
			     KMIP_AS_LIBVK_VOLUME_LABEL, NULL);
  vol->label = g_strdup (s);
  s = get_attribute_strings (key_value, KMIP_ATTR_APP_SPECIFIC,
			     KMIP_AS_LIBVK_VOLUME_FILE, error);
  if (s == NULL)
    goto err_vol;
  vol->path = g_strdup (s);
  s = get_attribute_strings (key_value, KMIP_ATTR_APP_SPECIFIC,
			     KMIP_AS_LIBVK_VOLUME_FORMAT, error);
  if (s == NULL)
    goto err_vol;
  vol->format = g_strdup (s);

  if (strcmp (vol->format, LIBVK_VOLUME_FORMAT_LUKS) == 0)
    {
      if (luks_parse_escrow_packet (vol, pack, key_value, error) != 0)
	goto err_vol;
    }
  else
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNSUPPORTED_VALUE,
		   _("Unsupported volume format \"%s\""), s);
      goto err_vol;
    }

  kmip_libvk_packet_free (pack);
  return vol;

 err_vol:
  libvk_volume_free (vol);
 err:
  kmip_libvk_packet_free (pack);
  return NULL;
}
