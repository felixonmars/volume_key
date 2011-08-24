/* Volume handling.

Copyright (C) 2009, 2011 Red Hat, Inc. All rights reserved.
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

#include <limits.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <blkid/blkid.h>
#include <glib.h>
#include <glib/gi18n-lib.h>

#include "kmip.h"
#include "libvolume_key.h"
#include "volume.h"
#include "volume_luks.h"

 /* Common KMIP code */

/* Add a "strings" attribute using ATTR_NAME, NAME and VALUE to KEY_VALUE */
void
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
struct kmip_libvk_packet *
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
  pack->v.symmetric->block->crypto_algorithm = KMIP_LIBVK_ENUM_NONE;
  pack->v.symmetric->block->crypto_length = -1;
  pack->v.symmetric->block->wrapping = NULL;
  *kv = key_value;
  return pack;
}

/* Create a KMIP packet structure for VOL that contains PASSPHRASE of SIZE.
   On success return the KMIP data, store the kmip_key_value component to KV.
   Return NULL on error. */
struct kmip_libvk_packet *
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
  pack->v.secret_data->block->crypto_algorithm = KMIP_LIBVK_ENUM_NONE;
  pack->v.secret_data->block->crypto_length = -1;
  pack->v.secret_data->block->wrapping = NULL;
  *kv = key_value;
  return pack;
}

/* Find an KMIP_TAG_APP_SPECIFIC attribute with ATTR_NAME and NAME.
   Return attribute value if found, NULL otherwise (reporting it in ERROR). */
const char *
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
	       _("Required attribute `%s' not found"), name);
  return NULL;
}

/* Find an attribute with TAG and NAME.
   Return attribute if found, NULL otherwise (reporting it in ERROR). */
const struct kmip_attribute *
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
	       _("Required attribute `%s' not found"), name);
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
GSList *
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
		   _("Cannot get attributes of `%s'"), path);
      vol = NULL;
      goto out;
    }
  vol = g_new (struct libvk_volume, 1);
  vol->source = VOLUME_SOURCE_LOCAL;
  /* The LUKS type identifier returned by blkid has changed. */
  if (strcmp (c, "crypto_LUKS") == 0)
    vol->format = g_strdup (LIBVK_VOLUME_FORMAT_LUKS);
  else
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
  g_return_val_if_fail ((unsigned)secret_type < LIBVK_SECRET_END__, -1);
  g_return_val_if_fail (ui != NULL, -1);
  g_return_val_if_fail (error == NULL || *error == NULL, -1);

  if (strcmp (vol->format, LIBVK_VOLUME_FORMAT_LUKS) == 0)
    return luks_get_secret (vol, secret_type, ui, error);
  else
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_VOLUME_UNKNOWN_FORMAT,
		   _("Volume `%s' has unsupported format"), vol->path);
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
		   _("Volume format mismatch (packet `%s', volume `%s')"),
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

      /* Re-test UUID now. */
      if (packet->uuid != NULL && vol->uuid != NULL
	  && strcmp (packet->uuid, vol->uuid) != 0)
	{
	  s = g_strdup_printf (_("UUID mismatch (packet `%s', volume `%s')"),
			       packet->uuid, vol->uuid);
	  g_ptr_array_add (warnings, s);
	}
      if (strcmp (packet->hostname, vol->hostname) != 0)
	{
	  s = g_strdup_printf (_("Host name mismatch (packet `%s', volume "
				 "`%s')"), packet->hostname, vol->hostname);
	  g_ptr_array_add (warnings, s);
	}
      if (packet->label != NULL && vol->label != NULL
	  && strcmp (packet->label, vol->label) != 0)
	{
	  s = g_strdup_printf (_("Volume label mismatch (packet `%s', volume "
				 "`%s')"), packet->label, vol->label);
	  g_ptr_array_add (warnings, s);
	}
      if (packet->path != NULL && vol->path != NULL
	  && strcmp (packet->path, vol->path) != 0)
	{
	  s = g_strdup_printf (_("Volume path mismatch (packet `%s', volume "
				 "`%s')"), packet->path, vol->path);
	  g_ptr_array_add (warnings, s);
	}
    }
  return LIBVK_PACKET_MATCH_UNSURE;
}

/* Load "secrets" from PACKET, verify them if possible and store them with VOL.
   Return 0 if OK, -1 on error.
   This can be used only on volumes returned by libvk_volume_open (), not
   by volumes created from escrow packets. */
int
libvk_volume_load_packet (struct libvk_volume *vol,
			  const struct libvk_volume *packet, GError **error)
{
  g_return_val_if_fail (vol != NULL, -1);
  g_return_val_if_fail (vol->source == VOLUME_SOURCE_LOCAL, -1);
  g_return_val_if_fail (packet != NULL, -1);
  g_return_val_if_fail (packet->source == VOLUME_SOURCE_PACKET, -1);
  g_return_val_if_fail (error == NULL || *error == NULL, -1);

  if (libvk_packet_match_volume (packet, vol, NULL, error)
      == LIBVK_PACKET_MATCH_ERROR)
    return -1;

  if (strcmp (vol->format, LIBVK_VOLUME_FORMAT_LUKS) == 0)
    return luks_load_packet (vol, packet, error);
  else
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_VOLUME_UNKNOWN_FORMAT,
		   _("Volume `%s' has unsupported format"), vol->path);
      return -1;
    }
}

/* Apply the "secret" of SECRET_TYPE in PACKET to restore conventional access
   to VOL, using UI to gather more information.
   Return 0 if OK, -1 on error.
   "Restore conventional access" usually means something like "prompt for a new
   passphrase".
   This can be used only on volumes returned by libvk_volume_open (), not
   by volumes created from escrow packets. */
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
		   _("Volume `%s' has unsupported format"), vol->path);
      return -1;
    }
}

/* Add SECRET with SIZE and SECRET_TYPE to VOLUME.
   Return 0 if OK, -1 on error.
   This operation should not be destructive.  Details are format-specific;
   for example, this may allow adding a LIBVK_SECRET_PASSPHRASE, assuming
   LIBVK_SECRET_DEFAULT was obtained before.
   If SECRET is a string, SIZE does not include the terminating NUL.
   This can be used only on volumes returned by libvk_volume_open (), not
   by volumes created from escrow packets. */
int
libvk_volume_add_secret (struct libvk_volume *vol,
			 enum libvk_secret secret_type, const void *secret,
			 size_t size, GError **error)
{
  g_return_val_if_fail (vol != NULL, -1);
  g_return_val_if_fail (vol->source == VOLUME_SOURCE_LOCAL, -1);
  g_return_val_if_fail ((unsigned)secret_type <= LIBVK_SECRET_END__, -1);
  g_return_val_if_fail (secret != NULL, -1);
  g_return_val_if_fail (error == NULL || *error == NULL, -1);

  if (strcmp (vol->format, LIBVK_VOLUME_FORMAT_LUKS) == 0)
    return luks_add_secret (vol, secret_type, secret, size, error);
  else
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_VOLUME_UNKNOWN_FORMAT,
		   _("Volume `%s' has unsupported format"), vol->path);
      return -1;
    }
}

/* Open VOL using volume format-specific NAME, using "secrets" from PACKET.
   Return 0 if OK, -1 on error.

   NAME is currently always a device-mapper name, please try not to rely on
   it.
   This can be used only on volumes returned by libvk_volume_open (), not
   by volumes created from escrow packets. */
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

  if (libvk_packet_match_volume (packet, vol, NULL, error)
      == LIBVK_PACKET_MATCH_ERROR)
    return -1;

  if (strcmp (vol->format, LIBVK_VOLUME_FORMAT_LUKS) == 0)
    return luks_open_with_packet (vol, packet, name, error);
  else
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_VOLUME_UNKNOWN_FORMAT,
		   _("Volume `%s' has unsupported format"), vol->path);
      return -1;
    }
}

 /* KMIP interaction */

/* Load volume information from PACKET of SIZE.
   Return volume information if OK, NULL on error.
   Note that the data in the packet might be obsolete! */
struct libvk_volume *
volume_load_escrow_packet (struct kmip_libvk_packet *packet, GError **error)
{
  const struct kmip_key_value *key_value;
  const char *s;
  struct libvk_volume *vol;

  if (packet->version->major != KMIP_VERSION_MAJOR
      || packet->version->minor != KMIP_VERSION_MINOR)
    {
      gchar major[sizeof (packet->version->major) * CHAR_BIT + 1];
      gchar minor[sizeof (packet->version->minor) * CHAR_BIT + 1];

      g_snprintf (major, sizeof (major), "%" G_GINT32_FORMAT,
		  packet->version->major);
      g_snprintf (minor, sizeof (minor), "%" G_GINT32_FORMAT,
		  packet->version->minor);
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNSUPPORTED_VALUE,
		   _("Unsupported KMIP version %s.%s"), major, minor);
      goto err;
    }
  switch (packet->type)
    {
    case KMIP_OBJECT_SYMMETRIC_KEY:
      key_value = packet->v.symmetric->block->value;
      break;

    case KMIP_OBJECT_SECRET_DATA:
      key_value = packet->v.secret_data->block->value;
      break;

    default:
      {
	gchar num[sizeof (packet->type) * CHAR_BIT + 1];

	g_snprintf (num, sizeof (num), "%" G_GUINT32_FORMAT, packet->type);
	g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNSUPPORTED_VALUE,
		     _("Unsupported packet type %s"), num);
	goto err;
      }
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
      if (luks_parse_escrow_packet (vol, packet, key_value, error) != 0)
	goto err_vol;
    }
  else
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNSUPPORTED_VALUE,
		   _("Unsupported volume format `%s'"), s);
      goto err_vol;
    }
  return vol;

 err_vol:
  libvk_volume_free (vol);
 err:
  return NULL;
}

/* Create a key escrow packet for SECRET_TYPE in VOL.
   Return KMIP packet structure (for kmip_libvk_packet_free ()) if OK, NULL on
   error. */
struct kmip_libvk_packet *
volume_create_escrow_packet (const struct libvk_volume *vol,
			     enum libvk_secret secret_type, GError **error)
{
  if (strcmp (vol->format, LIBVK_VOLUME_FORMAT_LUKS) == 0)
    return luks_create_escrow_packet (vol, secret_type, error);
  else
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_VOLUME_UNKNOWN_FORMAT,
		   _("Volume `%s' has unsupported format"), vol->path);
      return NULL;
    }
}
