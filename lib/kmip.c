/* KMIP handling.

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

#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include <glib.h>
#include <glib/gi18n-lib.h>
#include <pk11pub.h>

#include "crypto.h"
#include "kmip.h"
#include "libvolume_key.h"
#include "ui.h"

 /* Utilities */

/* g_free() PARAMS and all data it points to. */
void
kmip_crypto_params_free (struct kmip_crypto_params *params)
{
  g_free (params);
}

/* g_free() ATTR and all data it points to. */
void
kmip_attribute_free (struct kmip_attribute *attr)
{
  switch (attr->tag)
    {
    case KMIP_TAG_CRYPTO_PARAMS:
      kmip_crypto_params_free (attr->v.crypto_params);
      break;

    case KMIP_TAG_APP_SPECIFIC:
      g_free (attr->v.strings.name);
      g_free (attr->v.strings.value);
      break;
    }
  g_free (attr->name);
  g_free (attr);
}

/* g_free() KEY and all data it points to. */
void
kmip_symmetric_key_free (struct kmip_symmetric_key *key)
{
  if (key->data != NULL)
    {
      memset (key->data, 0, key->len);
      g_free (key->data);
    }
  g_free (key);
}

/* Free VALUE->v */
static void
kmip_key_value_free_v (struct kmip_key_value *value)
{
  switch (value->type)
    {
    case KMIP_KEY_VALUE_BYTES:
      g_free (value->v.bytes.data);
      break;

    case KMIP_KEY_VALUE_SYMMETRIC_KEY:
      if (value->v.key != NULL)
	kmip_symmetric_key_free (value->v.key);
      break;

    default:
      g_return_if_reached ();
    }
}

/* Replace any key material in VALUE with BYTES with LEN */
static void
kmip_key_value_set_bytes (struct kmip_key_value *value, const void *bytes,
			  size_t len)
{
  kmip_key_value_free_v (value);
  value->type = KMIP_KEY_VALUE_BYTES;
  value->v.bytes.data = g_memdup (bytes, len);
  value->v.bytes.len = len;
}

/* Replace any key material in VALUE with a symmetric KEY with LEN */
static void
kmip_key_value_set_symmetric_key (struct kmip_key_value *value, const void *key,
				  size_t len)
{
  kmip_key_value_free_v (value);
  value->type = KMIP_KEY_VALUE_SYMMETRIC_KEY;
  value->v.key = g_new (struct kmip_symmetric_key, 1);
  value->v.key->data = g_memdup (key, len);
  value->v.key->len = len;
}

/* g_free() VALUE and all data it points to. */
void
kmip_key_value_free (struct kmip_key_value *value)
{
  size_t i;

  kmip_key_value_free_v (value);
  if (value->attributes != NULL)
    {
      for (i = 0; i < value->attributes->len; i++)
	kmip_attribute_free (g_ptr_array_index (value->attributes, i));
      g_ptr_array_free (value->attributes, TRUE);
    }
  g_free (value);
}

/* g_free() INFO and all data it points to. */
void
kmip_encryption_key_info_free (struct kmip_encryption_key_info *info)
{
  g_free (info->identifier);
  if (info->params != NULL)
    kmip_crypto_params_free (info->params);
  g_free (info);
}

/* g_free() WRAPPING and all data it points to. */
void
kmip_key_wrapping_data_free (struct kmip_key_wrapping_data *wrapping)
{
  if (wrapping->encryption_key != NULL)
    kmip_encryption_key_info_free (wrapping->encryption_key);
  g_free (wrapping->iv);
  g_free (wrapping);
}

/* Replace wrapped secret value in BLOCK in PACKET_TYPE with SECRET with
   SIZE. */
static void
kmip_key_block_set_clear_secret (struct kmip_key_block *block,
				 guint32 packet_type, const void *secret,
				 size_t size)
{
  switch (packet_type)
    {
    case KMIP_OBJECT_SYMMETRIC_KEY:
      block->type = KMIP_KEY_TRANSPARENT_SYMMETRIC;
      kmip_key_value_set_symmetric_key (block->value, secret, size);
      break;

    case KMIP_OBJECT_SECRET_DATA:
      block->type = KMIP_KEY_OPAQUE;
      kmip_key_value_set_bytes (block->value, secret, size);
      break;

    default:
      g_return_if_reached ();
    }
  block->crypto_algorithm = KMIP_LIBVK_ENUM_NONE;
  block->crypto_length = -1;
  if (block->wrapping != NULL)
    {
      kmip_key_wrapping_data_free (block->wrapping);
      block->wrapping = NULL;
    }
}

/* g_free() BLOCK and all data it points to. */
void
kmip_key_block_free (struct kmip_key_block *block)
{
  if (block->value != NULL)
    kmip_key_value_free (block->value);
  if (block->wrapping != NULL)
    kmip_key_wrapping_data_free (block->wrapping);
  g_free (block);
}

/* g_free() OBJ and all data it points to. */
void
kmip_object_symmetric_key_free (struct kmip_object_symmetric_key *obj)
{
  if (obj->block != NULL)
    kmip_key_block_free (obj->block);
  g_free (obj);
}

/* g_free() OBJ and all data it points to. */
void
kmip_object_secret_data_free (struct kmip_object_secret_data *obj)
{
  if (obj->block != NULL)
    kmip_key_block_free (obj->block);
  g_free (obj);
}

/* Free VERSION and all data it points to. */
void
kmip_protocol_version_free (struct kmip_protocol_version *version)
{
  g_free (version);
}

/* Free PACKET and all data it points to. */
void
kmip_libvk_packet_free (struct kmip_libvk_packet *packet)
{
  if (packet->version != NULL)
    kmip_protocol_version_free (packet->version);
  switch (packet->type)
    {
    case KMIP_OBJECT_SYMMETRIC_KEY:
      if (packet->v.symmetric != NULL)
	kmip_object_symmetric_key_free (packet->v.symmetric);
      break;

    case KMIP_OBJECT_SECRET_DATA:
      if (packet->v.secret_data != NULL)
	kmip_object_secret_data_free (packet->v.secret_data);
      break;

    default:
      g_return_if_reached();
    }
  g_free (packet);
}

 /* KMIP encoding */

/* Add DATA of SIZE to KMIP.
   Return 0 if OK, -1 if DATA doesn't fit. */
static int
add_data (struct kmip_encoding_state *kmip, const void *data, size_t size,
	  GError **error)
{
  g_return_val_if_fail (kmip->offset <= kmip->size, -1);
  if (kmip->size - kmip->offset < size)
    {
      g_set_error(error, LIBVK_ERROR, LIBVK_ERROR_KMIP_NO_SPACE,
		  _("Not enough space provided to store a KMIP packet"));
      return -1;
    }
  if (kmip->data != NULL)
    memcpy (kmip->data + kmip->offset, data, size);
  kmip->offset += size;
  return 0;
}

/* Add an item with TAG, TYPE and DATA of SIZE to KMIP.
   Return 0 if OK, -1 if it doesn't fit. */
static int
add_ttlv (struct kmip_encoding_state *kmip, guint32 tag, guint8 type,
	  guint32 size, const void *data, GError **error)
{
  guint32 tag_be, size_be;

  tag_be = GUINT32_TO_BE (tag);
  size_be = GUINT32_TO_BE (size);
  if (add_data (kmip, &tag_be, sizeof (tag_be), error) != 0
      || add_data (kmip, &type, sizeof (type), error) != 0
      || add_data (kmip, &size_be, sizeof (size_be), error) != 0
      || add_data (kmip, data, size, error) != 0)
    return -1;
  return 0;
}

/* Add int32 VAL with TAG to KMIP.
   Return 0 if OK, -1 if it doesn't fit. */
static int
add_int32 (struct kmip_encoding_state *kmip, guint32 tag, gint32 val,
	   GError **error)
{
  gint32 val_be;

  val_be = GINT32_TO_BE (val);
  return add_ttlv (kmip, tag, KMIP_ITEM_INT32, sizeof (val_be), &val_be, error);
}

/* Add enum VAL with TAG to KMIP.
   Return 0 if OK, -1 if it doesn't fit. */
static int
add_enum (struct kmip_encoding_state *kmip, guint32 tag, guint32 val,
	  GError **error)
{
  guint32 val_be;

  val_be = GUINT32_TO_BE (val);
  return add_ttlv (kmip, tag, KMIP_ITEM_ENUM, sizeof (val_be), &val_be, error);
}

/* Add STRING with TAG to KMIP.
   Return 0 if OK, -1 on error. */
static int
add_string (struct kmip_encoding_state *kmip, guint32 tag, const char *string,
	    GError **error)
{
  char *utf8;
  gsize bytes_written;
  int res;

  utf8 = g_locale_to_utf8 (string, -1, NULL, &bytes_written, error);
  if (utf8 == NULL)
    return -1;
  if ((guint32)bytes_written != bytes_written)
    {
      g_set_error(error, LIBVK_ERROR, LIBVK_ERROR_INPUT_OVERFLOW,
		  _("A string is too long"));
      g_free (utf8);
      return -1;
    }
  res = add_ttlv (kmip, tag, KMIP_ITEM_STRING, bytes_written, utf8, error);
  g_free (utf8);
  return res;
}

/* Add BYTES of LEN with TAG to KMIP.
   Return 0 if OK, -1 if it doesn't fit. */
static int
add_bytes (struct kmip_encoding_state *kmip, guint32 tag, const void *bytes,
	   size_t len, GError **error)
{
  if ((guint32)len != len)
    {
      g_set_error(error, LIBVK_ERROR, LIBVK_ERROR_INPUT_OVERFLOW,
		  _("Binary data is too long"));
      return -1;
    }
  return add_ttlv (kmip, tag, KMIP_ITEM_BYTES, len, bytes, error);
}

/* Structure encoding state, for patching in length */
struct struct_encoding
{
  size_t length_pos; /* Position of the "item length" value of the structure */
};

/* Start encoding a KMIP_ITEM_STRUCTURE with TAG into KMIP, store state to
   STATE.
   Return 0 if OK, -1 if data doesn't fit. */
static int
se_start (struct kmip_encoding_state *kmip, struct struct_encoding *state,
	  guint32 tag, GError **error)
{
  static const guint8 struct_type = KMIP_ITEM_STRUCTURE;

  guint32 tag_be;

  tag_be = GUINT32_TO_BE (tag);
  if (add_data (kmip, &tag_be, sizeof (tag_be), error) != 0
      || add_data (kmip, &struct_type, sizeof (struct_type), error) != 0)
    return -1;
  g_return_val_if_fail (kmip->offset <= kmip->size, -1);
  if (kmip->size - kmip->offset < sizeof (guint32))
    {
      g_set_error(error, LIBVK_ERROR, LIBVK_ERROR_KMIP_NO_SPACE,
		  _("Not enough space provided to store a KMIP packet"));
      return -1;
    }
  state->length_pos = kmip->offset;
  kmip->offset += sizeof (guint32);
  return 0;
}

/* Finish encoding a KMIP_ITEM_STRUCTURE started with STATE into KMIP.
   Return 0 if OK, -1 if data doesn't fit. */
static int
se_end (struct kmip_encoding_state *kmip, struct struct_encoding *state,
	GError **error)
{
  size_t size;

  size = kmip->offset - (state->length_pos + sizeof (guint32));
  if ((guint32)size != size)
    {
      g_set_error(error, LIBVK_ERROR, LIBVK_ERROR_INPUT_OVERFLOW,
		  _("A KMIP structure is too long"));
      return -1;
    }
  if (kmip->data != NULL)
    {
      guint32 size_be;

      size_be = GUINT32_TO_BE (size);
      memcpy (kmip->data + state->length_pos, &size_be, sizeof (size_be));
    }
  return 0;
}

/* Encode PARAMS into KMIP as TAG.
   Return 0 if OK, -1 on error. */
static int
kmip_encode_crypto_params (struct kmip_encoding_state *kmip, guint32 tag,
			   const struct kmip_crypto_params *params,
			   GError **error)
{
  struct struct_encoding se;

  if (se_start (kmip, &se, tag, error) != 0)
    return -1;
  if (params->cipher_mode != KMIP_LIBVK_ENUM_NONE
      && add_enum (kmip, KMIP_TAG_BLOCK_CIPHER_MODE, params->cipher_mode,
		   error) != 0)
    return -1;
  if (params->padding_method != KMIP_LIBVK_ENUM_NONE
      && add_enum (kmip, KMIP_TAG_PADDING_METHOD, params->padding_method,
		   error) != 0)
    return -1;
  if (params->hash_algorithm != KMIP_LIBVK_ENUM_NONE
      && add_enum (kmip, KMIP_TAG_HASH_ALGORITHM, params->hash_algorithm,
		   error) != 0)
    return -1;
  if (se_end (kmip, &se, error) != 0)
    return -1;
  return 0;
}

/* Encode ATTR into KMIP as TAG.
   Return 0 if OK, -1 on error. */
static int
kmip_encode_attribute (struct kmip_encoding_state *kmip, guint32 tag,
		       const struct kmip_attribute *attr, GError **error)
{
  struct struct_encoding se;

  if (se_start (kmip, &se, tag, error) != 0
      || add_string (kmip, KMIP_TAG_ATTRIBUTE_NAME, attr->name, error) != 0)
    return -1;
  switch (attr->tag)
    {
    case KMIP_TAG_CRYPTO_ALGORITHM:
      if (add_enum (kmip, KMIP_TAG_ATTRIBUTE_VALUE, attr->v.enum_value,
		    error) != 0)
	return -1;
      break;

    case KMIP_TAG_CRYPTO_LENGTH:
      if (add_int32 (kmip, KMIP_TAG_ATTRIBUTE_VALUE, attr->v.int32_value,
		     error) != 0)
	return -1;
      break;

    case KMIP_TAG_CRYPTO_PARAMS:
      if (kmip_encode_crypto_params (kmip, KMIP_TAG_ATTRIBUTE_VALUE,
				     attr->v.crypto_params, error) != 0)
	return -1;
      break;

    case KMIP_TAG_APP_SPECIFIC:
      {
	struct struct_encoding se2;

	if (se_start (kmip, &se2, KMIP_TAG_ATTRIBUTE_VALUE, error) != 0
	    || add_string (kmip, KMIP_TAG_APP_NAME_SPACE,
			   attr->v.strings.name, error) != 0
	    || add_string (kmip, KMIP_TAG_APP_ID, attr->v.strings.value,
			   error) != 0
	    || se_end (kmip, &se2, error) != 0)
	  return -1;
	break;
      }
    default:
      g_return_val_if_reached (-1);
    }
  if (se_end (kmip, &se, error) != 0)
    return -1;
  return 0;
}

/* Encode KEY into KMIP as TAG.
   Return 0 if OK, -1 on error. */
static int
kmip_encode_symmetric_key (struct kmip_encoding_state *kmip, guint32 tag,
			   const struct kmip_symmetric_key *key,
			   GError **error)
{
  struct struct_encoding se;

  if (se_start (kmip, &se, tag, error) != 0
      || add_bytes (kmip, KMIP_TAG_KEY, key->data, key->len, error) != 0
      || se_end (kmip, &se, error) != 0)
    return -1;
  return 0;
}

/* Encode VALUE into KMIP as TAG.
   Return 0 if OK, -1 on error. */
static int
kmip_encode_key_value (struct kmip_encoding_state *kmip, guint32 tag,
		       const struct kmip_key_value *value, GError **error)
{
  struct struct_encoding se;
  size_t i;

  if (se_start (kmip, &se, tag, error) != 0)
    return -1;
  switch (value->type)
    {
    case KMIP_KEY_VALUE_BYTES:
      if (add_bytes (kmip, KMIP_TAG_KEY_MATERIAL, value->v.bytes.data,
		     value->v.bytes.len, error) != 0)
	return -1;
      break;

    case KMIP_KEY_VALUE_SYMMETRIC_KEY:
      if (kmip_encode_symmetric_key (kmip, KMIP_TAG_KEY_MATERIAL, value->v.key,
				     error) != 0)
	return -1;
      break;

    default:
      g_return_val_if_reached (-1);
    }
  for (i = 0; i < value->attributes->len; i++)
    {
      if (kmip_encode_attribute (kmip, KMIP_TAG_ATTRIBUTE,
				 g_ptr_array_index(value->attributes, i),
				 error) != 0)
	return -1;
    }
  if (se_end (kmip, &se, error) != 0)
    return -1;
  return 0;
}

/* Encode INFO into KMIP as TAG.
   Return 0 if OK, -1 on error. */
static int
kmip_encode_encryption_key_info (struct kmip_encoding_state *kmip, guint32 tag,
				 const struct kmip_encryption_key_info *info,
				 GError **error)
{
  struct struct_encoding se;

  if (se_start (kmip, &se, tag, error) != 0
      || add_string (kmip, KMIP_TAG_UNIQUE_IDENTIFIER, info->identifier,
		     error) != 0)
    return -1;
  if (info->params != NULL
      && kmip_encode_crypto_params (kmip, KMIP_TAG_CRYPTO_PARAMS, info->params,
				    error) != 0)
    return -1;
  if (se_end (kmip, &se, error) != 0)
    return -1;
  return 0;
}

/* Encode WRAPPING into KMIP as TAG.
   Return 0 if OK, -1 on error. */
static int
kmip_encode_key_wrapping_data (struct kmip_encoding_state *kmip, guint32 tag,
			       const struct kmip_key_wrapping_data *wrapping,
			       GError **error)
{
  struct struct_encoding se;

  if (se_start (kmip, &se, tag, error) != 0
      || add_enum (kmip, KMIP_TAG_WRAPPING_METHOD, wrapping->method,
		   error) != 0)
    return -1;
  if (wrapping->encryption_key != NULL
      && kmip_encode_encryption_key_info (kmip, KMIP_TAG_ENCRYPTION_KEY_INFO,
					  wrapping->encryption_key, error) != 0)
    return -1;
  if (wrapping->iv != NULL
      && add_bytes (kmip, KMIP_TAG_IV_COUNTER_NONCE, wrapping->iv,
		    wrapping->iv_len, error) != 0)
    return -1;
  if (se_end (kmip, &se, error) != 0)
    return -1;
  return 0;
}

/* Encode BLOCK into KMIP as TAG.
   Return 0 if OK, -1 on error. */
static int
kmip_encode_key_block (struct kmip_encoding_state *kmip, guint32 tag,
		       const struct kmip_key_block *block, GError **error)
{
  struct struct_encoding se;

  g_return_val_if_fail (((block->type == KMIP_KEY_OPAQUE
			  || block->wrapping != NULL)
			 && block->value->type == KMIP_KEY_VALUE_BYTES)
			|| (block->type == KMIP_KEY_TRANSPARENT_SYMMETRIC
			    && block->wrapping == NULL
			    && (block->value->type
				== KMIP_KEY_VALUE_SYMMETRIC_KEY)), -1);
  if (se_start (kmip, &se, tag, error) != 0
      || add_enum (kmip, KMIP_TAG_KEY_VALUE_TYPE, block->type, error) != 0
      || kmip_encode_key_value (kmip, KMIP_TAG_KEY_VALUE, block->value,
				error) != 0)
    return -1;
  if (block->crypto_algorithm != KMIP_LIBVK_ENUM_NONE
      && add_enum (kmip, KMIP_TAG_CRYPTO_ALGORITHM, block->crypto_algorithm,
		   error) != 0)
    return -1;
  if (block->crypto_length >= 0
      && add_int32 (kmip, KMIP_TAG_CRYPTO_LENGTH, block->crypto_length,
		    error) != 0)
    return -1;
  if (block->wrapping != NULL
      && kmip_encode_key_wrapping_data (kmip, KMIP_TAG_KEY_WRAPPING_DATA,
					block->wrapping, error) != 0)
    return -1;
  if (se_end (kmip, &se, error) != 0)
    return -1;
  return 0;
}

/* Encode OBJ into KMIP as TAG.
   Return 0 if OK, -1 on error. */
static int
kmip_encode_object_symmetric_key (struct kmip_encoding_state *kmip, guint32 tag,
				  const struct kmip_object_symmetric_key *obj,
				  GError **error)
{
  struct struct_encoding se;

  if (se_start (kmip, &se, tag, error) != 0
      || kmip_encode_key_block (kmip, KMIP_TAG_KEY_BLOCK, obj->block,
				error) != 0
      || se_end (kmip, &se, error) != 0)
    return -1;
  return 0;
}

/* Encode OBJ into KMIP as TAG.
   Return 0 if OK, -1 on error. */
static int
kmip_encode_object_secret_data (struct kmip_encoding_state *kmip, guint32 tag,
				const struct kmip_object_secret_data *obj,
				GError **error)
{
  struct struct_encoding se;

  if (se_start (kmip, &se, tag, error) != 0
      || add_enum (kmip, KMIP_TAG_SECRET_DATA_TYPE, obj->type, error) != 0
      || kmip_encode_key_block (kmip, KMIP_TAG_KEY_BLOCK, obj->block,
				error) != 0
      || se_end (kmip, &se, error) != 0)
    return -1;
  return 0;
}

/* Encode VERSION into KMIP as TAG.
   Return 0 if OK, -1 on error. */
static int
kmip_encode_protocol_version (struct kmip_encoding_state *kmip, guint32 tag,
			      const struct kmip_protocol_version *version,
			      GError **error)
{
  struct struct_encoding se;

  if (se_start (kmip, &se, tag, error) != 0
      || add_int32 (kmip, KMIP_TAG_PROTOCOL_VERSION_MAJOR, version->major,
		    error) != 0
      || add_int32 (kmip, KMIP_TAG_PROTOCOL_VERSION_MINOR, version->minor,
		    error) != 0
      || se_end (kmip, &se, error) != 0)
    return -1;
  return 0;
}

/* Encode PACKET into KMIP as TAG.
   Return 0 if OK, -1 on error. */
static int
kmip_encode_libvk_packet (struct kmip_encoding_state *kmip, guint32 tag,
			  const struct kmip_libvk_packet *packet,
			  GError **error)
{
  struct struct_encoding se;

  if (se_start (kmip, &se, tag, error) != 0
      || kmip_encode_protocol_version (kmip, KMIP_TAG_PROTOCOL_VERSION,
				       packet->version, error) != 0
      || add_enum (kmip, KMIP_TAG_OBJECT_TYPE, packet->type, error) != 0)
    return -1;
  switch (packet->type)
    {
    case KMIP_OBJECT_SYMMETRIC_KEY:
      if (kmip_encode_object_symmetric_key (kmip, KMIP_TAG_SYMMETRIC_KEY,
					    packet->v.symmetric, error) != 0)
	return -1;
      break;

    case KMIP_OBJECT_SECRET_DATA:
      if (kmip_encode_object_secret_data (kmip, KMIP_TAG_SECRET_DATA,
					  packet->v.secret_data, error) != 0)
	return -1;
      break;

    default:
      g_return_val_if_reached(-1);
    }
  if (se_end (kmip, &se, error) != 0)
    return -1;
  return 0;
}

 /* KMIP decoding */

/* Check if KMIP, positioned at the start of an item, starts with TAG */
gboolean
kmip_next_tag_is (const struct kmip_decoding_state *kmip, guint32 tag)
{
  guint32 t;

  if (kmip->left < sizeof (t))
    return FALSE;
  memcpy (&t, kmip->data, sizeof (tag));
  return GUINT32_FROM_BE (t) == tag;
}

/* Get DATA of SIZE from KMIP.
   Return 0 if OK, -1 if not enough data is available. */
static int
get_data (struct kmip_decoding_state *kmip, void *data, size_t size,
	  GError **error)
{
  if (kmip->left < size)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_NO_DATA,
		   _("Unexpected end of data"));
      return -1;
    }
  memcpy (data, kmip->data, size);
  kmip->data += size;
  kmip->left -= size;
  return 0;
}

/* Decode an item with expected TAG, TYPE and SIZE, copying value into DATA.
   Return 0 if OK, -1 on error */
static int
get_ttlv (struct kmip_decoding_state *kmip, guint32 tag, guint8 type,
	  size_t size, void *val, GError **error)
{
  guint32 tag_be, size_be;
  guint8 real_type;

  if (get_data (kmip, &tag_be, sizeof (tag_be), error) != 0
      || get_data (kmip, &real_type, sizeof (real_type), error) != 0
      || get_data (kmip, &size_be, sizeof (size_be), error) != 0)
    return -1;
  if (GUINT32_FROM_BE (tag_be) != tag)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNEXPECTED_FORMAT,
		   _("Unexpected item tag 0x%08lX"),
		   (unsigned long)GUINT32_FROM_BE (tag_be));
      return -1;
    }
  if (real_type != type)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNEXPECTED_FORMAT,
		   _("Unexpected item type 0x%02X"), (unsigned)real_type);
      return -1;
    }
  if (GUINT32_FROM_BE (size_be) != size)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNEXPECTED_FORMAT,
		   _("Unexpected item size"));
      return -1;
    }
  if (get_data (kmip, val, size, error) != 0)
    return -1;
  return 0;
}

/* Decode an int32 VAL with TAG from KMIP.
   Return 0 if OK, -1 on error */
static int
get_int32 (struct kmip_decoding_state *kmip, gint32 *val, guint32 tag,
	   GError **error)
{
  gint32 val_be;

  if (get_ttlv (kmip, tag, KMIP_ITEM_INT32, sizeof (val_be), &val_be, error)
      != 0)
    return -1;
  *val = GINT32_FROM_BE (val_be);
  return 0;
}

/* Decode an enum VAL with TAG from KMIP.  Make sure the value is in [MIN, END).
   Return 0 if OK, -1 on error */
static int
get_enum (struct kmip_decoding_state *kmip, guint32 *val, guint32 tag,
	  guint32 min, guint32 end, GError **error)
{
  guint32 val_be, v;

  if (get_ttlv (kmip, tag, KMIP_ITEM_ENUM, sizeof (val_be), &val_be, error)
      != 0)
    return -1;
  v = GUINT32_FROM_BE (val_be);
  if (v < min || v >= end)
    {
      gchar num[sizeof (v) * CHAR_BIT + 1];

      g_snprintf (num, sizeof (num), "%" G_GUINT32_FORMAT, v);
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNSUPPORTED_VALUE,
		   _("Unsupported enum value %s"), num);
      return -1;
    }
  *val = v;
  return 0;
}

/* Decode a STRING with TAG from KMIP.
   Return 0 if OK, -1 on error */
static int
get_string (struct kmip_decoding_state *kmip, char **string, guint32 tag,
	    GError **error)
{
  gsize bytes_read;
  guint32 tag_be, size_be, size;
  guint8 type;
  char *s;

  if (get_data (kmip, &tag_be, sizeof (tag_be), error) != 0
      || get_data (kmip, &type, sizeof (type), error) != 0
      || get_data (kmip, &size_be, sizeof (size_be), error) != 0)
    return -1;
  if (GUINT32_FROM_BE (tag_be) != tag)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNEXPECTED_FORMAT,
		   _("Unexpected item tag 0x%08lX"),
		   (unsigned long)GUINT32_FROM_BE (tag_be));
      return -1;
    }
  if (type != KMIP_ITEM_STRING)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNEXPECTED_FORMAT,
		   _("String item expected, got %02X"), (unsigned)type);
      return -1;
    }
  size = GUINT32_FROM_BE (size_be);
  if (kmip->left < size)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_NO_DATA,
		   _("Unexpected end of data"));
      return -1;
    }
  /* We really want simply "size > G_MAXSSIZE", but we must hide it from GCC to
     avoid a warning on architecures where G_MAXUINT32 <= G_MAXSSIZE. */
  {
    uintmax_t x;

    x = size;
    memmove (&x, &x, 1); /* "Hide x from GCC" */
    if (x > G_MAXSSIZE)
      {
	g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_INPUT_OVERFLOW,
		     _("A string is too long"));
	return -1;
      }
  }
  s = g_locale_from_utf8 ((const gchar *)kmip->data, size, &bytes_read, NULL,
			  error);
  kmip->data += size;
  kmip->left -= size;
  *string = s;
  return 0;
}

/* Decode binary data with TAG from KMIP.
   Return 0 if OK, -1 on error.
   Store data into BYTES (for g_free()) and its size into SIZE. */
static int
get_bytes (struct kmip_decoding_state *kmip, void **bytes, size_t *size,
	   guint32 tag, GError **error)
{
  guint32 tag_be, size_be;
  guint8 type;
  size_t s;

  if (get_data (kmip, &tag_be, sizeof (tag_be), error) != 0
      || get_data (kmip, &type, sizeof (type), error) != 0
      || get_data (kmip, &size_be, sizeof (size_be), error) != 0)
    return -1;
  if (GUINT32_FROM_BE (tag_be) != tag)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNEXPECTED_FORMAT,
		   _("Unexpected item tag 0x%08lX"),
		   (unsigned long)GUINT32_FROM_BE (tag_be));
      return -1;
    }
  if (type != KMIP_ITEM_BYTES)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNEXPECTED_FORMAT,
		   _("Unexpected item type 0x%02X"), (unsigned)type);
      return -1;
    }
  s = GUINT32_FROM_BE (size_be);
  if (s != GUINT32_FROM_BE (size_be))
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_INPUT_OVERFLOW,
		   _("Binary data is too long"));
      return -1;
    }
  if (kmip->left < s)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_NO_DATA,
		   _("Unexpected end of data"));
      return -1;
    }
  *bytes = g_memdup (kmip->data, s);
  *size = s;
  kmip->data += s;
  kmip->left -= s;
  return 0;
}

/* Start decoding a KMIP_ITEM_STRUCTURE TAG from KMIP, set KMIP2 to only the
   contained structure and advance KMIP past the structure.
   Return 0 if OK, -1 on error. */
static int
sd_start (struct kmip_decoding_state *kmip2, struct kmip_decoding_state *kmip,
	  guint32 tag, GError **error)
{
  guint32 tag_be, size_be;
  guint8 type;

  if (get_data (kmip, &tag_be, sizeof (tag_be), error) != 0
      || get_data (kmip, &type, sizeof (type), error) != 0
      || get_data (kmip, &size_be, sizeof (size_be), error) != 0)
    return -1;
  if (GUINT32_FROM_BE (tag_be) != tag)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNEXPECTED_FORMAT,
		   _("Unexpected item tag 0x%08lX"),
		   (unsigned long)GUINT32_FROM_BE (tag_be));
      return -1;
    }
  if (type != KMIP_ITEM_STRUCTURE)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNEXPECTED_FORMAT,
		   _("Unexpected item type 0x%02X"), (unsigned)type);
      return -1;
    }
  kmip2->data = kmip->data;
  kmip2->left = GUINT32_FROM_BE (size_be);
  if (kmip2->left > kmip->left)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_NO_DATA,
		   _("Structure does not fit in its container"));
      return -1;
    }
  kmip->data += kmip2->left;
  kmip->left -= kmip2->left;
  return 0;
}

/* Verify a structure decoding was correctly finished in KMIP2.
   Return 0 if OK, -1 on error */
static int
sd_end (struct kmip_decoding_state *kmip2, GError **error)
{
  if (kmip2->left != 0)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNEXPECTED_FORMAT,
		   _("Unexpected data in structure"));
      return -1;
    }
  return 0;
}

/* Decode cryptographics parameters TAG from KMIP, store it into PARAMS.
   Return 0 if OK, -1 on error. */
static int
kmip_decode_crypto_params (struct kmip_decoding_state *kmip,
			   struct kmip_crypto_params **params, guint32 tag,
			   GError **error)
{
  struct kmip_decoding_state k;
  struct kmip_crypto_params *res;

  res = g_new0 (struct kmip_crypto_params, 1);
  if (sd_start (&k, kmip, tag, error) != 0)
    goto err;
  if (kmip_next_tag_is (&k, KMIP_TAG_BLOCK_CIPHER_MODE))
    {
      if (get_enum (&k, &res->cipher_mode, KMIP_TAG_BLOCK_CIPHER_MODE, 1,
		    KMIP_END_MODES, error) != 0)
	goto err;
    }
  else
    res->cipher_mode = KMIP_LIBVK_ENUM_NONE;
  if (kmip_next_tag_is (&k, KMIP_TAG_PADDING_METHOD))
    {
      if (get_enum (&k, &res->padding_method, KMIP_TAG_PADDING_METHOD, 1,
		    KMIP_END_PADDINGS, error) != 0)
	goto err;
    }
  else
    res->padding_method = KMIP_LIBVK_ENUM_NONE;
  if (kmip_next_tag_is (&k, KMIP_TAG_HASH_ALGORITHM))
    {
      if (get_enum (&k, &res->hash_algorithm, KMIP_TAG_HASH_ALGORITHM, 1,
		    KMIP_END_HASHES, error) != 0)
	goto err;
    }
  else
    res->hash_algorithm = KMIP_LIBVK_ENUM_NONE;
  if (sd_end (&k, error) != 0)
    goto err;
  *params = res;
  return 0;

 err:
  kmip_crypto_params_free (res);
  return -1;
}

/* Decode an attribute TAG from KMIP, store it into ATTR.
   Return 0 if OK, -1 on error. */
static int
kmip_decode_attribute (struct kmip_decoding_state *kmip,
		       struct kmip_attribute **attr, guint32 tag,
		       GError **error)
{
  struct kmip_decoding_state k;
  struct kmip_attribute *res;

  res = g_new0 (struct kmip_attribute, 1);
  /* Something safe for kmip_attribute_free () */
  res->tag = KMIP_TAG_CRYPTO_LENGTH;
  if (sd_start (&k, kmip, tag, error) != 0)
    goto err;
  if (get_string (&k, &res->name, KMIP_TAG_ATTRIBUTE_NAME, error) != 0)
    goto err;
  if (strcmp (res->name, KMIP_ATTR_CRYPTO_ALGORITHM) == 0)
    {
      res->tag = KMIP_TAG_CRYPTO_ALGORITHM;
      if (get_enum (&k, &res->v.enum_value, KMIP_TAG_ATTRIBUTE_VALUE, 1,
		    KMIP_END_ALGORITHMS, error) != 0)
	goto err;
    }
  else if (strcmp (res->name, KMIP_ATTR_CRYPTO_LENGTH) == 0)
    {
      res->tag = KMIP_TAG_CRYPTO_LENGTH;
      if (get_int32 (&k, &res->v.int32_value, KMIP_TAG_ATTRIBUTE_VALUE,
		     error) != 0)
	goto err;
      if (res->v.int32_value <= 0)
	{
	  g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_INVALID_INPUT,
		       _("Number of key bits is not positive"));
	  goto err;
	}
    }
  else if (strcmp (res->name, KMIP_ATTR_CRYPTO_PARAMS) == 0)
    {
      res->tag = KMIP_TAG_CRYPTO_PARAMS;
      if (kmip_decode_crypto_params (&k, &res->v.crypto_params,
				     KMIP_TAG_ATTRIBUTE_VALUE, error) != 0)
	goto err;
    }
  else if (strcmp (res->name, KMIP_ATTR_APP_SPECIFIC) == 0
	   || strcmp (res->name, KMIP_ATTR_LIBVK_LUKS_CIPHER) == 0
	   || strcmp (res->name, KMIP_ATTR_LIBVK_LUKS_MODE) == 0)
    {
      struct kmip_decoding_state k2;

      res->tag = KMIP_TAG_APP_SPECIFIC;
      if (sd_start (&k2, &k, KMIP_TAG_ATTRIBUTE_VALUE, error) != 0
	  || get_string (&k2, &res->v.strings.name, KMIP_TAG_APP_NAME_SPACE,
			 error) != 0
	  || get_string (&k2, &res->v.strings.value, KMIP_TAG_APP_ID,
			 error) != 0
	  || sd_end (&k2, error) != 0)
	goto err;
    }
  if (sd_end (&k, error) != 0)
    goto err;
  *attr = res;
  return 0;

 err:
  kmip_attribute_free (res);
  return -1;
}

/* Decode a symmetric key TAG from KMIP, store it into KEY.
   Return 0 if OK, -1 on error. */
static int
kmip_decode_symmetric_key (struct kmip_decoding_state *kmip,
			   struct kmip_symmetric_key **key, guint32 tag,
			   GError **error)
{
  struct kmip_decoding_state k;
  struct kmip_symmetric_key *res;

  res = g_new0 (struct kmip_symmetric_key, 1);
  if (sd_start (&k, kmip, tag, error) != 0
      || get_bytes (&k, &res->data, &res->len, KMIP_TAG_KEY, error) != 0
      || sd_end (&k, error) != 0)
    goto err;
  *key = res;
  return 0;

 err:
  kmip_symmetric_key_free (res);
  return -1;
}

/* Decode a key value TAG from KMIP (given BLOCK_TYPE from enclosing
   kmip_key_block), store it into VALUE.
   Return 0 if OK, -1 on error. */
static int
kmip_decode_key_value (struct kmip_decoding_state *kmip,
		       struct kmip_key_value **value, guint32 tag,
		       guint32 block_type, GError **error)
{
  struct kmip_decoding_state k;
  struct kmip_key_value *res;

  res = g_new0 (struct kmip_key_value, 1);
  res->type = KMIP_KEY_VALUE_BYTES;
  if (sd_start (&k, kmip, tag, error) != 0)
    goto err;
  switch (block_type)
    {
    case KMIP_KEY_OPAQUE:
      if (get_bytes (&k, &res->v.bytes.data, &res->v.bytes.len,
		     KMIP_TAG_KEY_MATERIAL, error) != 0)
	goto err;
      res->type = KMIP_KEY_VALUE_BYTES;
      break;

    case KMIP_KEY_TRANSPARENT_SYMMETRIC:
      if (kmip_decode_symmetric_key (&k, &res->v.key, KMIP_TAG_KEY_MATERIAL,
				     error) != 0)
	goto err;
      res->type = KMIP_KEY_VALUE_SYMMETRIC_KEY;
      break;

    default:
      g_return_val_if_reached (-1);
    }
  res->attributes = g_ptr_array_new ();
  while (k.left != 0)
    {
      struct kmip_attribute *a;

      if (kmip_decode_attribute (&k, &a, KMIP_TAG_ATTRIBUTE, error) != 0)
	goto err;
      g_ptr_array_add (res->attributes, a);
    }
  if (sd_end (&k, error) != 0)
    goto err;
  *value = res;
  return 0;

 err:
  kmip_key_value_free (res);
  return -1;
}

/* Decode an encryption key info TAG from KMIP, store it into INFO.
   Return 0 if OK, -1 on error. */
static int
kmip_decode_encryption_key_info (struct kmip_decoding_state *kmip,
				 struct kmip_encryption_key_info **info,
				 guint32 tag, GError **error)
{
  struct kmip_decoding_state k;
  struct kmip_encryption_key_info *res;

  res = g_new0 (struct kmip_encryption_key_info, 1);
  if (sd_start (&k, kmip, tag, error) != 0
      || get_string (&k, &res->identifier, KMIP_TAG_UNIQUE_IDENTIFIER,
		     error) != 0)
    goto err;
  if (kmip_next_tag_is (&k, KMIP_TAG_CRYPTO_PARAMS))
    {
      if (kmip_decode_crypto_params (&k, &res->params, KMIP_TAG_CRYPTO_PARAMS,
				     error) != 0)
	goto err;
    }
  else
    res->params = NULL;
  if (sd_end (&k, error) != 0)
    goto err;
  *info = res;
  return 0;

 err:
  kmip_encryption_key_info_free (res);
  return -1;
}

/* Decode a key wrapping data TAG from KMIP, store it into WRAPPING.
   Return 0 if OK, -1 on error. */
static int
kmip_decode_key_wrapping_data (struct kmip_decoding_state *kmip,
			       struct kmip_key_wrapping_data **wrapping,
			       guint32 tag, GError **error)
{
  struct kmip_decoding_state k;
  struct kmip_key_wrapping_data *res;

  res = g_new0 (struct kmip_key_wrapping_data, 1);
  if (sd_start (&k, kmip, tag, error) != 0
      /* Only one supported value */
      || get_enum (&k, &res->method, KMIP_TAG_WRAPPING_METHOD,
		   KMIP_WRAPPING_LIBVK_ENCRYPT_KEY_ONLY,
		   KMIP_WRAPPING_LIBVK_ENCRYPT_KEY_ONLY + 1, error) != 0)
    goto err;
  if (kmip_next_tag_is (&k, KMIP_TAG_ENCRYPTION_KEY_INFO))
    {
      if (kmip_decode_encryption_key_info (&k, &res->encryption_key,
					   KMIP_TAG_ENCRYPTION_KEY_INFO,
					   error) != 0)
	goto err;
    }
  else
    res->encryption_key = NULL;
  if (kmip_next_tag_is (&k, KMIP_TAG_IV_COUNTER_NONCE))
    {
      if (get_bytes (&k, &res->iv, &res->iv_len, KMIP_TAG_IV_COUNTER_NONCE,
		     error) != 0)
	goto err;
    }
  else
    res->iv = NULL;
  if (sd_end (&k, error) != 0)
    goto err;
  *wrapping = res;
  return 0;

 err:
  kmip_key_wrapping_data_free (res);
  return -1;
}

/* Decode a key block TAG from KMIP, store it into BLOCK.
   Return 0 if OK, -1 on error. */
static int
kmip_decode_key_block (struct kmip_decoding_state *kmip,
		       struct kmip_key_block **block, guint32 tag,
		       GError **error)
{
  struct kmip_decoding_state k;
  struct kmip_key_block *res;

  res = g_new0 (struct kmip_key_block, 1);
  if (sd_start (&k, kmip, tag, error) != 0
      || get_enum (&k, &res->type, KMIP_TAG_KEY_VALUE_TYPE, 1, KMIP_END_KEYS,
		   error) != 0)
    goto err;
  if (res->type != KMIP_KEY_OPAQUE
      && res->type != KMIP_KEY_TRANSPARENT_SYMMETRIC)
    {
      gchar num[sizeof (res->type) * CHAR_BIT + 1];

      g_snprintf (num, sizeof (num), "%" G_GUINT32_FORMAT, res->type);
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNSUPPORTED_VALUE,
		   _("Unsupported enum value %s"), num);
      goto err;
    }
  if (kmip_decode_key_value (&k, &res->value, KMIP_TAG_KEY_VALUE, res->type,
			     error) != 0)
    goto err;
  if (kmip_next_tag_is (&k, KMIP_TAG_CRYPTO_ALGORITHM))
    {
      if (get_enum (&k, &res->crypto_algorithm, KMIP_TAG_CRYPTO_ALGORITHM, 1,
		    KMIP_END_ALGORITHMS, error) != 0)
	goto err;
    }
  else
    res->crypto_algorithm = KMIP_LIBVK_ENUM_NONE;
  if (kmip_next_tag_is (&k, KMIP_TAG_CRYPTO_LENGTH))
    {
      if (get_int32 (&k, &res->crypto_length, KMIP_TAG_CRYPTO_LENGTH,
		     error) != 0)
	goto err;
      if (res->crypto_length <= 0)
	{
	  g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_INVALID_INPUT,
		       _("Number of key bits is not positive"));
	  goto err;
	}
    }
  else
    res->crypto_length = -1;
  if (kmip_next_tag_is (&k, KMIP_TAG_KEY_WRAPPING_DATA))
    {
      if (kmip_decode_key_wrapping_data (&k, &res->wrapping,
					 KMIP_TAG_KEY_WRAPPING_DATA,
					 error) != 0)
	goto err;
      if (res->type != KMIP_KEY_OPAQUE)
	{
	  g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNEXPECTED_FORMAT,
		       _("Wrapped key is not opaque"));
	  goto err;
	}
    }
  else
    res->wrapping = NULL;
  if (sd_end (&k, error) != 0)
    goto err;
  *block = res;
  return 0;

 err:
  kmip_key_block_free (res);
  return -1;
}

/* Decode a symmetric key object TAG from KMIP, store it into OBJ.
   Return 0 if OK, -1 on error. */
static int
kmip_decode_object_symmetric_key (struct kmip_decoding_state *kmip,
				  struct kmip_object_symmetric_key **obj,
				  guint32 tag, GError **error)
{
  struct kmip_decoding_state k;
  struct kmip_object_symmetric_key *res;

  res = g_new0 (struct kmip_object_symmetric_key, 1);
  if (sd_start (&k, kmip, tag, error) != 0
      || kmip_decode_key_block (&k, &res->block, KMIP_TAG_KEY_BLOCK, error) != 0
      || sd_end (&k, error) != 0)
    goto err;
  if (res->block->wrapping == NULL
      && res->block->type != KMIP_KEY_TRANSPARENT_SYMMETRIC)
    {
      gchar num[sizeof (res->block->type) * CHAR_BIT + 1];

      g_snprintf (num, sizeof (num), "%" G_GUINT32_FORMAT, res->block->type);
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNSUPPORTED_VALUE,
		   _("Unsupported symmetric key format %s"), num);
      return -1;
    }
  *obj = res;
  return 0;

 err:
  kmip_object_symmetric_key_free (res);
  return -1;
}

/* Decode a secret data object TAG from KMIP, store it into OBJ.
   Return 0 if OK, -1 on error. */
static int
kmip_decode_object_secret_data (struct kmip_decoding_state *kmip,
				struct kmip_object_secret_data **obj,
				guint32 tag, GError **error)
{
  struct kmip_decoding_state k;
  struct kmip_object_secret_data *res;

  res = g_new0 (struct kmip_object_secret_data, 1);
  if (sd_start (&k, kmip, tag, error) != 0
      /* Only one supported value */
      || get_enum (&k, &res->type, KMIP_TAG_SECRET_DATA_TYPE,
		   KMIP_SECRET_DATA_PASSWORD, KMIP_SECRET_DATA_PASSWORD + 1,
		   error) != 0
      || kmip_decode_key_block (&k, &res->block, KMIP_TAG_KEY_BLOCK, error) != 0
      || sd_end (&k, error) != 0)
    goto err;
  if (res->block->wrapping == NULL && res->block->type != KMIP_KEY_OPAQUE)
    {
      gchar num[sizeof (res->block->type) * CHAR_BIT + 1];

      g_snprintf (num, sizeof (num), "%" G_GUINT32_FORMAT, res->block->type);
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNSUPPORTED_VALUE,
		   _("Unsupported symmetric key format %s"), num);
      return -1;
    }
  *obj = res;
  return 0;

 err:
  kmip_object_secret_data_free (res);
  return -1;
}

/* Decode version TAG from KMIP, store it into VERSION.
   Return 0 if OK, -1 on error. */
static int
kmip_decode_protocol_version (struct kmip_decoding_state *kmip,
			      struct kmip_protocol_version **version,
			      guint32 tag, GError **error)
{
  struct kmip_decoding_state k;
  struct kmip_protocol_version *res;

  res = g_new0 (struct kmip_protocol_version, 1);
  if (sd_start (&k, kmip, tag, error) != 0
      || get_int32 (&k, &res->major, KMIP_TAG_PROTOCOL_VERSION_MAJOR,
		    error) != 0
      || get_int32 (&k, &res->minor, KMIP_TAG_PROTOCOL_VERSION_MINOR,
		    error) != 0
      || sd_end (&k, error) != 0)
    goto err;
  if (res->major != KMIP_VERSION_MAJOR || res->minor != KMIP_VERSION_MINOR)
    {
      gchar major[sizeof (res->major) * CHAR_BIT + 1];
      gchar minor[sizeof (res->minor) * CHAR_BIT + 1];

      g_snprintf (major, sizeof (major), "%" G_GINT32_FORMAT, res->major);
      g_snprintf (minor, sizeof (minor), "%" G_GINT32_FORMAT, res->minor);
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNSUPPORTED_VALUE,
		   _("Unsupported KMIP version %s.%s"), major, minor);
      goto err;
    }
  *version = res;
  return 0;

 err:
  kmip_protocol_version_free (res);
  return -1;
}

/* Decode packet with TAG from KMIP, store it into PACKET.
   Return 0 if OK, -1 on error. */
static int
kmip_decode_libvk_packet (struct kmip_decoding_state *kmip,
			  struct kmip_libvk_packet **packet, guint32 tag,
			  GError **error)
{
  struct kmip_decoding_state k;
  struct kmip_libvk_packet *res;

  res = g_new0 (struct kmip_libvk_packet, 1);
  /* Something safe for kmip_libvk_packet_free (). */
  res->type = KMIP_OBJECT_SYMMETRIC_KEY;
  if (sd_start (&k, kmip, tag, error) != 0
      || kmip_decode_protocol_version (&k, &res->version,
				       KMIP_TAG_PROTOCOL_VERSION, error) != 0
      || get_enum (&k, &res->type, KMIP_TAG_OBJECT_TYPE, 1, KMIP_END_OBJECTS,
		   error) != 0)
    goto err;
  switch (res->type)
    {
    case KMIP_OBJECT_SYMMETRIC_KEY:
      if (kmip_decode_object_symmetric_key (&k, &res->v.symmetric,
					    KMIP_TAG_SYMMETRIC_KEY, error) != 0)
	goto err;
      break;

    case KMIP_OBJECT_SECRET_DATA:
      if (kmip_decode_object_secret_data (&k, &res->v.secret_data,
					  KMIP_TAG_SECRET_DATA, error) != 0)
	goto err;
      break;

    default:
      {
	gchar num[sizeof (res->type) * CHAR_BIT + 1];

	g_snprintf (num, sizeof (num), "%" G_GUINT32_FORMAT, res->type);
	g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNSUPPORTED_VALUE,
		   _("Unsupported object type %s"), num);
	goto err;
      }
    }
  if (sd_end (&k, error) != 0)
    goto err;
  *packet = res;
  return 0;

 err:
  kmip_libvk_packet_free (res);
  return -1;
}

 /* Packet-level operations */

/* Update kmip_libvk_packet_unwrap_secret_asymmetric() if additional mechanisms
   are introduced. */
struct mech_data
{
  CK_MECHANISM_TYPE mechanism;
  guint32 algorithm, mode, padding;
};

static const struct mech_data asymmetric_mechanisms[] =
  {
    {
      CKM_RSA_PKCS, KMIP_ALGORITHM_RSA, KMIP_LIBVK_ENUM_NONE,
      KMIP_PADDING_PKCS1_v1_5
    }
  };

static const struct mech_data symmetric_mechanisms[] =
  {
    { CKM_DES_ECB, KMIP_ALGORITHM_DES, KMIP_MODE_ECB, KMIP_PADDING_NONE },
    { CKM_DES_CBC, KMIP_ALGORITHM_DES, KMIP_MODE_CBC, KMIP_PADDING_NONE },
    { CKM_DES_CBC_PAD, KMIP_ALGORITHM_DES, KMIP_MODE_CBC, KMIP_PADDING_PKCS5 },
    { CKM_DES3_ECB, KMIP_ALGORITHM_3DES, KMIP_MODE_ECB, KMIP_PADDING_NONE },
    { CKM_DES3_CBC, KMIP_ALGORITHM_3DES, KMIP_MODE_CBC, KMIP_PADDING_NONE },
    {
      CKM_DES3_CBC_PAD, KMIP_ALGORITHM_3DES, KMIP_MODE_CBC, KMIP_PADDING_PKCS5
    },
    { CKM_AES_ECB, KMIP_ALGORITHM_AES, KMIP_MODE_ECB, KMIP_PADDING_NONE },
    { CKM_AES_CBC, KMIP_ALGORITHM_AES, KMIP_MODE_CBC, KMIP_PADDING_NONE },
    { CKM_AES_CBC_PAD, KMIP_ALGORITHM_AES, KMIP_MODE_CBC, KMIP_PADDING_PKCS5 },
  };

/* Decode PACKET of SIZE.
   Return KMIP packet (for kmip_libvk_packet_free ()) if OK, NULL on error. */
struct kmip_libvk_packet *
kmip_libvk_packet_decode (const void *packet, size_t size, GError **error)
{
  struct kmip_decoding_state kmip;
  struct kmip_libvk_packet *pack;

  kmip.data = packet;
  kmip.left = size;
  if (kmip_decode_libvk_packet (&kmip, &pack, KMIP_TAG_LIBVK_PACKET,
				error) != 0)
    goto err;
  if (kmip.left != 0)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNEXPECTED_FORMAT,
		   _("Unexpected data after packet"));
      goto err_pack;
    }
  return pack;

 err_pack:
  kmip_libvk_packet_free (pack);
 err:
  return NULL;
}

/* Drop secrets in PACKET. */
void
kmip_libvk_packet_drop_secret (struct kmip_libvk_packet *packet)
{
  struct kmip_key_block *block;

  switch (packet->type)
    {
    case KMIP_OBJECT_SYMMETRIC_KEY:
      block = packet->v.symmetric->block;
      block->type = KMIP_KEY_TRANSPARENT_SYMMETRIC;
      kmip_key_value_free_v (block->value);
      block->value->type = KMIP_KEY_VALUE_BYTES;
      block->value->v.bytes.data = NULL;
      block->value->v.bytes.len = 0;
      break;

    case KMIP_OBJECT_SECRET_DATA:
      block = packet->v.secret_data->block;
      block->type = KMIP_KEY_OPAQUE;
      kmip_key_value_free_v (block->value);
      block->value->type = KMIP_KEY_VALUE_SYMMETRIC_KEY;
      block->value->v.key = NULL;
      break;

    default:
      g_return_if_reached ();
    }

  block->crypto_algorithm = KMIP_LIBVK_ENUM_NONE;
  block->crypto_length = -1;
  if (block->wrapping != NULL)
    {
      kmip_key_wrapping_data_free (block->wrapping);
      block->wrapping = NULL;
    }
}

/* Encode PACKET, set SIZE to its size.
   Return packet data (for g_free ()) if OK, NULL on error. */
void *
kmip_libvk_packet_encode (struct kmip_libvk_packet *packet, size_t *size,
			  GError **error)
{
  struct kmip_encoding_state kmip;

  kmip.data = NULL;
  kmip.offset = 0;
  kmip.size = SIZE_MAX;
  if (kmip_encode_libvk_packet (&kmip, KMIP_TAG_LIBVK_PACKET, packet,
				error) != 0)
    return NULL;
  kmip.data = g_malloc (kmip.offset);
  kmip.size = kmip.offset;
  kmip.offset = 0;
  if (kmip_encode_libvk_packet (&kmip, KMIP_TAG_LIBVK_PACKET, packet,
				error) != 0)
    g_return_val_if_reached (NULL);
  *size = kmip.size;
  return kmip.data;
}

/* Modify PACKET to wrap its secret using CERT.
   Return 0 if OK, -1 on error.
   May use UI. */
int
kmip_libvk_packet_wrap_secret_asymmetric (struct kmip_libvk_packet *packet,
					  CERTCertificate *cert,
					  const struct libvk_ui *ui,
					  GError **error)
{
  struct kmip_key_block *key_block;
  struct kmip_encryption_key_info *encryption_key;
  const void *clear_secret;
  size_t clear_secret_len, wrapped_secret_len, issuer_len, sn_len;
  void *wrapped_secret, *issuer, *sn;
  CK_MECHANISM_TYPE mechanism;
  const struct mech_data *mech;
  gchar *base64_issuer, *base64_sn;

  switch (packet->type)
    {
    case KMIP_OBJECT_SYMMETRIC_KEY:
      key_block = packet->v.symmetric->block;
      clear_secret = key_block->value->v.key->data;
      clear_secret_len = key_block->value->v.key->len;
      break;

    case KMIP_OBJECT_SECRET_DATA:
      key_block = packet->v.secret_data->block;
      clear_secret = key_block->value->v.bytes.data;
      clear_secret_len = key_block->value->v.bytes.len;
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
  g_return_val_if_fail (key_block->wrapping == NULL, -1);

  if (wrap_asymmetric (&wrapped_secret, &wrapped_secret_len, &issuer,
		       &issuer_len, &sn, &sn_len, &mechanism, clear_secret,
		       clear_secret_len, cert, ui->nss_pwfn_arg, error) != 0)
    goto err;
  for (mech = asymmetric_mechanisms;
       mech < asymmetric_mechanisms + G_N_ELEMENTS (asymmetric_mechanisms);
       mech++)
    {
      if (mech->mechanism == mechanism)
	goto found_mech;
    }
  g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_UNSUPPORTED_WRAPPING_MECHANISM,
	       _("Unsupported mechanism %lu"), (unsigned long)mechanism);
  goto err_wrapped_secret;

 found_mech:
  base64_issuer = g_base64_encode (issuer, issuer_len);
  base64_sn = g_base64_encode (sn, sn_len);
  encryption_key = g_new (struct kmip_encryption_key_info, 1);
  encryption_key->identifier = g_strdup_printf
    (KMIP_LIBVK_IDENTIFIER_CERT_ISN_PREFIX "%s %s", base64_issuer, base64_sn);
  encryption_key->params = g_new (struct kmip_crypto_params, 1);
  encryption_key->params->cipher_mode = mech->mode;
  encryption_key->params->padding_method = mech->padding;
  encryption_key->params->hash_algorithm = KMIP_LIBVK_ENUM_NONE;
  g_free (base64_sn);
  g_free (base64_issuer);

  kmip_key_value_set_bytes (key_block->value, wrapped_secret,
			    wrapped_secret_len);
  key_block->type = KMIP_KEY_OPAQUE;
  key_block->crypto_algorithm = mech->algorithm;
  key_block->crypto_length = -1;
  key_block->wrapping = g_new (struct kmip_key_wrapping_data, 1);
  key_block->wrapping->method = KMIP_WRAPPING_LIBVK_ENCRYPT_KEY_ONLY;
  key_block->wrapping->encryption_key = encryption_key;
  key_block->wrapping->iv = NULL;
  key_block->wrapping->iv_len = 0;

  g_free (wrapped_secret);
  g_free (issuer);
  g_free (sn);
  return 0;

 err_wrapped_secret:
  g_free (wrapped_secret);
  g_free (issuer);
  g_free (sn);
 err:
  return -1;
}

/* Modify PACKET to unwrap its secret.
   Return 0 if OK, -1 on error.
   May use UI. */
int
kmip_libvk_packet_unwrap_secret_asymmetric (struct kmip_libvk_packet *packet,
					    const struct libvk_ui *ui,
					    GError **error)
{
  struct kmip_key_block *key_block;
  struct kmip_encryption_key_info *encryption_key;
  const struct mech_data *mech;
  gchar **base64;
  void *issuer, *sn, *clear_secret;
  gsize issuer_len, sn_len;
  size_t clear_secret_len;

  switch (packet->type)
    {
    case KMIP_OBJECT_SYMMETRIC_KEY:
      key_block = packet->v.symmetric->block;
      break;

    case KMIP_OBJECT_SECRET_DATA:
      key_block = packet->v.secret_data->block;
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
  g_return_val_if_fail (key_block->wrapping != NULL, -1);

  encryption_key = key_block->wrapping->encryption_key;
  if (key_block->type != KMIP_KEY_OPAQUE
      || key_block->value->type != KMIP_KEY_VALUE_BYTES
      || key_block->wrapping->method != KMIP_WRAPPING_LIBVK_ENCRYPT_KEY_ONLY
      || encryption_key == NULL || encryption_key->params == NULL
      || !g_str_has_prefix (encryption_key->identifier,
			    KMIP_LIBVK_IDENTIFIER_CERT_ISN_PREFIX))
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNEXPECTED_FORMAT,
		   _("Unexpected wrapped key format"));
      goto err;
    }
  for (mech = asymmetric_mechanisms;
       mech < asymmetric_mechanisms + G_N_ELEMENTS (asymmetric_mechanisms);
       mech++)
    {
      if (encryption_key->params->cipher_mode == mech->mode
	  && encryption_key->params->padding_method == mech->padding
	  && key_block->crypto_algorithm == mech->algorithm)
	goto found_mech;
    }
  g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_UNSUPPORTED_WRAPPING_MECHANISM,
	       _("Unsupported wrapping mechanism"));
  goto err;

 found_mech:
  base64 = g_strsplit (encryption_key->identifier
		       + strlen (KMIP_LIBVK_IDENTIFIER_CERT_ISN_PREFIX), " ",
		       0);
  if (g_strv_length (base64) != 2)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNEXPECTED_FORMAT,
		   _("Unexpected wrapped key format"));
      goto err_base64;
    }
  issuer = g_base64_decode (base64[0], &issuer_len);
  sn = g_base64_decode (base64[1], &sn_len);
  g_strfreev (base64);

  /* If more than one mechanism is supported, it will have to be passed to
     unwrap_asymmetric(). */
  clear_secret = unwrap_asymmetric (&clear_secret_len,
				    key_block->value->v.bytes.data,
				    key_block->value->v.bytes.len, issuer,
				    issuer_len, sn, sn_len, ui->nss_pwfn_arg,
				    error);
  g_free (sn);
  g_free (issuer);
  if (clear_secret == NULL)
    goto err;

  kmip_key_block_set_clear_secret (key_block, packet->type, clear_secret,
				   clear_secret_len);

  memset (clear_secret, 0, clear_secret_len);
  g_free (clear_secret);
  return 0;

 err_base64:
  g_strfreev (base64);
 err:
  return -1;
}

/* Modify PACKET to wrap its secret using KEY.
   Return 0 if OK, -1 on error.
   May use UI. */
int
kmip_libvk_packet_wrap_secret_symmetric (struct kmip_libvk_packet *packet,
					 PK11SymKey *key,
					 const struct libvk_ui *ui,
					 GError **error)
{
  struct kmip_key_block *key_block;
  CK_MECHANISM_TYPE mechanism;
  struct kmip_encryption_key_info *encryption_key;
  const void *clear_secret;
  size_t clear_secret_len, wrapped_secret_len, iv_len;
  void *wrapped_secret, *iv;
  const struct mech_data *mech;

  switch (packet->type)
    {
    case KMIP_OBJECT_SYMMETRIC_KEY:
      key_block = packet->v.symmetric->block;
      clear_secret = key_block->value->v.key->data;
      clear_secret_len = key_block->value->v.key->len;
      break;

    case KMIP_OBJECT_SECRET_DATA:
      key_block = packet->v.secret_data->block;
      clear_secret = key_block->value->v.bytes.data;
      clear_secret_len = key_block->value->v.bytes.len;
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
  g_return_val_if_fail (key_block->wrapping == NULL, -1);

  mechanism = PK11_GetMechanism (key);
  if (wrap_symmetric (&wrapped_secret, &wrapped_secret_len, &iv, &iv_len,
		      key, mechanism, clear_secret, clear_secret_len,
		      ui->nss_pwfn_arg, error) != 0)
    goto err;
  for (mech = symmetric_mechanisms;
       mech < symmetric_mechanisms + G_N_ELEMENTS (symmetric_mechanisms);
       mech++)
    {
      if (mech->mechanism == mechanism)
	goto found_mech;
    }
  g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_UNSUPPORTED_WRAPPING_MECHANISM,
	       _("Unsupported mechanism %lu"), (unsigned long)mechanism);
  goto err_wrapped_secret;

 found_mech:
  encryption_key = g_new (struct kmip_encryption_key_info, 1);
  encryption_key->identifier = g_strdup (KMIP_LIBVK_IDENTIFIER_SECRET_KEY);
  encryption_key->params = g_new (struct kmip_crypto_params, 1);
  encryption_key->params->cipher_mode = mech->mode;
  encryption_key->params->padding_method = mech->padding;
  encryption_key->params->hash_algorithm = KMIP_LIBVK_ENUM_NONE;

  kmip_key_value_set_bytes (key_block->value, wrapped_secret,
			    wrapped_secret_len);
  key_block->type = KMIP_KEY_OPAQUE;
  key_block->crypto_algorithm = mech->algorithm;
  key_block->crypto_length = PK11_GetKeyLength (key) * 8;
  if (key_block->crypto_length == 0)
    key_block->crypto_length = -1;
  key_block->wrapping = g_new (struct kmip_key_wrapping_data, 1);
  key_block->wrapping->method = KMIP_WRAPPING_LIBVK_ENCRYPT_KEY_ONLY;
  key_block->wrapping->encryption_key = encryption_key;
  key_block->wrapping->iv = g_memdup (iv, iv_len);
  key_block->wrapping->iv_len = iv_len;

  g_free (iv);
  g_free (wrapped_secret);
  return 0;

 err_wrapped_secret:
  g_free (iv);
  g_free (wrapped_secret);
 err:
  return -1;
}

/* Modify PACKET to unwrap its secret using KEY.
   Return 0 if OK, -1 on error. */
int
kmip_libvk_packet_unwrap_secret_symmetric (struct kmip_libvk_packet *packet,
					   PK11SymKey *key, GError **error)
{
  struct kmip_key_block *key_block;
  struct kmip_encryption_key_info *encryption_key;
  const struct mech_data *mech;
  void *clear_secret;
  size_t clear_secret_len;

  switch (packet->type)
    {
    case KMIP_OBJECT_SYMMETRIC_KEY:
      key_block = packet->v.symmetric->block;
      break;

    case KMIP_OBJECT_SECRET_DATA:
      key_block = packet->v.secret_data->block;
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
  g_return_val_if_fail (key_block->wrapping != NULL, -1);

  encryption_key = key_block->wrapping->encryption_key;
  if (key_block->type != KMIP_KEY_OPAQUE
      || key_block->value->type != KMIP_KEY_VALUE_BYTES
      || key_block->wrapping->method != KMIP_WRAPPING_LIBVK_ENCRYPT_KEY_ONLY
      || encryption_key == NULL || encryption_key->params == NULL)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNEXPECTED_FORMAT,
		   _("Unexpected wrapped key format"));
      goto err;
    }
  for (mech = symmetric_mechanisms;
       mech < symmetric_mechanisms + G_N_ELEMENTS (symmetric_mechanisms);
       mech++)
    {
      if (encryption_key->params->cipher_mode == mech->mode
	  && encryption_key->params->padding_method == mech->padding
	  && key_block->crypto_algorithm == mech->algorithm)
	goto found_mech;
    }
  g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_UNSUPPORTED_WRAPPING_MECHANISM,
	       _("Unsupported wrapping mechanism"));
  goto err;

 found_mech:
  clear_secret = unwrap_symmetric (&clear_secret_len, key, mech->mechanism,
				   key_block->value->v.bytes.data,
				   key_block->value->v.bytes.len,
				   key_block->wrapping->iv,
				   key_block->wrapping->iv != NULL
				   ? key_block->wrapping->iv_len : 0,
				   error);
  if (clear_secret == NULL)
    goto err;

  kmip_key_block_set_clear_secret (key_block, packet->type, clear_secret,
				   clear_secret_len);

  memset (clear_secret, 0, clear_secret_len);
  g_free (clear_secret);
  return 0;

 err:
  return -1;
}

 /* Debug output */

/* Dump KMIP DATA of SIZE to FILE, using indent LEVEL.
   Return total length of the consumed entry. */
static size_t
kmip_dump_sub (FILE *file, const void *data_, size_t size, unsigned level)
{
  const guint8 *data;
  unsigned i;
  size_t consumed;
  guint32 tag, data_size;
  guint8 data_type;

  for (i = 0; i < level; i++)
    fputs ("  ", file);
  consumed = 0;
  data = data_;
#define COPY(VAR)							\
  do									\
    {									\
      if (size - consumed < sizeof (VAR))				\
	{								\
	  fprintf (file, "ERROR: Only %zu bytes left\n", size - consumed); \
	  return size;							\
	}								\
      memcpy (&(VAR), data, sizeof (VAR));				\
      data += sizeof (VAR);						\
      consumed += sizeof (VAR);						\
    }									\
  while (0)

  COPY (tag);
  fprintf (file, "0x%08lX: ", (unsigned long)GUINT32_FROM_BE (tag));
  COPY (data_type);
  COPY (data_size);
  data_size = GUINT32_FROM_BE (data_size);
  switch (data_type)
    {
#define CHECK_DATA_SIZE(VALUE)						\
      do								\
	{								\
	  if (data_size != (VALUE))					\
	    {								\
	      fprintf (file,						\
		       "ERROR: unexpected data size %" G_GUINT32_FORMAT "\n", \
		       data_size);					\
	      return consumed + data_size;				\
	    }								\
	}								\
      while (0)

    case KMIP_ITEM_INT32:
      {
	gint32 v;

	CHECK_DATA_SIZE (4);
	COPY (v);
	fprintf (file, "int32 %" G_GINT32_FORMAT "\n", GINT32_FROM_BE (v));
	break;
      }

    case KMIP_ITEM_INT64:
      {
	gint64 v;

	CHECK_DATA_SIZE (8);
	COPY (v);
	fprintf (file, "int64 %" G_GINT64_FORMAT "\n", GINT64_FROM_BE (v));
	break;
      }

    case KMIP_ITEM_BIGNUM:
      {
	fputs ("bignum 0x", file);
	while (data_size != 0)
	  {
	    guint8 v;

	    COPY (v);
	    fprintf (file, "%02X", (unsigned)v);
	    data_size--;
	  }
	putc ('\n', file);
	break;
      }

    case KMIP_ITEM_ENUM:
      {
	guint32 v;

	CHECK_DATA_SIZE (4);
	COPY (v);
	fprintf (file, "enum %" G_GUINT32_FORMAT "\n", GUINT32_FROM_BE (v));
	break;
      }

    case KMIP_ITEM_BOOLEAN:
      {
	guint8 v;

	CHECK_DATA_SIZE (1);
	COPY (v);
	fprintf (file, "bool %u\n", (unsigned)v);
	break;
      }

    case KMIP_ITEM_STRING:
      {
	char *t;
	gsize bytes_read;

	if ((size_t)data_size != data_size)
	  fprintf (file, "ERROR: string size %" G_GUINT32_FORMAT " too large\n",
		   data_size);
	if (size - consumed < data_size)
	  {
	    fprintf (file, "ERROR: Only %zu bytes left\n", size - consumed);
	    return size;
	  }
	t = g_locale_from_utf8 ((const gchar *)data, data_size, &bytes_read,
				NULL, NULL);
	data += data_size;
	consumed += data_size;
	if (t == NULL)
	  {
	    fprintf (file, "ERROR converting string from UTF-8\n");
	    return consumed;
	  }
	fprintf (file, "string `%s'", t);
	g_free (t);
	if (bytes_read < data_size)
	  {
	    fprintf (file, "ERROR: %" G_GSIZE_FORMAT "bytes unconverted\n",
		     data_size - bytes_read);
	    return consumed;
	  }
	putc ('\n', file);
	break;
      }

    case KMIP_ITEM_BYTES:
      {
	fputs ("binary 0x", file);
	while (data_size != 0)
	  {
	    guint8 v;

	    COPY (v);
	    fprintf (file, "%02X", (unsigned)v);
	    data_size--;
	  }
	putc ('\n', file);
	break;
      }

    case KMIP_ITEM_DATE_TIME:
      {
	char buf[27];
	time_t t;
	gint64 v;

	CHECK_DATA_SIZE (8);
	COPY (v);
	v = GINT64_FROM_BE (v);
	t = v;
	if (t != v)
	  {
	    fprintf (file, "ERROR: time_t overflow\n");
	    return consumed;
	  }
	if (ctime_r (&t, buf) == NULL)
	  {
	    fprintf (file, "ERROR: ctime_r failed\n");
	    return consumed;
	  }
	fprintf (file, "date/time %s\n", buf);
	break;
      }

    case KMIP_ITEM_INTERVAL:
      {
	guint32 v;

	CHECK_DATA_SIZE (4);
	COPY (v);
	fprintf (file, "interval %" G_GUINT32_FORMAT "\n", GUINT32_FROM_BE (v));
	break;
      }

    case KMIP_ITEM_STRUCTURE:
      if (size - consumed < data_size)
	{
	  fprintf (file, "ERROR: Only %zu bytes left\n", size - consumed);
	  return size;
	}
      fprintf (file, "struct:\n");
      while (data_size > 0)
	{
	  size_t item_size;

	  item_size = kmip_dump_sub (file, data, data_size, level + 1);
	  g_return_val_if_fail (item_size <= data_size, consumed + item_size);
	  data += item_size;
	  consumed += item_size;
	  data_size -= item_size;
	}
      break;
    default:
      fprintf (file, "ERROR: unknown data type 0x%02X\n", (unsigned)data_type);
      return consumed + data_size;
#undef CHECK_DATA_SIZE
    }
  return consumed;
#undef COPY
}

/* Dump KMIP DATA of SIZE to FILE */
void
kmip_dump (FILE *file, const void *data, size_t size)
{
  kmip_dump_sub (file, data, size, 0);
}
