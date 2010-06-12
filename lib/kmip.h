/* Internal KMIP interface.

Copyright (C) 2009, 2010 Red Hat, Inc. All rights reserved.
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

#ifndef LIBVK_KMIP_H__
#define LIBVK_KMIP_H__

#include <config.h>

#include <stdio.h>

#include <cert.h>
#include <glib.h>

#include "libvolume_key.h"

/* This is not a generic KMIP reader/writer.  It only supports the specific
   packet formats used by libvolume_key, and rejects packets that contain
   anything else. */

/* KMIP encoding state.
   Encoding is two-stage: first encode without writing data to determine the
   total size, then allocate memory and encode again.  This is done to avoid
   realloc() and the unmanageable memory copies it may cause. */
struct kmip_encoding_state
{
  unsigned char *data; 		/* NULL to only compute data size during
				   encoding. */
  size_t offset;		/* Current pointer */
  size_t size;
};

/* KMIP decoding state */
struct kmip_decoding_state
{
  const unsigned char *data;
  size_t left;
};

enum
  {
    KMIP_ITEM_INT32 = 0x01,    /* 4 bytes, signed, big-endian */
    KMIP_ITEM_INT64 = 0x02,    /* 8 bytes, signed, big-endian */
    KMIP_ITEM_BIGNUM = 0x03,   /* N bytes, signed, big-endian */
    KMIP_ITEM_ENUM = 0x04,     /* 4 bytes, unsigned, big-endian */
    KMIP_ITEM_BOOLEAN = 0x05,  /* 1 byte, 0 = false, other = true (prefer 1) */
    KMIP_ITEM_STRING = 0x06,   /* UTF-8, no NUL termination */
    KMIP_ITEM_BYTES = 0x07,    /* N bytes, binary data */
    KMIP_ITEM_DATE_TIME = 0x08,	/* 8 bytes, signed, big-endian POSIX time */
    /* 4 bytes, unsigned, big-endian number of seconds */
    KMIP_ITEM_INTERVAL = 0x09,
    KMIP_ITEM_STRUCTURE = 0x80	/* N bytes, elements in specified order */
  };

#define KMIP_LIBVK_ENUM_NONE ((guint32)-1)

#define KMIP_TAG_APP_ID 0x42000002
#define KMIP_TAG_APP_NAME_SPACE 0x42000003
#define KMIP_TAG_APP_SPECIFIC 0x42000004
#define KMIP_TAG_ATTRIBUTE 0x42000008
#define KMIP_TAG_ATTRIBUTE_NAME 0x4200000A
#define KMIP_TAG_ATTRIBUTE_VALUE 0x4200000B
#define KMIP_TAG_BLOCK_CIPHER_MODE 0x42000011
#define KMIP_TAG_CRYPTO_ALGORITHM 0x42000025
#define KMIP_TAG_CRYPTO_LENGTH 0x42000026
#define KMIP_TAG_CRYPTO_PARAMS 0x42000027
#define KMIP_TAG_ENCRYPTION_KEY_INFO 0x42000032
#define KMIP_TAG_HASH_ALGORITHM 0x42000034
#define KMIP_TAG_IV_COUNTER_NONCE 0x42000039
#define KMIP_TAG_KEY 0x4200003B
#define KMIP_TAG_KEY_BLOCK 0x4200003C
#define KMIP_TAG_KEY_MATERIAL 0x4200003D
#define KMIP_TAG_KEY_VALUE 0x4200003F
#define KMIP_TAG_KEY_VALUE_TYPE 0x42000040
#define KMIP_TAG_KEY_WRAPPING_DATA 0x42000041
#define KMIP_TAG_OBJECT_TYPE 0x42000052
#define KMIP_TAG_PADDING_METHOD 0x4200005A
#define KMIP_TAG_PROTOCOL_VERSION 0x42000065
#define KMIP_TAG_PROTOCOL_VERSION_MAJOR 0x42000066
#define KMIP_TAG_PROTOCOL_VERSION_MINOR 0x42000067
#define KMIP_TAG_SECRET_DATA 0x42000080
#define KMIP_TAG_SECRET_DATA_TYPE 0x42000081
/* Note that this means either struct kmip_symmetric_key or
   struct kmip_object_symmetric_key! */
#define KMIP_TAG_SYMMETRIC_KEY 0x4200008A
#define KMIP_TAG_UNIQUE_IDENTIFIER 0x4200008F
#define KMIP_TAG_WRAPPING_METHOD 0x4200009A

/* Check if KMIP, positioned at the start of an item, starts with TAG */
G_GNUC_INTERNAL
extern gboolean kmip_next_tag_is (const struct kmip_decoding_state *kmip,
				  guint32 tag);

/* The value is from $RANDOM */
#define KMIP_TAG_LIBVK_PACKET 0x420135F4

struct kmip_crypto_params
{
  guint32 cipher_mode; /* See KMIP_ALGORITHM_* below, or KMIP_LIBVK_ENUM_NONE */
  /* See KMIP_PADDING_* below, or KMIP_LIBVK_ENUM_NONE */
  guint32 padding_method;
  guint32 hash_algorithm; /* See KMIP_HASH_* below, or KMIP_LIBVK_ENUM_NONE */
};

enum
  {
    KMIP_MODE_CBC = 0x01,
    KMIP_MODE_ECB = 0x02,
    KMIP_MODE_PCBC = 0x03,
    KMIP_MODE_CFB = 0x04,
    KMIP_MODE_OFB = 0x05,
    KMIP_MODE_CTR = 0x06,
    KMIP_MODE_CMAC = 0x07,
    KMIP_MODE_CCM = 0x08,
    KMIP_MODE_GCM = 0x09,
    KMIP_MODE_CBC_MAC = 0x0A,
    KMIP_MODE_AESKEYWRAP = 0x0B,
    KMIP_END_MODES
  };

enum
  {
    KMIP_PADDING_NONE = 0x01,
    KMIP_PADDING_OAEP = 0x02,
    KMIP_PADDING_PKCS5 = 0x03,
    KMIP_PADDING_SSL3 = 0x04,
    KMIP_PADDING_ZEROS = 0x05,
    KMIP_PADDING_X9_23 = 0x06,
    KMIP_PADDING_ISO_10126 = 0x07,
    KMIP_PADDING_PKCS1_v1_5 = 0x08,
    KMIP_END_PADDINGS
  };

enum
  {
    KMIP_HASH_MD2 = 0x01,
    KMIP_HASH_MD4 = 0x02,
    KMIP_HASH_MD5 = 0x03,
    KMIP_HASH_SHA_1 = 0x04,
    KMIP_HASH_SHA_256 = 0x05,
    KMIP_HASH_SHA_384 = 0x06,
    KMIP_HASH_SHA_512 = 0x07,
    KMIP_HASH_SHA_224 = 0x08,
    KMIP_END_HASHES
  };

/* g_free() PARAMS and all data it points to. */
G_GNUC_INTERNAL
extern void kmip_crypto_params_free (struct kmip_crypto_params *params);

struct kmip_attribute
{
  char *name;			/* We recognize KMIP_ATTR_* */
  /* Value tag; note that the encoding always uses KMIP_TAG_ATTRIBUTE_VALUE,
     this tag would be used if the value stood alone. */
  guint32 tag;
  union
  {
    guint32 enum_value;		/* KMIP_TAG_CRYPTO_ALGORITHM */
    gint32 int32_value;		/* KMIP_TAG_CRYPTO_LENGTH */
    struct kmip_crypto_params *crypto_params;
    struct
    {
      char *name, *value;
    } strings;			/* KMIP_TAG_APP_SPECIFIC */
  } v;
};

#define KMIP_ATTR_APP_SPECIFIC "Application Specific Identification"
#define KMIP_ATTR_CRYPTO_ALGORITHM "Cryptographic Algorithm"
#define KMIP_ATTR_CRYPTO_LENGTH "Cryptographic Length"
#define KMIP_ATTR_CRYPTO_PARAMS "Cryptographic Parameters"

/* KMIP_ATTR_APP_SPECIFIC names */
#define KMIP_AS_LIBVK_HOST_NAME "Host Name"
#define KMIP_AS_LIBVK_VOLUME_UUID "Volume UUID"
#define KMIP_AS_LIBVK_VOLUME_LABEL "Volume Label"
#define KMIP_AS_LIBVK_VOLUME_FILE "Volume File"
#define KMIP_AS_LIBVK_VOLUME_FORMAT "Volume Format"
#define KMIP_AS_LIBVK_PASSPHRASE_SLOT "Passphrase Slot"

/* These custom attribute types use KMIP_TAG_APP_SPECIFIC */
#define KMIP_ATTR_LIBVK_LUKS_CIPHER "x-redhat.com:volume_key LUKS Cipher Name"
#define KMIP_ATTR_LIBVK_LUKS_CIPHER_NAME "LUKS Cipher Name"
#define KMIP_ATTR_LIBVK_LUKS_MODE "x-redhat.com:volume_key LUKS Cipher Mode"
#define KMIP_ATTR_LIBVK_LUKS_MODE_NAME "LUKS Cipher Mode"

enum
  {
    KMIP_ALGORITHM_DES = 0x01,
    KMIP_ALGORITHM_3DES = 0x02,
    KMIP_ALGORITHM_AES = 0x03,
    KMIP_ALGORITHM_RSA = 0x04,
    KMIP_ALGORITHM_DSA = 0x05,
    KMIP_ALGORITHM_ECDSA = 0x06,
    KMIP_ALGORITHM_HMAC_SHA1 = 0x07,
    KMIP_ALGORITHM_HMAC_SHA256 = 0x08,
    KMIP_ALGORITHM_HMAC_SHA512 = 0x09,
    KMIP_ALGORITHM_HMAC_MD5 = 0x0A,
    KMIP_ALGORITHM_DH = 0x0B,
    KMIP_ALGORITHM_ECDH = 0x0C,
    KMIP_END_ALGORITHMS
  };

/* g_free() ATTR and all data it points to. */
G_GNUC_INTERNAL
extern void kmip_attribute_free (struct kmip_attribute *attr);

struct kmip_symmetric_key
{
  void *data;
  size_t len;
};

/* g_free() KEY and all data it points to. */
G_GNUC_INTERNAL
extern void kmip_symmetric_key_free (struct kmip_symmetric_key *key);

enum kmip_key_value_type
  {
    KMIP_KEY_VALUE_BYTES,
    KMIP_KEY_VALUE_SYMMETRIC_KEY,
  };

struct kmip_key_value
{
  enum kmip_key_value_type type;
  union
  {
    struct
    {
      void *data;
      size_t len;
    } bytes;
    struct kmip_symmetric_key *key;
  } v;
  GPtrArray *attributes;
};

/* g_free() VALUE and all data it points to. */
G_GNUC_INTERNAL
extern void kmip_key_value_free (struct kmip_key_value *value);

struct kmip_encryption_key_info
{
  char *identifier;	  /* See KMIP_LIBVK_IDENTIFIER_CERT_ISN_PREFIX below */
  struct kmip_crypto_params *params;
};

/* "Unique Identifier" usually refers to a KMIP-managed key.  Use certificate
   issuer/SN for externally managed certificates; both issuer and SN are base64
   encoded and space-separated */
#define KMIP_LIBVK_IDENTIFIER_CERT_ISN_PREFIX \
  "x-redhat.com:volume_key issuer/SN:"

#define KMIP_LIBVK_IDENTIFIER_SECRET_KEY "x-redhat.com:volume_key secret key"

/* g_free() INFO and all data it points to. */
G_GNUC_INTERNAL
extern void kmip_encryption_key_info_free (struct kmip_encryption_key_info
					   *info);

struct kmip_key_wrapping_data
{
  guint32 method; 		/* See KMIP_WRAPPING_* below */
  struct kmip_encryption_key_info *encryption_key;
  void *iv;
  size_t iv_len;		/* If iv != NULL */
};

enum
  {
    /* The value is from $RANDOM */
    KMIP_WRAPPING_LIBVK_ENCRYPT_KEY_ONLY = 0x81E64B1B
  };

/* g_free() WRAPPING and all data it points to. */
G_GNUC_INTERNAL
extern void kmip_key_wrapping_data_free (struct kmip_key_wrapping_data
					 *wrapping);

struct kmip_key_block
{
  guint32 type;			/* See KMIP_KEY_* below */
  struct kmip_key_value *value;
  guint32 crypto_algorithm;	/* KMIP_LIBVK_ENUM_NONE if unknown */
  gint32 crypto_length;		/* < 0 if unknown */
  struct kmip_key_wrapping_data *wrapping;
};

enum
  {
    KMIP_KEY_RAW = 0x01,
    KMIP_KEY_OPAQUE = 0x02,
    KMIP_KEY_PKCS1 = 0x03,
    KMIP_KEY_PKCS8 = 0x04,
    KMIP_KEY_TRANSPARENT_SYMMETRIC = 0x05,
    KMIP_KEY_TRANSPARENT_DSA_PRIVATE = 0x06,
    KMIP_KEY_TRANSPARENT_DSA_PUBLIC = 0x07,
    KMIP_KEY_TRANSPARENT_RSA_PRIVATE = 0x08,
    KMIP_KEY_TRANSPARENT_RSA_PUBLIC = 0x09,
    KMIP_KEY_TRANSPARENT_DH_PRIVATE = 0x0A,
    KMIP_KEY_TRANSPARENT_DH_PUBLIC = 0x0B,
    KMIP_KEY_TRANSPARENT_ECDSA_PRIVATE = 0x0C,
    KMIP_KEY_TRANSPARENT_ECDSA_PUBLIC = 0x0D,
    KMIP_KEY_TRANSPARENT_ECDH_PRIVATE = 0x0E,
    KMIP_KEY_TRANSPARENT_ECDH_PUBLIC = 0x0F,
    KMIP_END_KEYS
  };

/* g_free() BLOCK and all data it points to. */
G_GNUC_INTERNAL
extern void kmip_key_block_free (struct kmip_key_block *block);

struct kmip_object_symmetric_key
{
  struct kmip_key_block *block;
};

/* g_free() OBJ and all data it points to. */
G_GNUC_INTERNAL
extern void kmip_object_symmetric_key_free
	(struct kmip_object_symmetric_key *obj);

struct kmip_object_secret_data
{
  guint32 type;			/* See KMIP_SECRET_* below */
  struct kmip_key_block *block;
};

enum
  {
    KMIP_SECRET_DATA_PASSWORD = 0x01,
    KMIP_SECRET_DATA_SEED = 0x02,
  };

/* g_free() OBJ and all data it points to. */
G_GNUC_INTERNAL
extern void kmip_object_secret_data_free (struct kmip_object_secret_data *obj);

struct kmip_protocol_version
{
  gint32 major, minor;
};

enum
  {
    KMIP_VERSION_MAJOR = 0,
    KMIP_VERSION_MINOR = 98
  };

/* Free VERSION and all data it points to. */
G_GNUC_INTERNAL
extern void kmip_protocol_version_free (struct kmip_protocol_version *version);

struct kmip_libvk_packet
{
  struct kmip_protocol_version *version;
  guint32 type; 		/* See KMIP_OBJECT_* below. */
  union
  {
    struct kmip_object_symmetric_key *symmetric;
    struct kmip_object_secret_data *secret_data;
  } v;
};

enum
  {
    KMIP_OBJECT_CERTIFICATE = 0x01,
    KMIP_OBJECT_SYMMETRIC_KEY = 0x02,
    KMIP_OBJECT_PUBLIC_KEY = 0x03,
    KMIP_OBJECT_PRIVATE_KEY = 0x04,
    KMIP_OBJECT_SPLIT_KEY = 0x05,
    KMIP_OBJECT_TEMPLATE = 0x06,
    KMIP_OBJECT_POLICY_TEMPLATE = 0x07,
    KMIP_OBJECT_SECRET_DATA = 0x08,
    KMIP_OBJECT_OPAQUE_OBJECT = 0x09,
    KMIP_END_OBJECTS
  };

/* Free PACKET and all data it points to. */
G_GNUC_INTERNAL
extern void kmip_libvk_packet_free (struct kmip_libvk_packet *packet);

/* Decode PACKET of SIZE.
   Return KMIP packet (for kmip_libvk_packet_free ()) if OK, NULL on error. */
G_GNUC_INTERNAL
extern struct kmip_libvk_packet *kmip_libvk_packet_decode (const void *packet,
							   size_t size,
							   GError **error);

/* Drop secrets in PACKET. */
G_GNUC_INTERNAL
extern void kmip_libvk_packet_drop_secret (struct kmip_libvk_packet *packet);

/* Encode PACKET, set SIZE to its size.
   Return packet data (for g_free ()) if OK, NULL on error. */
G_GNUC_INTERNAL
extern void *kmip_libvk_packet_encode (struct kmip_libvk_packet *packet,
				       size_t *size, GError **error);

/* Modify PACKET to wrap its secret using CERT.
   Return 0 if OK, -1 on error.
   May use UI. */
G_GNUC_INTERNAL
extern int kmip_libvk_packet_wrap_secret_asymmetric
	(struct kmip_libvk_packet *packet, CERTCertificate *cert,
	 const struct libvk_ui *ui, GError **error);

/* Modify PACKET to unwrap its secret.
   Return 0 if OK, -1 on error.
   May use UI. */
G_GNUC_INTERNAL
extern int kmip_libvk_packet_unwrap_secret_asymmetric
	(struct kmip_libvk_packet *packet, const struct libvk_ui *ui,
	 GError **error);

/* Modify PACKET to wrap its secret using KEY.
   Return 0 if OK, -1 on error.
   May use UI. */
G_GNUC_INTERNAL
extern int kmip_libvk_packet_wrap_secret_symmetric
	(struct kmip_libvk_packet *packet, PK11SymKey *key,
	 const struct libvk_ui *ui, GError **error);

/* Modify PACKET to unwrap its secret using KEY.
   Return 0 if OK, -1 on error. */
G_GNUC_INTERNAL
extern int kmip_libvk_packet_unwrap_secret_symmetric
	(struct kmip_libvk_packet *packet, PK11SymKey *key, GError **error);

/* Dump KMIP DATA of SIZE to FILE */
G_GNUC_INTERNAL
extern void kmip_dump (FILE *file, const void *data, size_t size);

#endif
