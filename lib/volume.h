/* Internal volume interface.

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

#ifndef LIBVK_VOLUME_H__
#define LIBVK_VOLUME_H__

#include <config.h>

#include <glib.h>

#include "libvolume_key.h"

struct kmip_key_value;

enum volume_source
  {
    VOLUME_SOURCE_LOCAL,
    VOLUME_SOURCE_PACKET,
  };

/* Volume information, mostly independent of its content. */
struct libvk_volume
{
  enum volume_source source;
  char *hostname;
  char *uuid;			/* Volume UUID in ASCII, or NULL */
  char *label;			/* Volume label, or NULL */
  char *path;			/* Block device path for the volume */
  char *format;			/* See LIBVK_VOLUME_FORMAT_* */
  union
  {
    struct luks_volume *luks;	/* LIBVK_VOLUME_FORMAT_LUKS */
  } v;
};

 /* Utilities */

/* Add NAME (constant) and VALUE (for g_free ()) to start of LIST, return
   new list. */
G_GNUC_INTERNAL
extern GSList *add_vp (GSList *list, const char *label, const char *name,
		       enum libvk_vp_type type, char *value);

/* Add a "strings" attribute using ATTR_NAME, NAME and VALUE to KEY_VALUE */
G_GNUC_INTERNAL
extern void add_attribute_strings (struct kmip_key_value *key_value,
				   const char *attr_name, const char *name,
				   const char *value);

/* Find an KMIP_TAG_APP_SPECIFIC attribute with ATTR_NAME and NAME.
   Return attribute value if found, NULL otherwise (reporting it in ERROR). */
G_GNUC_INTERNAL
extern const char *get_attribute_strings
	(const struct kmip_key_value *key_value, const char *attr_name,
	 const char *name, GError **error);

/* Find an attribute with TAG and NAME.
   Return attribute if found, NULL otherwise (reporting it in ERROR). */
G_GNUC_INTERNAL
extern const struct kmip_attribute *get_attribute
	(const struct kmip_key_value *key_value, guint32 tag, const char *name,
	 GError **error);

/* Create a KMIP packet structure for VOL that contains a data encryption KEY
   of KEY_BYTES.
   On success return the KMIP data, store the kmip_key_value component to KV.
   Return NULL on error. */
G_GNUC_INTERNAL
extern struct kmip_libvk_packet *volume_create_data_encryption_key_packet
	(struct kmip_key_value **kv, const struct libvk_volume *vol,
	 const void *key, size_t key_bytes, GError **error);

/* Create a KMIP packet structure for VOL that contains PASSPHRASE of SIZE.
   On success return the KMIP data, store the kmip_key_value component to KV.
   Return NULL on error. */
G_GNUC_INTERNAL
extern struct kmip_libvk_packet *volume_create_passphrase_packet
	(struct kmip_key_value **kv, const struct libvk_volume *vol,
	 const void *passphrase, size_t size);

 /* Internal operations */

/* Create a key escrow packet for SECRET_TYPE in VOL.
   Return KMIP packet structure (for kmip_libvk_packet_free ()) if OK, NULL on
   error. */
G_GNUC_INTERNAL
extern struct kmip_libvk_packet *volume_create_escrow_packet
	(const struct libvk_volume *vol, enum libvk_secret secret_type,
	 GError **error);

/* Load volume information from PACKET of SIZE.
   Return volume information if OK, NULL on error.
   Note that the data in the packet might be obsolete! */
G_GNUC_INTERNAL
extern struct libvk_volume *volume_load_escrow_packet
	(struct kmip_libvk_packet *packet, GError **error);

#endif
