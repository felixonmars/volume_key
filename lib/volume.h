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

/* LUKS volume information, if available. */
struct luks_volume
{
  /* From LUKS header, may be NULL in packets */
  char *cipher_name, *cipher_mode;
  size_t key_bytes;		   /* From LUKS header, may be 0 in packets */
  void *key;			   /* If known, or NULL */
  char *passphrase;		   /* If known, or NULL */
  int passphrase_slot;		   /* If passphrase != NULL and known, or -1 */
};

/* Create a key escrow packet for SECRET in VOL, set SIZE to its size.
   Return packet data (for g_free ()) if OK, NULL on error. */
G_GNUC_INTERNAL
extern void *volume_create_escrow_packet (const struct libvk_volume *vol,
					  size_t *size,
					  enum libvk_secret secret_type,
					  GError **error);

/* Load volume information from PACKET of SIZE.
   Return volume information if OK, NULL on error.
   Note that the data in the packet might be obsolete! */
G_GNUC_INTERNAL
extern struct libvk_volume *volume_load_escrow_packet (const void *packet,
						       size_t size,
						       GError **error);

#endif
