/* Internal LUKS volume interface.

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

#ifndef LIBVK_VOLUME_LUKS_H__
#define LIBVK_VOLUME_LUKS_H__

#include <config.h>

#include <glib.h>

#include "kmip.h"
#include "libvolume_key.h"

/* LUKS volume information */
struct luks_volume
{
  /* From LUKS header, may be NULL in packets */
  char *cipher_name, *cipher_mode;
  size_t key_bytes;		   /* From LUKS header, may be 0 in packets */
  void *key;			   /* If known, or NULL */
  char *passphrase;		   /* If known, or NULL */
  int passphrase_slot;		   /* If relevant and known, or -1 */
};

/* g_free() LUKS and everything it points to. */
G_GNUC_INTERNAL
extern void luks_volume_free (struct luks_volume *luks);

/* Open a LUKS VOL at PATH.
   Return LUKS volume information, or NULL on error. */
G_GNUC_INTERNAL
extern struct luks_volume *luks_volume_open (struct libvk_volume *vol,
					     const char *path, GError **error);

/* Add properties of LUKS, including "secrets" if WITH_SECRETS != 0, to LIST.
   Return an updated list. */
G_GNUC_INTERNAL
extern GSList *luks_volume_dump_properties (GSList *res,
					    const struct luks_volume *luks,
					    int with_secrets);

/* Get a "secret" of SECRET_TYPE for LUKS VOL, interacting with the user using
   the provided UI.
   Return 0 if OK, -1 on error. */
G_GNUC_INTERNAL
extern int luks_get_secret (struct libvk_volume *vol,
			    enum libvk_secret secret_type,
			    const struct libvk_ui *ui, GError **error);

/* Check if PACKET matches VOL, modifying previous comparison result RES.
   Return the comparison result:
   On LIBVK_PACKET_MATCH_MISMATCH set an error message.
   On LIBVK_PACKET_MATCH_UNSURE, if WARNINGS is not NULL, add warning messages
   (char *, for g_free ()) to it. */
G_GNUC_INTERNAL
extern enum libvk_packet_match_result luks_packet_match_volume
	(const struct libvk_volume *packet, const struct libvk_volume *vol,
	 enum libvk_packet_match_result res, GPtrArray *warnings,
	 GError **error);

/* Load "secrets" from PACKET, verify them if possible and store them with VOL.
   Return 0 if OK, -1 on error. */
G_GNUC_INTERNAL
extern int luks_load_packet (struct libvk_volume *vol,
			     const struct libvk_volume *packet, GError **error);

/* Apply the "secret" of SECRET_TYPE in PACKET to restore conventional access
   to VOL, using UI to gather more information.
   Return 0 if OK, -1 on error.
   "Restore conventional access" usually means "prompt for a new passphrase". */
G_GNUC_INTERNAL
extern int luks_apply_secret (struct libvk_volume *vol,
			      const struct libvk_volume *packet,
			      enum libvk_secret secret_type,
			      const struct libvk_ui *ui, GError **error);

/* Add SECRET with SIZE and SECRET_TYPE to LUKS VOLUME.
   Return 0 if OK, -1 on error. */
G_GNUC_INTERNAL
extern int luks_add_secret (struct libvk_volume *vol,
			    enum libvk_secret secret_type, const void *secret,
			    size_t size, GError **error);

/* Create a KMIP packet structure for SECRET in VOL.
   Return the KMIP data on success, NULL no error. */
G_GNUC_INTERNAL
extern struct kmip_libvk_packet *luks_create_escrow_packet
	(const struct libvk_volume *vol, enum libvk_secret secret_type,
	 GError **error);

/* Load volume information from PACK its component KEY_VALUE.
   Return 0 if OK, -1 on error. */
G_GNUC_INTERNAL
extern int luks_parse_escrow_packet (struct libvk_volume *vol,
				     const struct kmip_libvk_packet *pack,
				     const struct kmip_key_value *key_value,
				     GError **error);

/* Open VOL using volume format-specific NAME, using "secrets" from PACKET.
   Return 0 if OK, -1 on error.

   NAME is currently always a device-mapper name, please try not to rely on
   it. */
G_GNUC_INTERNAL
extern int luks_open_with_packet (struct libvk_volume *vol,
				  const struct libvk_volume *packet,
				  const char *name, GError **error);

#endif
