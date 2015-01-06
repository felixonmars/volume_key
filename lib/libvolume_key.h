/* volume_key library.

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

#ifndef LIBVOLUME_KEY_H__
#define LIBVOLUME_KEY_H__

#include <cert.h>
#include <glib.h>

G_BEGIN_DECLS

/* Initialize libvolume_key. */
extern void libvk_init (void);

/* GError definitions. */
extern GQuark libvk_error_quark(void);
#define LIBVK_ERROR libvk_error_quark()

typedef enum
  {
    LIBVK_ERROR_CRYPTO,
    LIBVK_ERROR_INPUT_OVERFLOW,
    LIBVK_ERROR_KMIP_NO_DATA,
    LIBVK_ERROR_KMIP_NO_SPACE,
    LIBVK_ERROR_KMIP_UNEXPECTED_FORMAT,
    LIBVK_ERROR_KMIP_UNSUPPORTED_VALUE,
    LIBVK_ERROR_KMIP_INVALID_INPUT,
    LIBVK_ERROR_PACKET_VOLUME_MISMATCH,
    LIBVK_ERROR_UI_NO_RESPONSE,
    LIBVK_ERROR_VOLUME_UNKNOWN_FORMAT,
    LIBVK_ERROR_VOLUME_UNSUPPORTED_SECRET,
    LIBVK_ERROR_VOLUME_NEED_SECRET,
    LIBVK_ERROR_VOLUME_INVALID_SECRET,

    LIBVK_ERROR_FAILED,

    LIBVK_ERROR_KMIP_UNSUPPORTED_FORMAT,
    LIBVK_ERROR_UNSUPPORTED_WRAPPING_MECHANISM,

    LIBVK_ERROR_METADATA_ENCRYPTED,
  } LIBVKError;

enum libvk_secret
  {
    /* The default key for the specific volume format.  It is intended to be
       most suitable for restoring access to the volume. */
    LIBVK_SECRET_DEFAULT,
    /* The lowest-level key, used for encrypting data.  Note that this might be
       a result of an one-way transformation in some formats, making it
       impossible to restore access to the volume using the standard tools
       given only this secret is known. */
    LIBVK_SECRET_DATA_ENCRYPTION_KEY,
    /* User's passphrase. */
    LIBVK_SECRET_PASSPHRASE,
    /* (Add more secret types here, not below.) */
    LIBVK_SECRET_END__
  };

 /* User interaction. */

/* User interaction context. */
struct libvk_ui;

/* Create and return an empty context. */
extern struct libvk_ui *libvk_ui_new (void);

/* Free an user interaction context. */
extern void libvk_ui_free (struct libvk_ui *ui);

/* Set a generic conversation callback of UI to CB with DATA.
   This callback is used if a more specific callback is not define or not set.

   The callback is called with the supplied data, a prompt, and an indication
   whether the response should be echoed.  It returns a response (for
   g_free ()), or NULL on error.

   Upon libvk_ui_free (UI) or subsequent libvk_ui_set_generic_cb (UI, ...),
   FREE_DATA (DATA) will be called if FREE_DATA is not NULL. */
extern void libvk_ui_set_generic_cb (struct libvk_ui *ui,
				     char *(*cb) (void *data,
						  const char *prompt, int echo),
				     void *data,
				     void (*free_data) (void *data));

/* Set a simple passphrase callback of UI to CB with DATA.
   The callback is used to collect a passphrase or password (which should
   probably not be echoed), using a simple prompt.

   The callbacks is called with the supplied data, a prompt, and number of
   preceding failed attempts.  It returns a passphrase (for g_free ()), or
   NULL on error.

   Upon libvk_ui_free (UI) or subsequent libvk_ui_set_passphrase_cb (UI, ...),
   FREE_DATA (DATA) will be called if FREE_DATA is not NULL. */
extern void libvk_ui_set_passphrase_cb (struct libvk_ui *ui,
					char *(*cb) (void *data,
						     const char *prompt,
						     unsigned failed_attempts),
					void *data,
					void (*free_data) (void *data));

/* Set a NSS password callback (set by PK11_SetPasswordFunc) parameter to DATA.

   Upon libvk_ui_free (UI) or subsequent libvk_ui_set_nss_pwfn_arg (UI, ...),
   FREE_DATA (DATA) will be called if FREE_DATA is not NULL. */
extern void libvk_ui_set_nss_pwfn_arg (struct libvk_ui *ui, void *data,
				       void (*free_data) (void *data));

/* Set a NSS symmetric key callback to CB with DATA.
   The callback is used to get a symmetric key for unwrapping secrets.

   The callback is called with the supplied data, and number of preceding
   failed attempts.  It returns a symmetric key (for PK11_FreeSymKey ()), or
   NULL on error.

   Upon libvk_ui_free (UI) or subsequent libvk_ui_set_sym_key_cb (UI, ...),
   FREE_DATA (DATA) will be called if FREE_DATA is not NULL. */
extern void libvk_ui_set_sym_key_cb (struct libvk_ui *ui,
				     PK11SymKey *(*cb)
					(void *data,
					 unsigned failed_attempts),
				     void *data,
				     void (*free_data) (void *data));

 /* A volume property. */

struct libvk_volume_property;

/* Free PROP. */
extern void libvk_vp_free (struct libvk_volume_property *prop);

/* Get a label of PROP (user-readable, in current locale encoding).
   Return property label, for g_free (). */
extern char *libvk_vp_get_label (const struct libvk_volume_property *prop);

/* Get an invariant name of PROP (useful for programs).
   Return property name, for g_free (). */
extern char *libvk_vp_get_name (const struct libvk_volume_property *prop);

enum libvk_vp_type
  {
    LIBVK_VP_IDENTIFICATION,	/* Which volume is this? */
    LIBVK_VP_CONFIGURATION,	/* Information about the volume */
    LIBVK_VP_SECRET,		/* A "secret" managed by libvolume_key */
  };

/* Return type of PROP.
   Make sure the caller can handle unknown values! */
extern enum libvk_vp_type libvk_vp_get_type
	(const struct libvk_volume_property *prop);

/* Get the value of PROP.
   Return property value, for g_free ().
   The caller might want to zero the memory of LIBVK_VP_SECRET values before
   freeing them. */
extern char *libvk_vp_get_value (const struct libvk_volume_property *prop);

 /* Volume operations. */

/* Volume information.
   This can come either from examining a volume, or from an escrow packet. */
struct libvk_volume;

/* Free VOL and everything it points to. */
extern void libvk_volume_free (struct libvk_volume *vol);

/* Open PATH and gather general information (format, attributes) about it.
   Return volume information if OK, NULL on error.
   This does not usually get encryption keys nor passphrases.  No user
   interaction is necessary. */
extern struct libvk_volume *libvk_volume_open (const char *path,
					       GError **error);

/* Get host name associated with VOL.
   Return host name, for g_free (). */
extern char *libvk_volume_get_hostname (const struct libvk_volume *vol);

/* Get UUID associated with VOL.
   Return UUID in ASCII, for g_free (), if available, NULL otherwise. */
extern char *libvk_volume_get_uuid (const struct libvk_volume *vol);

/* Get a label associated with VOL.
   Return volume label, for g_free (), if available, NULL otherwise. */
extern char *libvk_volume_get_label (const struct libvk_volume *vol);

/* Get a path associated with VOL.
   Return path, for g_free ().
   Note that the path need not be canonical, there may be more than one path
   pointing to the same volume. */
extern char *libvk_volume_get_path (const struct libvk_volume *vol);

/* Get format of VOL.
   Return the format, for g_free ().
   See LIBVK_VOLUME_FORMAT_* below.
   A volume format will always be returned, even if it is not supported by
   libvolume_key. */
extern char *libvk_volume_get_format (const struct libvk_volume *vol);

#define LIBVK_VOLUME_FORMAT_LUKS "crypt_LUKS"

/* Return a list of all properties of VOL, including "secrets" if WITH_SECRETS
   != 0.
   Each element of the list is struct libvk_volume_property.  The caller should
   call libvk_vp_free () on each element, and free each GSList element.
   Be careful with the secrets! */
extern GSList *libvk_volume_dump_properties (const struct libvk_volume *vol,
					     int with_secrets);

/* Get a "secret" of SECRET_TYPE for VOL, interacting with the user using the
   provided UI.
   Return 0 if OK, -1 on error.
   This can be used only on volumes returned by libvk_volume_open (), not
   by volumes created from escrow packets. */
extern int libvk_volume_get_secret (struct libvk_volume *vol,
				    enum libvk_secret secret_type,
				    const struct libvk_ui *ui, GError **error);

/* Add SECRET with SIZE and SECRET_TYPE to VOLUME.
   Return 0 if OK, -1 on error.
   This operation should not be destructive.  Details are format-specific;
   for example, this may allow adding a LIBVK_SECRET_PASSPHRASE, assuming
   LIBVK_SECRET_DEFAULT was obtained before.
   If SECRET is a string, SIZE does not include the terminating NUL.
   This can be used only on volumes returned by libvk_volume_open (), not
   by volumes created from escrow packets. */
extern int libvk_volume_add_secret (struct libvk_volume *vol,
				    enum libvk_secret secret_type,
				    const void *secret, size_t size,
				    GError **error);

/* Load "secrets" from PACKET, verify them if possible and store them with VOL.
   Return 0 if OK, -1 on error.
   This can be used only on volumes returned by libvk_volume_open (), not
   by volumes created from escrow packets. */
extern int libvk_volume_load_packet (struct libvk_volume *vol,
				     const struct libvk_volume *packet,
				     GError **error);

/* Apply the "secret" of SECRET_TYPE in PACKET to restore conventional access
   to VOL, using UI to gather more information.
   Return 0 if OK, -1 on error.
   "Restore conventional access" means something like "prompt for a new
   passphrase".
   This can be used only on volumes returned by libvk_volume_open (), not
   by volumes created from escrow packets. */
extern int libvk_volume_apply_packet (struct libvk_volume *vol,
				      const struct libvk_volume *packet,
				      enum libvk_secret secret_type,
				      const struct libvk_ui *ui,
				      GError **error);

/* Open VOL using volume format-specific NAME, using "secrets" from PACKET.
   Return 0 if OK, -1 on error.

   NAME is currently always a device-mapper name, please try not to rely on
   it.
   This can be used only on volumes returned by libvk_volume_open (), not
   by volumes created from escrow packets. */
extern int libvk_volume_open_with_packet (struct libvk_volume *vol,
					  const struct libvk_volume *packet,
					  const char *name, GError **error);

 /* Escrow packet handling */

enum libvk_packet_format
  {
    LIBVK_PACKET_FORMAT_UNKNOWN = -1,
    LIBVK_PACKET_FORMAT_CLEARTEXT = 0,
    LIBVK_PACKET_FORMAT_ASYMMETRIC = 1, /* Whole packet encrypted */
    /* For compatibility */
    LIBVK_PACKET_FORMAT_ASSYMETRIC = LIBVK_PACKET_FORMAT_ASYMMETRIC,
    LIBVK_PACKET_FORMAT_PASSPHRASE = 2,
    /* Metadata unencrypted */
    LIBVK_PACKET_FORMAT_ASYMMETRIC_WRAP_SECRET_ONLY = 3,
    /* Metadata unencrypted */
    LIBVK_PACKET_FORMAT_SYMMETRIC_WRAP_SECRET_ONLY = 4,
    /* (Add more packet types here, not below.) */
    LIBVK_PACKET_FORMAT_END__
  };

/* Create a clear-text escrow packet with secret of SECRET_TYPE from VOL, store
   its size into SIZE.
   Return the packet (for g_free ()) if OK, NULL on error.
   VOL must contain at least one "secret".
   Be extremely careful with the results! */
extern void *libvk_volume_create_packet_cleartext
	(const struct libvk_volume *vol, size_t *size,
	 enum libvk_secret secret_type, GError **error);

/* Create an escrow packet encrypted for CERT with secret of SECRET_TYPE from
   VOL, store its size into SIZE.
   Return the packet (for g_free ()) if OK, NULL on error.
   VOL must contain at least one "secret".
   May use UI. */
extern void *libvk_volume_create_packet_asymmetric
	(const struct libvk_volume *vol, size_t *size,
	 enum libvk_secret secret_type, CERTCertificate *cert,
	 const struct libvk_ui *ui, GError **error);

/* For compatibility */
extern void *libvk_volume_create_packet_assymetric
	(const struct libvk_volume *vol, size_t *size,
	 enum libvk_secret secret_type, CERTCertificate *cert,
	 const struct libvk_ui *ui, GError **error);

/* Create an escrow packet encrypted for CERT with secret of SECRET_TYPE from
   VOL using FORMAT, store its size into SIZE.
   Return the packet (for g_free ()) if OK, NULL on error.
   VOL must contain at least one "secret".
   May use UI. */
extern void *libvk_volume_create_packet_asymmetric_with_format
	(const struct libvk_volume *vol, size_t *size,
	 enum libvk_secret secret_type, CERTCertificate *cert,
	 const struct libvk_ui *ui, enum libvk_packet_format format,
	 GError **error);

/* Create an escrow packet encrypted using PASSPHRASE with secret of SECRET_TYPE
   from VOL, store its size into SIZE.
   Return the packet (for g_free ()) if OK, NULL on error.
   VOL must contain at least one "secret". */
extern void *libvk_volume_create_packet_with_passphrase
	(const struct libvk_volume *vol, size_t *size,
	 enum libvk_secret secret_type, const char *passphrase, GError **error);

/* Create an escrow packet with the secrets wrapped using KEY from VOL, store
   its size into SIZE.
   Return the packet (for g_free ()) if OK, NULL on error.
   VOL must contain at least one "secret".
   May use UI. */
extern void *libvk_volume_create_packet_wrap_secret_symmetric
	(const struct libvk_volume *vol, size_t *size,
	 enum libvk_secret secret_type, PK11SymKey *key,
	 const struct libvk_ui *ui, GError **error);

/* Return a format of PACKET of SIZE, or LIBVK_PACKET_FORMAT_UNKNOWN.
   Make sure the caller can handle unknown values! */
extern enum libvk_packet_format libvk_packet_get_format (const void *packet,
							 size_t size,
							 GError **error);

/* Open PACKET of SIZE, using UI.
   Return the volume information it contains, or NULL on error. */
extern struct libvk_volume *libvk_packet_open (const void *packet, size_t size,
					       const struct libvk_ui *ui,
					       GError **error);

/* Open PACKET of SIZE, without decrypting it or asking for any decryption keys.
   Return the volume information it contains, or NULL on error.
   On success, at least some of the metadata must be available. */
extern struct libvk_volume *libvk_packet_open_unencrypted (const void *packet,
							   size_t size,
							   GError **error);

enum libvk_packet_match_result
  {
    LIBVK_PACKET_MATCH_OK,
    LIBVK_PACKET_MATCH_ERROR,
    LIBVK_PACKET_MATCH_UNSURE
  };

/* Check if PACKET matches VOL.
   Return the comparison result:
   On LIBVK_PACKET_MATCH_ERROR set an error message.
   On LIBVK_PACKET_MATCH_UNSURE, if WARNINGS is not NULL, add warning messages
   (char *, for g_free ()) to it. */
extern enum libvk_packet_match_result libvk_packet_match_volume
	(const struct libvk_volume *packet, const struct libvk_volume *vol,
	 GPtrArray *warnings, GError **error);


G_END_DECLS

#endif
