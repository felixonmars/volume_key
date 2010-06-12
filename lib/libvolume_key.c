/* Generic infrastructure for the volume_key library.

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
#include <config.h>

#include <glib.h>
#include <glib/gi18n-lib.h>

#include "crypto.h"
#include "kmip.h"
#include "libvolume_key.h"
#include "ui.h"
#include "volume.h"

/* Initialize libvolume_key. */
void
libvk_init (void)
{
  bindtextdomain (PACKAGE_NAME, LOCALEDIR);
}

GQuark
libvk_error_quark(void)
{
  return g_quark_from_static_string("libvolume_key-error-quark");
}

 /* Top-level packet format */

struct packet_header
{
  unsigned char magic[11]; 	/* packet_magic */
  unsigned char format;		/* PACKET_FORMAT_* */
};

static const unsigned char packet_magic[11] = "\0volume_key";

/* Prepend packet header with FORMAT to KMIP with KMIP_SIZE.
   Return new packet, set its PACKET_SIZE to its size. */
static void *
packet_prepend_header (size_t *packet_size, const void *kmip, size_t kmip_size,
		       enum libvk_packet_format format)
{
  struct packet_header hdr;
  void *res;
  G_STATIC_ASSERT (sizeof (hdr.magic) == sizeof (packet_magic));

  memcpy (hdr.magic, packet_magic, sizeof (hdr.magic));
  hdr.format = format;

  *packet_size = sizeof (hdr) + kmip_size;
  res = g_malloc (*packet_size);
  memcpy (res, &hdr, sizeof (hdr));
  memcpy ((unsigned char *)res + sizeof (hdr), kmip, kmip_size);
  return res;
}

/* Create a clear-text escrow packet with secret of SECRET_TYPE from VOL, store
   it into PACKET (for g_free()) and SIZE.
   Return 0 if OK, -1 on error.
   VOL must contain at least one "secret".
   Be extremely careful with the results! */
void *
libvk_volume_create_packet_cleartext (const struct libvk_volume *vol,
				      size_t *size,
				      enum libvk_secret secret_type,
				      GError **error)
{
  struct kmip_libvk_packet *pack;
  void *inner;
  unsigned char *res;
  size_t inner_size;

  g_return_val_if_fail (vol != NULL, NULL);
  g_return_val_if_fail (size != NULL, NULL);
  g_return_val_if_fail ((unsigned)secret_type < LIBVK_SECRET_END__, NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);

  pack = volume_create_escrow_packet (vol, secret_type, error);
  if (pack == NULL)
    return NULL;
  inner = kmip_libvk_packet_encode (pack, &inner_size, error);
  kmip_libvk_packet_free (pack);
  if (inner == NULL)
    return NULL;

  res = packet_prepend_header (size, inner, inner_size,
			       LIBVK_PACKET_FORMAT_CLEARTEXT);
  memset (inner, 0, inner_size);
  g_free (inner);

  return res;
}

/* Create an escrow packet encrypted for CERT with secret of SECRET_TYPE from
   VOL, store its size into SIZE.
   Return the packet (for g_free ()) if OK, NULL on error.
   VOL must contain at least one "secret".
   May use UI. */
void *
libvk_volume_create_packet_asymmetric (const struct libvk_volume *vol,
				       size_t *size,
				       enum libvk_secret secret_type,
				       CERTCertificate *cert,
				       const struct libvk_ui *ui,
				       GError **error)
{
  g_return_val_if_fail (vol != NULL, NULL);
  g_return_val_if_fail (size != NULL, NULL);
  g_return_val_if_fail ((unsigned)secret_type < LIBVK_SECRET_END__, NULL);
  g_return_val_if_fail (cert != NULL, NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);

  return libvk_volume_create_packet_asymmetric_with_format
    (vol, size, secret_type, cert, ui,
     LIBVK_PACKET_FORMAT_ASYMMETRIC_WRAP_SECRET_ONLY, error);
}

/* For compatibility */
void *
libvk_volume_create_packet_assymetric (const struct libvk_volume *vol,
				       size_t *size,
				       enum libvk_secret secret_type,
				       CERTCertificate *cert,
				       const struct libvk_ui *ui,
				       GError **error)
{
  return libvk_volume_create_packet_asymmetric (vol, size, secret_type, cert,
						ui, error);
}

/* Create an escrow packet encrypted for CERT with secret of SECRET_TYPE from
   VOL using FORMAT, store its size into SIZE.
   Return the packet (for g_free ()) if OK, NULL on error.
   VOL must contain at least one "secret".
   May use UI. */
void *
libvk_volume_create_packet_asymmetric_with_format
	(const struct libvk_volume *vol, size_t *size,
	 enum libvk_secret secret_type, CERTCertificate *cert,
	 const struct libvk_ui *ui, enum libvk_packet_format format,
	 GError **error)
{
  struct kmip_libvk_packet *pack;
  void *encrypted, *res;
  size_t encrypted_size;

  g_return_val_if_fail (vol != NULL, NULL);
  g_return_val_if_fail (size != NULL, NULL);
  g_return_val_if_fail ((unsigned)secret_type < LIBVK_SECRET_END__, NULL);
  g_return_val_if_fail (cert != NULL, NULL);
  g_return_val_if_fail ((unsigned)format < LIBVK_PACKET_FORMAT_END__, NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);

  pack = volume_create_escrow_packet (vol, secret_type, error);
  if (pack == NULL)
    goto err;

  switch (format)
    {
    case LIBVK_PACKET_FORMAT_ASYMMETRIC:
      {
	void *inner;
	size_t inner_size;

	inner = kmip_libvk_packet_encode (pack, &inner_size, error);
	if (inner == NULL)
	  goto err_pack;
	encrypted = encrypt_asymmetric (&encrypted_size, inner, inner_size,
					cert, ui->nss_pwfn_arg, error);
	memset (inner, 0, inner_size);
	g_free (inner);
	if (encrypted == NULL)
	  goto err_pack;
	break;
      }

    case LIBVK_PACKET_FORMAT_ASYMMETRIC_WRAP_SECRET_ONLY:
      {
	if (kmip_libvk_packet_wrap_secret_asymmetric (pack, cert, ui,
						      error) != 0)
	  goto err_pack;
	encrypted = kmip_libvk_packet_encode (pack, &encrypted_size, error);
	if (encrypted == NULL)
	  goto err_pack;
	break;
      }

    default:
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_UNSUPPORTED_FORMAT,
		   _("Unsupported asymmetric encryption format"));
      goto err_pack;
    }

  kmip_libvk_packet_free (pack);

  res = packet_prepend_header (size, encrypted, encrypted_size, format);
  g_free (encrypted);

  return res;

 err_pack:
  kmip_libvk_packet_free (pack);
 err:
  return NULL;
}

/* Create an escrow packet encrypted using PASSPHRASE with secret of SECRET_TYPE
   from VOL, store its size into SIZE.
   Return the packet (for g_free ()) if OK, NULL on error.
   VOL must contain at least one "secret". */
void *
libvk_volume_create_packet_with_passphrase (const struct libvk_volume *vol,
					    size_t *size,
					    enum libvk_secret secret_type,
					    const char *passphrase,
					    GError **error)
{
  struct kmip_libvk_packet *pack;
  void *inner, *encrypted, *res;
  size_t inner_size, encrypted_size;

  g_return_val_if_fail (vol != NULL, NULL);
  g_return_val_if_fail (size != NULL, NULL);
  g_return_val_if_fail ((unsigned)secret_type < LIBVK_SECRET_END__, NULL);
  g_return_val_if_fail (passphrase != NULL, NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);

  pack = volume_create_escrow_packet (vol, secret_type, error);
  if (pack == NULL)
    return NULL;
  inner = kmip_libvk_packet_encode (pack, &inner_size, error);
  kmip_libvk_packet_free (pack);
  if (inner == NULL)
    return NULL;

  encrypted = encrypt_with_passphrase (&encrypted_size, inner, inner_size,
				       passphrase, error);
  memset (inner, 0, inner_size);
  g_free (inner);
  if (encrypted == NULL)
    return NULL;

  res = packet_prepend_header (size, encrypted, encrypted_size,
			       LIBVK_PACKET_FORMAT_PASSPHRASE);
  g_free (encrypted);

  return res;
}

/* Create an escrow packet with the secrets wrapped using KEY from VOL, store
   its size into SIZE.
   Return the packet (for g_free ()) if OK, NULL on error.
   VOL must contain at least one "secret".
   May use UI. */
void *
libvk_volume_create_packet_wrap_secret_symmetric
	(const struct libvk_volume *vol, size_t *size,
	 enum libvk_secret secret_type, PK11SymKey *key,
	 const struct libvk_ui *ui, GError **error)
{
  struct kmip_libvk_packet *pack;
  void *encrypted, *res;
  size_t encrypted_size;

  g_return_val_if_fail (vol != NULL, NULL);
  g_return_val_if_fail (size != NULL, NULL);
  g_return_val_if_fail ((unsigned)secret_type < LIBVK_SECRET_END__, NULL);
  g_return_val_if_fail (key != NULL, NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);

  pack = volume_create_escrow_packet (vol, secret_type, error);
  if (pack == NULL)
    goto err;

  if (kmip_libvk_packet_wrap_secret_symmetric (pack, key, ui, error) != 0)
    goto err_pack;
  encrypted = kmip_libvk_packet_encode (pack, &encrypted_size, error);
  if (encrypted == NULL)
    goto err_pack;

  kmip_libvk_packet_free (pack);

  res = packet_prepend_header (size, encrypted, encrypted_size,
			       LIBVK_PACKET_FORMAT_SYMMETRIC_WRAP_SECRET_ONLY);

  g_free (encrypted);

  return res;

 err_pack:
  kmip_libvk_packet_free (pack);
 err:
  return NULL;
}

/* Return a format of PACKET of SIZE, or LIBVK_PACKET_FORMAT_UNKNOWN */
enum libvk_packet_format
libvk_packet_get_format (const void *packet, size_t size, GError **error)
{
  struct packet_header hdr;

  g_return_val_if_fail (packet != NULL, LIBVK_PACKET_FORMAT_UNKNOWN);
  g_return_val_if_fail (error == NULL || *error == NULL,
			LIBVK_PACKET_FORMAT_UNKNOWN);

  if (size < sizeof (hdr))
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_INVALID_INPUT,
		   _("Input packet is too small"));
      return LIBVK_PACKET_FORMAT_UNKNOWN;
    }
  memcpy (&hdr, packet, sizeof (hdr));
  {
    G_STATIC_ASSERT (sizeof (hdr.magic) == sizeof (packet_magic));
  }
  if (memcmp (hdr.magic, packet_magic, sizeof (hdr.magic)) != 0)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_INVALID_INPUT,
		   _("Input is not a volume_key escrow packet"));
      return LIBVK_PACKET_FORMAT_UNKNOWN;
    }
  if (hdr.format >= LIBVK_PACKET_FORMAT_END__)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_KMIP_INVALID_INPUT,
		   _("Unsupported packet format"));
      return LIBVK_PACKET_FORMAT_UNKNOWN;
    }
  return hdr.format;
}

/* Open PACKET of SIZE, using UI.
   Return the volume information it contains, or NULL on error. */
struct libvk_volume *
libvk_packet_open (const void *packet, size_t size, const struct libvk_ui *ui,
		   GError **error)
{
  enum libvk_packet_format format;
  const void *outer;
  size_t outer_size;
  struct kmip_libvk_packet *pack;
  struct libvk_volume *v;

  g_return_val_if_fail (packet != NULL, NULL);
  g_return_val_if_fail (ui != NULL, NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);

  format = libvk_packet_get_format (packet, size, error);
  if (format == LIBVK_PACKET_FORMAT_UNKNOWN)
    goto err;
  g_return_val_if_fail (size >= sizeof (struct packet_header), NULL);
  outer = (const unsigned char *)packet + sizeof (struct packet_header);
  outer_size = size - sizeof (struct packet_header);
  switch (format)
    {
    case LIBVK_PACKET_FORMAT_CLEARTEXT:
      pack = kmip_libvk_packet_decode (outer, outer_size, error);
      if (pack == NULL)
	goto err;
      break;

    case LIBVK_PACKET_FORMAT_ASYMMETRIC:
      {
	void *inner;
	size_t inner_size;

	inner = decrypt_asymmetric (&inner_size, outer, outer_size,
				    ui->nss_pwfn_arg, error);
	if (inner == NULL)
	  goto err;
	pack = kmip_libvk_packet_decode (inner, inner_size, error);
	memset (inner, 0, inner_size);
	g_free (inner);
	if (pack == NULL)
	  goto err;
	break;
      }

    case LIBVK_PACKET_FORMAT_PASSPHRASE:
      {
	unsigned failed;
	void *inner;
	size_t inner_size;

	/* Our only real concern is overflow of the failed counter; limit the
	   number of iterations just in case the application programmer is
	   always returning the same passphrase from the callback, regardless
	   of the failed counter. */
	for (failed = 0; failed < 64; failed++)
	  {
	    char *passphrase;

	    passphrase = ui_get_passphrase (ui, _("Escrow packet passphrase"),
					    failed, error);
	    if (passphrase == NULL)
	      goto err;
	    inner = decrypt_with_passphrase (&inner_size, outer, outer_size,
					     passphrase, error);
	    g_free (passphrase);
	    if (inner != NULL)
	      goto got_passphrase;
	    g_clear_error (error);
	  }
	g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_FAILED,
		     _("Too many attempts to get a valid passphrase"));
	goto err;

      got_passphrase:
	pack = kmip_libvk_packet_decode (inner, inner_size, error);
	memset (inner, 0, inner_size);
	g_free (inner);
	if (pack == NULL)
	  goto err;
	break;
      }

    case LIBVK_PACKET_FORMAT_ASYMMETRIC_WRAP_SECRET_ONLY:
      pack = kmip_libvk_packet_decode (outer, outer_size, error);
      if (pack == NULL)
	goto err;
      if (kmip_libvk_packet_unwrap_secret_asymmetric (pack, ui, error) != 0)
	goto err_pack;
      break;

    case LIBVK_PACKET_FORMAT_SYMMETRIC_WRAP_SECRET_ONLY:
      {
	unsigned failed;

	/* Our only real concern is overflow of the failed counter; limit the
	   number of iterations just in case the application programmer is
	   always returning the same key from the callback, regardless of the
	   failed counter. */
	for (failed = 0; failed < 64; failed++)
	  {
	    PK11SymKey *key;

	    pack = kmip_libvk_packet_decode (outer, outer_size, error);
	    if (pack == NULL)
	      goto err;
	    key = ui_get_sym_key (ui, failed, error);
	    if (key == NULL)
	      goto err;
	    if (kmip_libvk_packet_unwrap_secret_symmetric (pack, key,
							   error) == 0)
	      goto unwrapped_symmetric;
	    g_clear_error (error);
	  }
	g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_FAILED,
		     _("Too many attempts to get a valid symmetric key"));
	goto err;

      unwrapped_symmetric:
	break;
      }

    default:
      g_return_val_if_reached (NULL);
    }

  v = volume_load_escrow_packet (pack, error);
  kmip_libvk_packet_free (pack);
  return v;

 err_pack:
  kmip_libvk_packet_free (pack);
 err:
  return NULL;
}

/* Open PACKET of SIZE, without decrypting it or asking for any decryption keys.
   Return the volume information it contains, or NULL on error.
   On success, at least some of the metadata must be available. */
struct libvk_volume *
libvk_packet_open_unencrypted (const void *packet, size_t size, GError **error)
{
  enum libvk_packet_format format;
  const void *outer;
  size_t outer_size;
  struct kmip_libvk_packet *pack;
  struct libvk_volume *v;

  g_return_val_if_fail (packet != NULL, NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);

  format = libvk_packet_get_format (packet, size, error);
  if (format == LIBVK_PACKET_FORMAT_UNKNOWN)
    return NULL;
  g_return_val_if_fail (size >= sizeof (struct packet_header), NULL);
  outer = (const unsigned char *)packet + sizeof (struct packet_header);
  outer_size = size - sizeof (struct packet_header);
  switch (format)
    {
    case LIBVK_PACKET_FORMAT_CLEARTEXT:
      pack = kmip_libvk_packet_decode (outer, outer_size, error);
      if (pack == NULL)
	return NULL;
      break;

    case LIBVK_PACKET_FORMAT_ASYMMETRIC: case LIBVK_PACKET_FORMAT_PASSPHRASE:
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_METADATA_ENCRYPTED,
		   _("The packet metadata is encrypted"));
      return NULL;

    case LIBVK_PACKET_FORMAT_ASYMMETRIC_WRAP_SECRET_ONLY:
    case LIBVK_PACKET_FORMAT_SYMMETRIC_WRAP_SECRET_ONLY:
      pack = kmip_libvk_packet_decode (outer, outer_size, error);
      if (pack == NULL)
	return NULL;
      kmip_libvk_packet_drop_secret (pack);
      break;

    default:
      g_return_val_if_reached (NULL);
    }

  v = volume_load_escrow_packet (pack, error);
  kmip_libvk_packet_free (pack);
  return v;
}
