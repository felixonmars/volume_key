/* Generic infrastructure for the volume_key library.

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

#include <glib.h>
#include <glib/gi18n-lib.h>

#include "crypto.h"
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
  void *inner;
  unsigned char *res;
  size_t inner_size;
  struct packet_header hdr;

  g_return_val_if_fail (vol != NULL, NULL);
  g_return_val_if_fail (size != NULL, NULL);
  g_return_val_if_fail ((unsigned)secret_type < LIBVK_SECRET_END__, NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);

  inner = volume_create_escrow_packet (vol, &inner_size, secret_type, error);
  if (inner == NULL)
    return NULL;
  {
    G_STATIC_ASSERT (sizeof (hdr.magic) == sizeof (packet_magic));
  }
  memcpy (hdr.magic, packet_magic, sizeof (hdr.magic));
  hdr.format = LIBVK_PACKET_FORMAT_CLEARTEXT;
  *size = sizeof (hdr) + inner_size;
  res = g_malloc (*size);
  memcpy (res, &hdr, sizeof (hdr));
  memcpy (res + sizeof (hdr), inner, inner_size);

  memset (inner, 0, inner_size);
  g_free (inner);

  return res;
}

/* Create an escrow packet encrypted for CERT with secret of SECRET_TYPE from
   VOL, store its size into SIZE.
   Return the packet (for g_free ()) if OK, NULL on error.
   VOL must contain at least one "secret".
   May use UI.
   Be extremely careful with the results! */
void *
libvk_volume_create_packet_assymetric (const struct libvk_volume *vol,
				       size_t *size,
				       enum libvk_secret secret_type,
				       CERTCertificate *cert,
				       const struct libvk_ui *ui,
				       GError **error)
{
  void *inner, *encrypted;
  unsigned char *res;
  size_t inner_size, encrypted_size;
  struct packet_header hdr;

  g_return_val_if_fail (vol != NULL, NULL);
  g_return_val_if_fail (size != NULL, NULL);
  g_return_val_if_fail ((unsigned)secret_type < LIBVK_SECRET_END__, NULL);
  g_return_val_if_fail (cert != NULL, NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);

  inner = volume_create_escrow_packet (vol, &inner_size, secret_type, error);
  if (inner == NULL)
    return NULL;

  encrypted = encrypt_assymetric (&encrypted_size, inner, inner_size, cert,
				  ui->nss_pwfn_arg, error);
  memset (inner, 0, inner_size);
  g_free (inner);
  if (encrypted == NULL)
    return NULL;

  {
    G_STATIC_ASSERT (sizeof (hdr.magic) == sizeof (packet_magic));
  }
  memcpy (hdr.magic, packet_magic, sizeof (hdr.magic));
  hdr.format = LIBVK_PACKET_FORMAT_ASSYMETRIC;

  *size = sizeof (hdr) + encrypted_size;
  res = g_malloc (*size);
  memcpy (res, &hdr, sizeof (hdr));
  memcpy (res + sizeof (hdr), encrypted, encrypted_size);

  g_free (encrypted);

  return res;
}

/* Create an escrow packet encrypted using PASSPHRASE with secret of SECRET_TYPE
   from VOL, store its size into SIZE.
   Return the packet (for g_free ()) if OK, NULL on error.
   VOL must contain at least one "secret".
   Be extremely careful with the results! */
void *
libvk_volume_create_packet_with_passphrase (const struct libvk_volume *vol,
					    size_t *size,
					    enum libvk_secret secret_type,
					    const char *passphrase,
					    GError **error)
{
  void *inner, *encrypted;
  unsigned char *res;
  size_t inner_size, encrypted_size;
  struct packet_header hdr;

  g_return_val_if_fail (vol != NULL, NULL);
  g_return_val_if_fail (size != NULL, NULL);
  g_return_val_if_fail ((unsigned)secret_type < LIBVK_SECRET_END__, NULL);
  g_return_val_if_fail (passphrase != NULL, NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);

  inner = volume_create_escrow_packet (vol, &inner_size, secret_type, error);
  if (inner == NULL)
    return NULL;

  encrypted = encrypt_with_passphrase (&encrypted_size, inner, inner_size,
				       passphrase, error);
  memset (inner, 0, inner_size);
  g_free (inner);
  if (encrypted == NULL)
    return NULL;

  {
    G_STATIC_ASSERT (sizeof (hdr.magic) == sizeof (packet_magic));
  }
  memcpy (hdr.magic, packet_magic, sizeof (hdr.magic));
  hdr.format = LIBVK_PACKET_FORMAT_PASSPHRASE;

  *size = sizeof (hdr) + encrypted_size;
  res = g_malloc (*size);
  memcpy (res, &hdr, sizeof (hdr));
  memcpy (res + sizeof (hdr), encrypted, encrypted_size);

  g_free (encrypted);

  return res;
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
  const void *inner;
  void *to_free; 		/* inner or NULL */
  size_t inner_size;
  struct libvk_volume *v;

  g_return_val_if_fail (packet != NULL, NULL);
  g_return_val_if_fail (ui != NULL, NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);

  format = libvk_packet_get_format (packet, size, error);
  if (format == LIBVK_PACKET_FORMAT_UNKNOWN)
      return NULL;
  g_return_val_if_fail (size >= sizeof (struct packet_header), NULL);
  inner = (const unsigned char *)packet + sizeof (struct packet_header);
  inner_size = size - sizeof (struct packet_header);
  switch (format)
    {
    case LIBVK_PACKET_FORMAT_CLEARTEXT:
      to_free = NULL;
      break;

    case LIBVK_PACKET_FORMAT_ASSYMETRIC:
      to_free = decrypt_assymetric (&inner_size, inner, inner_size,
				    ui->nss_pwfn_arg, error);
      if (to_free == NULL)
	return NULL;
      inner = to_free;
      break;

    case LIBVK_PACKET_FORMAT_PASSPHRASE:
      {
	unsigned failed;

	/* Our only real concern is overflow of the failed counter; limit the
	   number of iterations just in case the application programmer is
	   always returning the same passphrase from the callback, regardless
	   of the failed counter. */
	for (failed = 0; failed < 64; failed++)
	  {
	    void *clear;
	    size_t clear_size;
	    char *passphrase;

	    passphrase = ui_get_passphrase (ui, _("Escrow packet passphrase"),
					    failed, error);
	    if (passphrase == NULL)
	      return NULL;
	    clear = decrypt_with_passphrase (&clear_size, inner, inner_size,
					     passphrase, error);
	    g_free (passphrase);
	    if (clear != NULL)
	      {
		to_free = clear;
		inner_size = clear_size;
		goto got_passphrase;
	      }
	    g_clear_error(error);
	  }
	g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_FAILED,
		     _("Too many attempts to get a valid passphrase"));
	return NULL;

      got_passphrase:
	inner = to_free;
	break;
      }

    default:
      g_return_val_if_reached (NULL);
    }

  v = volume_load_escrow_packet (inner, inner_size, error);
  if (to_free != NULL)
    {
      memset (to_free, 0, inner_size);
      g_free (to_free);
    }
  return v;
}
