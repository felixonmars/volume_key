/* A packet round-trip encoding/decoding test.

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <nss.h>
#include <pk11pub.h>
#include <prerror.h>
#include <prinit.h>

#include "../lib/libvolume_key.h"

static char *
nss_password_fn (PK11SlotInfo *slot, PRBool retry, void *arg)
{
  (void)slot;
  (void)arg;
  if (retry)
    return NULL;
  return PL_strdup ("nss_pw");
}

static void
error_from_pr (GError **error)
{
  size_t len;
  const char *err_utf8;
  char *err;

  err_utf8 = PR_ErrorToString (PR_GetError (), PR_LANGUAGE_I_DEFAULT);
  err = g_locale_from_utf8 (err_utf8, -1, NULL, NULL, NULL);
  /* Fall back to err_utf8 on error below. */
  len = PR_GetErrorTextLength();
  if (len == 0)
    g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_CRYPTO, "%s",
		 err != NULL ? err : err_utf8);
  else
    {
      char *msg;

      msg = g_malloc (len);
      PR_GetErrorText (msg);
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_CRYPTO, "%s: %s",
		   err != NULL ? err : err_utf8, msg);
      g_free (msg);
    }
  g_free (err);
}

static const char passphrase[] = "passphrase";

static char *
ui_passphrase_cb (void *data, const char *prompt, unsigned failed_attempts)
{
  (void)data;
  (void)prompt;
  if (failed_attempts != 0)
    return NULL;
  return g_strdup (passphrase);
}

static PK11SymKey *
ui_sym_key_cb (void *data_, unsigned failed_attempts)
{
  PK11SymKey *data;

  data = data_;
  if (failed_attempts != 0)
    return NULL;
  return PK11_ReferenceSymKey (data);
}

static void
free_sym_key (void *data_)
{
  PK11SymKey *data;

  data = data_;
  PK11_FreeSymKey (data);
}

static int
test (const char *test_packet, enum libvk_secret secret_type,
      CERTCertificate *cert, PK11SymKey *sym_key, struct libvk_ui *ui)
{
  GError *error;
  char *file_name;
  enum libvk_packet_format format;
  gchar *orig_packet;
  gsize orig_size;
  struct libvk_volume *v;
  void *packet2;
  size_t size2;

  error = NULL;
  file_name = g_strconcat (getenv ("srcdir"), "/", test_packet, NULL);
  if (g_file_get_contents (file_name, &orig_packet, &orig_size,
			   &error) == FALSE)
    {
      fprintf (stderr, "Error loading test packet: %s\n", error->message);
      g_error_free (error);
      return EXIT_FAILURE;
    }
  g_free (file_name);

  format = libvk_packet_get_format (orig_packet, orig_size, &error);
  if (format == LIBVK_PACKET_FORMAT_UNKNOWN)
    {
      fprintf (stderr, "Unknown test packet format: %s\n", error->message);
      g_error_free (error);
      return EXIT_FAILURE;
    }
  if (format != LIBVK_PACKET_FORMAT_CLEARTEXT)
    {
      fprintf (stderr, "Unexpected test packet format %d\n", format);
      return EXIT_FAILURE;
    }
  v = libvk_packet_open (orig_packet, orig_size, ui, &error);
  if (v == NULL)
    {
      fprintf (stderr, "Error loading test packet: %s\n", error->message);
      g_error_free (error);
      return EXIT_FAILURE;
    }

  packet2 = libvk_volume_create_packet_asymmetric_with_format
    (v, &size2, secret_type, cert, ui, LIBVK_PACKET_FORMAT_ASYMMETRIC, &error);
  libvk_volume_free (v);
  if (packet2 == NULL)
    {
      fprintf (stderr, "Error creating asymmetric packet: %s\n",
	       error->message);
      g_error_free (error);
      return EXIT_FAILURE;
    }
  if (libvk_packet_get_format (packet2, size2, &error)
      != LIBVK_PACKET_FORMAT_ASYMMETRIC)
    {
      fprintf (stderr, "Unexpected asymmetric packet format\n");
      return EXIT_FAILURE;
    }
  v = libvk_packet_open (packet2, size2, ui, &error);
  g_free (packet2);
  if (v == NULL)
    {
      fprintf (stderr, "Error loading asymmetric packet: %s\n", error->message);
      g_error_free (error);
      return EXIT_FAILURE;
    }

  packet2 = libvk_volume_create_packet_with_passphrase
    (v, &size2, secret_type, passphrase, &error);
  libvk_volume_free (v);
  if (packet2 == NULL)
    {
      fprintf (stderr, "Error creating passphrase-encrypted packet: %s\n",
	       error->message);
      g_error_free (error);
      return EXIT_FAILURE;
    }
  if (libvk_packet_get_format (packet2, size2, &error)
      != LIBVK_PACKET_FORMAT_PASSPHRASE)
    {
      fprintf (stderr, "Unexpected passphrase-encrypted packet format\n");
      return EXIT_FAILURE;
    }
  v = libvk_packet_open (packet2, size2, ui, &error);
  g_free (packet2);
  if (v == NULL)
    {
      fprintf (stderr, "Error loading passphrase-encrypted packet: %s\n",
	       error->message);
      g_error_free (error);
      return EXIT_FAILURE;
    }

  packet2 = libvk_volume_create_packet_asymmetric_with_format
    (v, &size2, secret_type, cert, ui,
     LIBVK_PACKET_FORMAT_ASYMMETRIC_WRAP_SECRET_ONLY, &error);
  libvk_volume_free (v);
  if (packet2 == NULL)
    {
      fprintf (stderr, "Error creating asymmetric key wrapping packet: %s\n",
	       error->message);
      g_error_free (error);
      return EXIT_FAILURE;
    }
  if (libvk_packet_get_format (packet2, size2, &error)
      != LIBVK_PACKET_FORMAT_ASYMMETRIC_WRAP_SECRET_ONLY)
    {
      fprintf (stderr, "Unexpected asymmetric key wrapping packet format\n");
      return EXIT_FAILURE;
    }
  v = libvk_packet_open (packet2, size2, ui, &error);
  g_free (packet2);
  if (v == NULL)
    {
      fprintf (stderr, "Error loading asymmetric key wrapping packet: %s\n",
	       error->message);
      g_error_free (error);
      return EXIT_FAILURE;
    }

  packet2 = libvk_volume_create_packet_wrap_secret_symmetric (v, &size2,
							      secret_type,
							      sym_key, ui,
							      &error);
  libvk_volume_free (v);
  if (packet2 == NULL)
    {
      fprintf (stderr, "Error creating symmetric key wrapping packet: %s\n",
	       error->message);
      g_error_free (error);
      return EXIT_FAILURE;
    }
  if (libvk_packet_get_format (packet2, size2, &error)
      != LIBVK_PACKET_FORMAT_SYMMETRIC_WRAP_SECRET_ONLY)
    {
      fprintf (stderr, "Unexpected symmetric key wrapping packet format\n");
      return EXIT_FAILURE;
    }
  v = libvk_packet_open (packet2, size2, ui, &error);
  g_free (packet2);
  if (v == NULL)
    {
      fprintf (stderr, "Error loading symmetric key wrapping packet: %s\n",
	       error->message);
      g_error_free (error);
      return EXIT_FAILURE;
    }

  packet2 = libvk_volume_create_packet_cleartext (v, &size2, secret_type,
						  &error);
  libvk_volume_free (v);
  if (packet2 == NULL)
    {
      fprintf (stderr, "Error creating cleartext packet: %s\n", error->message);
      g_error_free (error);
      return EXIT_FAILURE;
    }
  if (libvk_packet_get_format (packet2, size2, &error)
      != LIBVK_PACKET_FORMAT_CLEARTEXT)
    {
      fprintf (stderr, "Unexpected cleartext packet format\n");
      return EXIT_FAILURE;
    }

  if (orig_size != size2)
    {
      fprintf (stderr, "Size mismatch: %zu vs. %zu\n", orig_size, size2);
      return EXIT_FAILURE;
    }
  if (memcmp (orig_packet, packet2, orig_size) != 0)
    {
      fprintf (stderr, "Data difference\n");
      return EXIT_FAILURE;
    }
  g_free (orig_packet);
  g_free (packet2);
  return EXIT_SUCCESS;
}

int
main (void)
{
  struct libvk_ui *ui;
  GError *error;
  gchar *cert_data;
  gsize cert_size;
  CERTCertificate *cert;
  PK11SlotInfo *slot;
  PK11SymKey *sym_key;
  int r;

  error = NULL;
  PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 0);
  if (NSS_Init("nss_db") != SECSuccess)
    {
      error_from_pr (&error);
      fprintf (stderr, "Error initializing NSS: %s\n", error->message);
      return EXIT_FAILURE;
    }
  PK11_SetPasswordFunc (nss_password_fn);

  if (g_file_get_contents ("cert.pem", &cert_data, &cert_size, &error) == FALSE)
    {
      fprintf (stderr, "Error reading certificate: %s\n", error->message);
      g_error_free (error);
      return EXIT_FAILURE;
    }
  cert = CERT_DecodeCertFromPackage (cert_data, cert_size);
  g_free (cert_data);
  if (cert == NULL)
    {
      error_from_pr (&error);
      return EXIT_FAILURE;
    }

  slot = PK11_GetBestSlot (CKM_AES_CBC_PAD, NULL);
  if (slot == NULL)
    {
      error_from_pr (&error);
      fprintf (stderr, "Error getting a slot for key generation: %s\n",
	       error->message);
      g_error_free (error);
      return EXIT_FAILURE;
    }
  sym_key = PK11_KeyGen (slot, CKM_AES_CBC_PAD, NULL, 32, NULL);
  if (sym_key == NULL)
    {
      error_from_pr (&error);
      fprintf (stderr, "Error generating a symmetric key: %s\n",
	       error->message);
      g_error_free (error);
      return EXIT_FAILURE;
    }
  PK11_FreeSlot (slot);

  ui = libvk_ui_new ();
  libvk_ui_set_passphrase_cb (ui, ui_passphrase_cb, NULL, NULL);
  libvk_ui_set_sym_key_cb (ui, ui_sym_key_cb, sym_key, free_sym_key);

  r = test ("packet_roundtrips_luks_symmetric", LIBVK_SECRET_DEFAULT, cert,
	    sym_key, ui);
  if (r != EXIT_SUCCESS)
    return r;
  r = test ("packet_roundtrips_luks_passphrase", LIBVK_SECRET_PASSPHRASE, cert,
	    sym_key, ui);
  if (r != EXIT_SUCCESS)
    return r;

  libvk_ui_free (ui);
  CERT_DestroyCertificate(cert);
  NSS_Shutdown ();

  return EXIT_SUCCESS;
}
