/* Encryption round-trip (encrypt/decrypt) tests.

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

#include <assert.h>
#include <stdio.h>
#include <sys/stat.h>

#include <glib.h>
#include <nss.h>
#include <prerror.h>
#include <prinit.h>
#include <pk11pub.h>
#include <secmod.h>

#include "../lib/crypto.h"
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

static void *
data_from_file (size_t *res_size, const char *filename)
{
  struct stat st;
  FILE *f;
  void *res;
  size_t size;

  if (stat (filename, &st) != 0)
    {
      perror ("stat ()");
      return NULL;
    }
  size = st.st_size;
  assert ((off_t)size == st.st_size);
  f = fopen (filename, "rb");
  if (f == NULL)
    {
      perror ("fopen ()");
      return NULL;
    }
  res = g_malloc (size);
  if (fread (res, 1, size, f) != size)
    {
      perror ("fread ()");
      fclose (f);
      return NULL;
    }
  fclose (f);
  *res_size = size;
  return res;
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

int
main (void)
{
  GError *error;
  void *original, *encrypted, *decrypted, *cert_data;
  size_t original_size, encrypted_size, decrypted_size, cert_size;
  CERTCertificate *cert;

  error = NULL;
  PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 0);
  if (NSS_Init("nss_db") != SECSuccess)
    {
      error_from_pr (&error);
      fprintf (stderr, "Error initializing NSS: %s\n", error->message);
      return EXIT_FAILURE;
    }
  PK11_SetPasswordFunc (nss_password_fn);

  original_size = 1024;
  original = g_malloc (original_size);
  memset (original, 0xAA, original_size);

  encrypted = encrypt_with_passphrase (&encrypted_size, original, original_size,
				       "password", &error);
  if (encrypted == NULL)
    {
      fprintf (stderr, "Error encrypting: %s\n", error->message);
      g_error_free (error);
      return EXIT_FAILURE;
    }
  decrypted = decrypt_with_passphrase (&decrypted_size, encrypted,
				       encrypted_size, "password", &error);
  g_free (encrypted);
  if (decrypted == NULL)
    {
      fprintf (stderr, "Error decrypting: %s\n", error->message);
      g_error_free (error);
      return EXIT_FAILURE;
    }
  if (decrypted_size != original_size
      || memcmp (decrypted, original, original_size) != 0)
    {
      fprintf (stderr, "Password encryption data mismatch\n");
      return EXIT_FAILURE;
    }
  g_free (decrypted);

  cert_data = data_from_file (&cert_size, "cert.pem");
  if (cert_data == NULL)
    {
      fprintf (stderr, "Cannot open certificate\n");
      return EXIT_FAILURE;
    }
  cert = CERT_DecodeCertFromPackage (cert_data, cert_size);
  g_free (cert_data);
  if (cert == NULL)
    {
      error_from_pr (&error);
      return EXIT_FAILURE;
    }
  encrypted = encrypt_assymetric (&encrypted_size, original, original_size,
				  cert, NULL, &error);
  CERT_DestroyCertificate (cert);
  if (encrypted == NULL)
    {
      fprintf (stderr, "Error encrypting: %s\n", error->message);
      g_error_free (error);
      return EXIT_FAILURE;
    }
  decrypted = decrypt_assymetric (&decrypted_size, encrypted, encrypted_size,
				  NULL, &error);
  g_free (encrypted);
  if (decrypted == NULL)
    {
      fprintf (stderr, "Error decrypting: %s\n", error->message);
      g_error_free (error);
      return EXIT_FAILURE;
    }
  if (decrypted_size != original_size
      || memcmp (decrypted, original, original_size) != 0)
    {
      fprintf (stderr, "Certificate encryption data mismatch\n");
      return EXIT_FAILURE;
    }
  g_free (decrypted);

  g_free (original);
  NSS_Shutdown();

  return EXIT_SUCCESS;
}
