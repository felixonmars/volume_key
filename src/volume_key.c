/* A command-line utility.

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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <nss.h>
#include <pk11pub.h>
#include <prerror.h>
#include <prinit.h>
#include <secmod.h>

// FIXME: use the actual include paths?
#include "../lib/crypto.h"
#include "../lib/libvolume_key.h"
#include "../lib/kmip.h"
#include "../lib/volume.h"

static char *
nss_password_fn (PK11SlotInfo *slot, PRBool retry, void *arg)
{
  char *prompt, *res;

  fprintf (stderr, "%s", (char *)arg);
  if (retry)
    fprintf (stderr, "Error, try again.\n");
  prompt = g_strdup_printf ("Enter password for \"%s\": ",
			    PK11_GetTokenName (slot));
  res = getpass (prompt);
  g_free (prompt);
  return PL_strdup (res);
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
  res = g_malloc (size != 0 ? size : 1);
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

static char *
generic_ui_cb (void *id, const char *prompt, int echo)
{
  if (echo)
    {
      char *res;

      fputs (id, stderr);
      putc (' ', stderr);
      res = getpass (prompt);
      if (res != NULL && res[0] != '\0')
	return g_strdup (res);
      return NULL;
    }
  else
    {
      char buf[LINE_MAX];
      size_t len;

      fprintf (stderr, "%s %s", (char *)id, prompt);
      fflush (stderr);
      if (fgets (buf, sizeof (buf), stdin) == NULL)
	return NULL;
      len = strlen (buf);
      if (len != 0 && buf[len - 1] == '\n')
	{
	  len--;
	  buf[len] = '\0';
	}
      if (len == 0)
	return NULL;
      return g_memdup (buf, len + 1);
    }
}

static char *
passphrase_ui_cb (void *id, const char *prompt, unsigned failed_attempts)
{
  char *res;

  fprintf (stderr, "%s (%u failed attempts) ", (char *)id, failed_attempts);
  res = getpass (prompt);
  if (res != NULL && res[0] != '\0')
    return g_strdup (res);
  return NULL;
}

static struct libvk_ui *
create_ui (void)
{
  struct libvk_ui *ui;

  ui = libvk_ui_new ();
  libvk_ui_set_generic_cb (ui, generic_ui_cb, g_strdup ("(Generic)"), g_free);
  libvk_ui_set_passphrase_cb (ui, passphrase_ui_cb, g_strdup ("(Passphrase)"),
			    g_free);
  libvk_ui_set_nss_pwfn_arg (ui, g_strdup ("(NSS arg)"), g_free);
  return ui;
}

static void
print_volume_info (const struct libvk_volume *vol)
{
  GSList *list, *next;
  char *s;

  for (list = libvk_volume_dump_properties (vol, 1); list != NULL; list = next)
    {
      GPtrArray *a;
      char *name, *value;

      a = list->data;
      name = g_ptr_array_index (a, 0);
      value = g_ptr_array_index (a, 1);
      fprintf (stderr, "%s:\t%s\n", name, value);
      g_free (name);
      g_free (value);
      g_ptr_array_free (a, TRUE);
      next = list->next;
      g_slist_free_1 (list);
    }
  s = libvk_volume_get_hostname (vol);
  fprintf (stderr, "Host name:\t%s\n", s);
  g_free (s);
  s = libvk_volume_get_uuid (vol);
  fprintf (stderr, "UUID:\t%s\n", s);
  g_free (s);
  s = libvk_volume_get_label (vol);
  fprintf (stderr, "Label:\t%s\n", s);
  g_free (s);
  s = libvk_volume_get_path (vol);
  fprintf (stderr, "Path:\t%s\n", s);
  g_free (s);
  s = libvk_volume_get_format (vol);
  fprintf (stderr, "Format:\t%s\n", s);
  g_free (s);
}

static struct libvk_volume *
open_volume (const char *path, struct libvk_ui *ui, GError **error)
{
  struct libvk_volume *v;

  v = libvk_volume_open (path, error);
  if (v == NULL)
    return NULL;

  if (libvk_volume_get_secret (v, LIBVK_SECRET_DEFAULT, ui, error) != 0)
    {
      libvk_volume_free (v);
      return NULL;
    }

  print_volume_info (v);

  return v;
}

int
create_escrow_packet (int argc, char *argv[])
{
  GError *error;
  struct libvk_volume *v;
  struct libvk_ui *ui;
  void *packet;
  size_t size;

  (void)argc;
  error = NULL;
  ui = create_ui ();
  v = open_volume (argv[1], ui, &error);
  libvk_ui_free (ui);
  if (v == NULL)
    {
      fprintf (stderr, "Error opening volume: %s\n", error->message);
      g_error_free (error);
      return EXIT_FAILURE;
    }

  packet = libvk_volume_create_packet_cleartext (v, &size, LIBVK_SECRET_DEFAULT,
						 &error);
  if (packet == NULL)
    {
      fprintf (stderr, "Error creating escrow packet: %s\n", error->message);
      g_error_free (error);
      return EXIT_FAILURE;
    }
  libvk_volume_free (v);

  kmip_dump (stderr, (const unsigned char *)packet + 12, size - 12);
  fwrite (packet, 1, size, stdout);

  v = volume_load_escrow_packet ((const unsigned char *)packet + 12, size - 12,
				 &error);
  memset (packet, 0, size);
  g_free (packet);

  if (v == NULL)
    {
      fprintf (stderr, "Error loading escrow packet: %s\n", error->message);
      return EXIT_FAILURE;
    }
  else
    {
      libvk_volume_free (v);
      fprintf (stderr, "OK");
    }
  return EXIT_SUCCESS;
}

int
escrow_packet_for_cert (int argc, char *argv[])
{
  GError *error;
  struct libvk_volume *v;
  struct libvk_ui *ui;
  void *packet, *cert_data;
  size_t size, cert_size;
  CERTCertificate *cert;

  (void)argc;
  error = NULL;
  ui = create_ui ();
  v = open_volume (argv[1], ui, &error);
  if (v == NULL)
    {
      fprintf (stderr, "Error opening volume: %s\n", error->message);
      g_error_free (error);
      libvk_ui_free (ui);
      return EXIT_FAILURE;
    }

  cert_data = data_from_file (&cert_size, argv[2]);
  if (cert_data == NULL)
    return EXIT_FAILURE;
  cert = CERT_DecodeCertFromPackage (cert_data, cert_size);
  g_free (cert_data);
  if (cert == NULL)
    {
      error_from_pr (&error);
      return EXIT_FAILURE;
    }

  packet = libvk_volume_create_packet_assymetric (v, &size,
						  LIBVK_SECRET_DEFAULT, cert,
						  ui, &error);
  CERT_DestroyCertificate (cert);
  libvk_volume_free (v);
  libvk_ui_free (ui);
  if (packet == NULL)
    {
      fprintf (stderr, "Error creating escrow packet: %s\n", error->message);
      g_error_free (error);
      return EXIT_FAILURE;
    }

  if (fwrite (packet, 1, size, stdout) != size)
    {
      perror ("fwrite ()");
      return EXIT_FAILURE;
    }
  g_free (packet);

  return EXIT_SUCCESS;
}

int
escrow_packet_for_passphrase (int argc, char *argv[])
{
  GError *error;
  struct libvk_volume *v;
  struct libvk_ui *ui;
  void *packet;
  size_t size;

  (void)argc;
  error = NULL;
  ui = create_ui ();
  v = open_volume (argv[1], ui, &error);
  libvk_ui_free (ui);
  if (v == NULL)
    {
      fprintf (stderr, "Error opening volume: %s\n", error->message);
      g_error_free (error);
      return EXIT_FAILURE;
    }

  packet = libvk_volume_create_packet_with_passphrase (v, &size,
						       LIBVK_SECRET_DEFAULT,
						       "password", &error);
  libvk_volume_free (v);
  if (packet == NULL)
    {
      fprintf (stderr, "Error creating escrow packet: %s\n", error->message);
      g_error_free (error);
      return EXIT_FAILURE;
    }

  if (fwrite (packet, 1, size, stdout) != size)
    {
      perror ("fwrite ()");
      return EXIT_FAILURE;
    }
  g_free (packet);

  return EXIT_SUCCESS;
}

int
apply_packet (int argc, char *argv[])
{
  GError *error;
  GPtrArray *warnings;
  void *packet;
  size_t size;
  struct libvk_volume *pack, *v;
  struct libvk_ui *ui;

  (void)argc;
  error = NULL;
  packet = data_from_file (&size, argv[1]);
  if (packet == NULL)
    return EXIT_FAILURE;

  ui = create_ui ();
  switch (libvk_packet_get_format (packet, size, &error))
    {
    case LIBVK_PACKET_FORMAT_UNKNOWN:
      fprintf (stderr, "Invalid packet: %s\n", error->message);
      g_clear_error (&error);
      break;

    case LIBVK_PACKET_FORMAT_CLEARTEXT:
      printf ("Clear-text packet:\n");
      break;

    case LIBVK_PACKET_FORMAT_ASSYMETRIC:
      printf ("Cert-encrypted packet:\n");
      break;

    case LIBVK_PACKET_FORMAT_PASSPHRASE:
      printf ("Passphrase-protected packet:\n");
      break;

    default:
      abort ();
    }
  pack = libvk_packet_open (packet, size, ui, &error);
  g_free (packet);

  if (pack == NULL)
    {
      fprintf (stderr, "Error opening packet: %s\n", error->message);
      return EXIT_FAILURE;
    }
  print_volume_info (pack);

  v = libvk_volume_open (argv[2], &error);
  if (v == NULL)
    {
      fprintf (stderr, "Error opening volume: %s\n", error->message);
      return EXIT_FAILURE;
    }

  warnings = g_ptr_array_new ();
  switch (libvk_packet_match_volume (pack, v, warnings, &error))
    {
    case LIBVK_PACKET_MATCH_OK:
      break;

    case LIBVK_PACKET_MATCH_ERROR:
      fprintf (stderr, "Packet does not match volume: %s\n", error->message);
      return EXIT_FAILURE;

    case LIBVK_PACKET_MATCH_UNSURE:
      {
	size_t i;
	char c[2];

	fprintf (stderr, "Are you sure you want to apply this packet?\n");
	for (i = 0; i < warnings->len; i++)
	  {
	    char *s;

	    s = g_ptr_array_index (warnings, i);
	    fprintf (stderr, "  %s\n", s);
	    g_free (s);
	  }
	fprintf (stderr, "(y/n)");
	if (fscanf (stderr, " %1[yYnN]", c) != 1
	    || (c[0] != 'y' && c[0] != 'Y'))
	  return EXIT_FAILURE;
	break;
      }
    }
  g_ptr_array_free (warnings, TRUE);

  if (libvk_volume_apply_packet (v, pack, LIBVK_SECRET_DEFAULT, ui, &error)
      != 0)
    {
      fprintf (stderr, "Error restoring access: %s\n", error->message);
      return EXIT_FAILURE;
    }

  libvk_volume_free (v);
  libvk_volume_free (pack);
  libvk_ui_free (ui);
  return EXIT_SUCCESS;
}

int
random_passphrase (int argc, char *argv[])
{
#define PASSPHRASE_LENGTH 8
  GError *error;
  struct libvk_volume *v;
  struct libvk_ui *ui;
  void *packet;
  size_t size, i;
  unsigned char rnd[PASSPHRASE_LENGTH];
  char passphrase[PASSPHRASE_LENGTH + 1];

  (void)argc;
  error = NULL;
  ui = create_ui ();
  v = open_volume (argv[1], ui, &error);
  libvk_ui_free (ui);
  if (v == NULL)
    {
      fprintf (stderr, "Error opening volume: %s\n", error->message);
      g_error_free (error);
      return EXIT_FAILURE;
    }

  if (PK11_GenerateRandom (rnd, sizeof (rnd)) != SECSuccess)
    {
      error_from_pr (&error);
      fprintf (stderr, "Error generating passphrase: %s\n", error->message);
      return EXIT_FAILURE;
    }

  for (i = 0; i < sizeof (passphrase) - 1; i++)
    {
      static const char set[36] = "0123456789zbcdefghijklmnopqrstuvwxyz";

      passphrase[i] = set[rnd[i] % sizeof (set)];
    }
  passphrase[i] = '\0';

  if (libvk_volume_add_secret (v, LIBVK_SECRET_PASSPHRASE, passphrase,
			       strlen (passphrase) + 1, &error) != 0)
    {
      fprintf (stderr, "Error setting a passphrase: %s\n", error->message);
      return EXIT_FAILURE;
    }
  fprintf (stderr, "-> Generated passphrase: %s\n", passphrase);
  print_volume_info (v);

  packet = libvk_volume_create_packet_cleartext (v, &size,
						 LIBVK_SECRET_PASSPHRASE,
						 &error);
  if (packet == NULL)
    {
      fprintf (stderr, "Error creating escrow packet: %s\n", error->message);
      g_error_free (error);
      return EXIT_FAILURE;
    }
  libvk_volume_free (v);

  kmip_dump (stderr, (const unsigned char *)packet + 12, size - 12);
  fwrite (packet, 1, size, stdout);

  v = volume_load_escrow_packet ((const unsigned char *)packet + 12, size - 12,
				 &error);
  memset (packet, 0, size);
  g_free (packet);

  if (v == NULL)
    {
      fprintf (stderr, "Error loading escrow packet: %s\n", error->message);
      return EXIT_FAILURE;
    }
  else
    {
      libvk_volume_free (v);
      fprintf (stderr, "OK");
    }
  return EXIT_SUCCESS;
#undef PASSPHRASE_LENGTH
}


int
main (int argc, char *argv[])
{
  GError *error;
  int res;

  (void)argc;
  error = NULL;
  PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 0);
  if (NSS_Init("nss_db") != SECSuccess) // FIXME: path
    {
      error_from_pr (&error);
      fprintf (stderr, "Error initializing NSS: %s\n", error->message);
      return EXIT_FAILURE;
    }
  PK11_SetPasswordFunc (nss_password_fn);

  if (0)
    res = create_escrow_packet (argc, argv);
  else if (0)
    res = escrow_packet_for_cert (argc, argv);
  else if (0)
    res = escrow_packet_for_passphrase (argc, argv);
  else if (0)
    res = apply_packet (argc, argv);
  else if (1)
    res = random_passphrase (argc, argv);


  NSS_Shutdown();

  return res;
}
