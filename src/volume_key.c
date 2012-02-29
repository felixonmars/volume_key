/* A command-line utility.

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

#include <assert.h>
#include <langinfo.h>
#include <locale.h>
#include <regex.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#include <glib.h>
#include <glib/gi18n.h>
#include <libintl.h>
#include <nss.h>
#include <pk11pub.h>
#include <prerror.h>
#include <prinit.h>
#include <prmem.h>
#include <secmod.h>

#include "../lib/libvolume_key.h"
#include "../lib/nss_error.h"

 /* General utilities */

/* Print an error message FMT, ... (without trailing '\n') to stderr, and
   exit (EXIT_FAILURE). */
G_GNUC_NORETURN
static void
error_exit (const char *fmt, ...)
{
  va_list ap;

  fprintf (stderr, _("%s: "), g_get_prgname ());
  va_start (ap, fmt);
  vfprintf (stderr, fmt, ap);
  va_end (ap);
  fputc ('\n', stderr);
  exit (EXIT_FAILURE);
}

/* Interactively ask the user a "yes" or "no" QUESTION.
   Return 1 on "yes", 0 on "no", -1 on error. */
static int
yes_or_no (const char *question)
{
  regex_t re_yes, re_no;
  char *buf;
  size_t buf_size;
  int res;

  if (regcomp (&re_yes, nl_langinfo (YESEXPR), REG_EXTENDED | REG_NOSUB) != 0)
    g_return_val_if_reached (-1);
  if (regcomp (&re_no, nl_langinfo (NOEXPR), REG_EXTENDED | REG_NOSUB) != 0)
    g_return_val_if_reached (-1);
  buf = NULL;
  buf_size = 0;
  for (;;)
    {
      ssize_t len;

      /* TRANSLATORS: The "(y/n)" part should indicate to the user that input
	 matching (locale yesexpr) and (locale noexpr) is expected. */
      fprintf (stderr, _("%s (y/n) "), question);
      fflush (stderr);
      len = getline (&buf, &buf_size, stdin);
      if (len == -1)
	continue;
      if (len != 0 && buf[len - 1] == '\n')
	buf[len - 1] = '\0';
      if (regexec (&re_yes, buf, 0, NULL, 0) == 0)
	{
	  res = 1;
	  break;
	}
      else if (regexec (&re_no, buf, 0, NULL, 0) == 0)
	{
	  res = 0;
	  break;
	}
    }
  free (buf);
  regfree (&re_yes);
  regfree (&re_no);
  return res;
}

/* Set up ERROR based on NSPR error state. */
static void
error_from_pr (GError **error)
{
  size_t len;
  const char *err_utf8;
  char *err;

  err_utf8 = libvk_nss_error_text__ (PR_GetError ());
  if (err_utf8 == NULL)
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

 /* Options */

/* A directory that contains a NSS database, or NULL. */
static gchar *nss_dir; /* = NULL; */

/* Operation modes */
static gboolean mode_version, mode_save, mode_restore, mode_setup_volume;
static gboolean mode_reencrypt, mode_dump, mode_secrets; /* All = FALSE; */

/* Run in batch mode */
static gboolean batch_mode; /* = FALSE; */

/* if (mode_dump), include secrets in output */
static gboolean dump_with_secrets; /* = FALSE; */
/* if (mode_dump), do not attempt to decrypt anything */
static gboolean dump_unencrypted; /* = FALSE; */

/* Output format: */
/* Use clear-text instead of certificate or passphrase encryption */
static gboolean output_format_cleartext; /* = FALSE */
/* Certificate file path, or NULL to use some other output format. */
static gchar *output_certificate; /* = NULL; */
/* Explicit packet format - used when the above is not specific enough */
static enum libvk_packet_format output_format = LIBVK_PACKET_FORMAT_UNKNOWN;
static gchar *output_format_string; /* = NULL; */

/* Packet output files, or NULL */
static gchar *output_default; /* = NULL; */
static gchar *output_data_encryption_key; /* = NULL; */
static gchar *output_passphrase; /* = NULL; */
/* Random passphrase output file, or NULL */
static gchar *output_created_random_passphrase; /* = NULL; */

/* Use G_OPTION_ARG_FILENAME for all strings to avoid the conversion to
   UTF-8. */
static const GOptionEntry option_descriptions[] =
  {
    /* Operation modes */
    {
      "version", 0, 0, G_OPTION_ARG_NONE, &mode_version, N_("Show version"),
      NULL
    },
    {
      "save", 0, 0, G_OPTION_ARG_NONE, &mode_save,
      N_("Save volume secrets to a packet.  Expects operands VOLUME [PACKET]."),
      NULL
    },
    {
      "restore", 0, 0, G_OPTION_ARG_NONE, &mode_restore,
      N_("Restore volume secrets from a packet.  Expects operands VOLUME "
	 "PACKET."), NULL
    },
    {
      "setup-volume", 0, 0, G_OPTION_ARG_NONE, &mode_setup_volume,
      N_("Set up an encrypted volume using secrets from a packet.  Expects "
	 "operands VOLUME PACKET NAME."), NULL
    },
    {
      "reencrypt", 0, 0, G_OPTION_ARG_NONE, &mode_reencrypt,
      N_("Re-encrypt an escrow packet.  Expects operand PACKET."), NULL
    },
    {
      "dump", 0, 0, G_OPTION_ARG_NONE, &mode_dump,
      N_("Show information contained in a packet.  Expects operand PACKET."),
      NULL
    },
    {
      "secrets", 0, 0, G_OPTION_ARG_NONE, &mode_secrets,
      N_("Show secrets contained in a packet.  Expects operand PACKET."), NULL
    },
    /* Common options */
    {
      "nss-dir", 'd', 0, G_OPTION_ARG_FILENAME, &nss_dir,
      N_("Use the NSS database in DIR"), N_("DIR")
    },
    {
      "batch", 'b', 0, G_OPTION_ARG_NONE, &batch_mode, N_("Run in batch mode"),
      NULL
    },
    /* Mode-specific options */
    {
      "output", 'o', 0, G_OPTION_ARG_FILENAME, &output_default,
      N_("Write the default secret to PACKET"), N_("PACKET")
    },
    {
      "output-data-encryption-key", 0, 0, G_OPTION_ARG_FILENAME,
      &output_data_encryption_key, N_("Write data encryption key to PACKET"),
      N_("PACKET")
    },
    {
      "output-passphrase", 0, 0, G_OPTION_ARG_FILENAME, &output_passphrase,
      N_("Write passphrase to PACKET"), N_("PACKET")
    },
    {
      "create-random-passphrase", 0, 0, G_OPTION_ARG_FILENAME,
      &output_created_random_passphrase,
      N_("Create a random passphrase and write it to PACKET"), N_("PACKET")
    },
    {
      "unencrypted-yes-really", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_NONE,
      &output_format_cleartext, NULL, NULL
    },
    {
      "certificate", 'c', 0, G_OPTION_ARG_FILENAME, &output_certificate,
      N_("Encrypt for the certificate in CERT"), N_("CERT")
    },
    {
      "output-format", 0, 0, G_OPTION_ARG_FILENAME, &output_format_string,
      N_("Use FORMAT for all output packets"), N_("FORMAT")
    },
    {
      "unencrypted", 0, 0, G_OPTION_ARG_NONE, &dump_unencrypted,
      N_("Only include unencrypted information, if any, in --dump"), NULL
    },
    {
      "with-secrets", 0, 0, G_OPTION_ARG_NONE, &dump_with_secrets,
      N_("Include secrets in --dump output"), NULL
    },
    { NULL, 0, 0, G_OPTION_ARG_NONE, NULL, NULL, NULL }
  };

/* Parse options, modify ARGC and ARGV to contain only operands.
   May exit (). */
static void
parse_options (int *argc, char ***argv)
{
  GOptionContext *options;
  GError *error;
  char *s;

  error = NULL;
  options = g_option_context_new (_("OPERANDS"));
  g_option_context_set_summary
    (options, _("Manages encrypted volume keys and passphrases."));
  s = g_strdup_printf (_("Report bugs to %s"), PACKAGE_BUGREPORT);
  g_option_context_set_description (options, s);
  g_free (s);

  g_option_context_add_main_entries (options, option_descriptions,
				     PACKAGE_NAME);
  if (g_option_context_parse (options, argc, argv, &error) == FALSE)
    {
      fprintf (stderr, _("%s: %s\n"
			 "Run `%s --help' for more information.\n"),
	       g_get_prgname (), error->message, g_get_prgname ());
      g_option_context_free (options);
      exit (EXIT_FAILURE);
    }
  g_option_context_free (options);

  if (mode_version != 0)
    {
      puts (PACKAGE_NAME " " PACKAGE_VERSION);
      puts (_("Copyright (C) 2009 Red Hat, Inc. All rights reserved.\n"
	      "This software is distributed under the GPL v.2.\n"
	      "\n"
	      "This program is provided with NO WARRANTY, to the extent "
	      "permitted by law."));
      exit (EXIT_SUCCESS);
    }

  switch ((mode_save != 0) + (mode_restore != 0) + (mode_setup_volume != 0)
	  + (mode_reencrypt != 0) + (mode_dump != 0) + (mode_secrets != 0))
    {
    case 0:
      error_exit (_("Operation mode not specified"));

    case 1:
      break; /* OK */

    default:
      error_exit (_("Ambiguous operation mode"));
    }

  if (dump_with_secrets != 0 && mode_dump == 0)
    error_exit (_("`--%s' is only valid with `--%s'"), "with-secrets", "dump");
  if (dump_unencrypted != 0 && mode_dump == 0)
    error_exit (_("`--%s' is only valid with `--%s'"), "unencrypted", "dump");
  if (mode_save == 0 && mode_reencrypt == 0)
    {
      if (output_default != NULL || output_data_encryption_key != NULL
	  || output_passphrase != NULL || output_format_cleartext != 0
	  || output_certificate != NULL || output_format_string != NULL)
	error_exit (_("Output can be specified only with `--save' or "
		      "`--reencrypt'"));
    }
  else {
    if (output_default == NULL && output_data_encryption_key == NULL
	&& output_passphrase == NULL
	&& output_created_random_passphrase == NULL)
      error_exit (_("No output specified"));
    if (output_format_cleartext != 0 && output_certificate != NULL)
      error_exit (_("Ambiguous output format"));
    if (output_format_string != NULL)
      {
	gboolean format_ok;

	if (strcmp (output_format_string, "cleartext") == 0)
	  output_format = LIBVK_PACKET_FORMAT_CLEARTEXT;
	else if (strcmp (output_format_string, "asymmetric") == 0)
	  output_format = LIBVK_PACKET_FORMAT_ASYMMETRIC;
	else if (strcmp (output_format_string,
			 "asymmetric_wrap_secret_only") == 0)
	  output_format = LIBVK_PACKET_FORMAT_ASYMMETRIC_WRAP_SECRET_ONLY;
	else if (strcmp (output_format_string, "passphrase") == 0)
	  output_format = LIBVK_PACKET_FORMAT_PASSPHRASE;
	else
	  error_exit (_("Unknown packet format `%s'"), output_format_string);
	if (output_format_cleartext != 0)
	  format_ok = output_format == LIBVK_PACKET_FORMAT_CLEARTEXT;
	else if (output_certificate != NULL)
	  format_ok = (output_format == LIBVK_PACKET_FORMAT_ASYMMETRIC
		       || (output_format
			   == LIBVK_PACKET_FORMAT_ASYMMETRIC_WRAP_SECRET_ONLY));
	else
	  format_ok = output_format == LIBVK_PACKET_FORMAT_PASSPHRASE;
	if (!format_ok)
	  error_exit (_("Output format does not match other options"));
      }
    else
      {
	if (output_format_cleartext != 0)
	  output_format = LIBVK_PACKET_FORMAT_CLEARTEXT;
	else if (output_certificate != NULL)
	  output_format = LIBVK_PACKET_FORMAT_ASYMMETRIC_WRAP_SECRET_ONLY;
	else
	  output_format = LIBVK_PACKET_FORMAT_PASSPHRASE;
      }
  }
  if (output_created_random_passphrase != NULL && mode_save == 0)
    error_exit (_("`--%s' is only valid with `--%s'"),
		"create-random-passphrase", "save");
}

 /* User interface */

/* Read a NUL-terminated string from stdin.
   Return a string for g_free (), or NULL. */
static char *
read_batch_string (void)
{
  char *buf, *res;
  size_t buf_size;
  ssize_t len;

  buf = NULL;
  buf_size = 0;
  len = getdelim (&buf, &buf_size, '\0', stdin);
  if (len == -1 || len == 0 || buf[len - 1] != '\0')
    {
      free (buf);
      return NULL;
    }
  res = g_memdup (buf, len);
  free (buf);
  return res;
}

/* Read a password (from /dev/tty if possible).
   Return a password for g_free (), or NULL on error.
   Unlike getpass(), does not block SIGINT and other signals.  (We rely on the
   shell to re-enable ECHO on SIGINT.) */
static char *
get_password (const char *prompt)
{
  FILE *tty, *in_file, *out_file;
  char buf[LINE_MAX], *p;
  struct termios otermios;
  gboolean echo_disabled;

  tty = fopen ("/dev/tty", "r+");
  if (tty != NULL)
    {
      in_file = tty;
      out_file = tty;
    }
  else
    {
      in_file = stdin;
      out_file = stderr;
    }

  fputs (prompt, out_file);
  fflush (out_file);

  if (tcgetattr (fileno (in_file), &otermios) != 0)
    echo_disabled = FALSE;
  else
    {
      struct termios ntermios;

      ntermios = otermios;
      ntermios.c_lflag &= ~ECHO;
      echo_disabled = tcsetattr (fileno (in_file), TCSAFLUSH, &ntermios) == 0;
    }

  p = fgets(buf, sizeof(buf), in_file);

  if (echo_disabled)
    {
      (void)tcsetattr (fileno (in_file), TCSAFLUSH, &otermios);
      putc ('\n', out_file);
    }

  if (tty != NULL)
    fclose (tty);

  if (p == NULL)
    return NULL;

  p = strchr(buf, '\r');
  if (p != NULL)
    *p = '\0';
  p = strchr(buf, '\n');
  if (p != NULL)
    *p = '\0';

  return g_strdup (buf);
}

/* A PK11_SetPaswordFunc handler */
static char *
nss_password_fn (PK11SlotInfo *slot, PRBool retry, void *arg)
{
  char *s, *res;

  (void)arg;
  if (batch_mode == 0)
    {
      char *prompt;

      if (retry)
	fprintf (stderr, _("Error, try again.\n"));
      prompt = g_strdup_printf (_("Enter password for `%s': "),
				PK11_GetTokenName (slot));
      s = get_password (prompt);
      g_free (prompt);
    }
  else
    s = read_batch_string ();
  if (s == NULL)
    return NULL;
  res = PL_strdup (s);
  g_free (s);
  return res;
}

/* A "generic" struct libvk_ui callback. */
static char *
generic_ui_cb (void *id, const char *prompt, int echo)
{
  (void)id;
  if (batch_mode != 0)
    return read_batch_string ();
  else if (echo == 0)
    {
      char *s, *res;

      s = g_strdup_printf (_("%s: "), prompt);
      res = get_password (s);
      g_free (s);
      if (res != NULL && res[0] != '\0')
	return res;
      g_free (res);
      return NULL;
    }
  else
    {
      char *buf, *res;
      size_t buf_size;
      ssize_t len;

      fprintf (stderr, "%s: ", prompt);
      fflush (stderr);
      buf = NULL;
      buf_size = 0;
      len = getline (&buf, &buf_size, stdin);
      if (len == -1)
	{
	  free (buf);
	  return NULL;
	}
      if (len != 0 && buf[len - 1] == '\n')
	{
	  len--;
	  buf[len] = '\0';
	}
      if (len == 0)
	{
	  free (buf);
	  return NULL;
	}
      res = g_memdup (buf, len + 1);
      free (buf);
      return res;
    }
}

/* A "passphrase" struct libvk_ui callback. */
static char *
passphrase_ui_cb (void *data, const char *prompt, unsigned failed_attempts)
{
  char *s, *res;

  (void)data;
  if (batch_mode != 0)
    {
      if (failed_attempts != 0)
	return NULL;
      return read_batch_string ();
    }
  if (failed_attempts != 0)
    fprintf (stderr, _("Error, try again.\n"));
  s = g_strdup_printf (_("%s: "), prompt);
  res = get_password (s);
  g_free (s);
  if (res != NULL && res[0] != '\0')
    return res;
  g_free (res);
  return NULL;
}

/* Set up a struct libvk_ui * and return it. */
static struct libvk_ui *
create_ui (void)
{
  struct libvk_ui *ui;

  ui = libvk_ui_new ();
  libvk_ui_set_generic_cb (ui, generic_ui_cb, NULL, NULL);
  libvk_ui_set_passphrase_cb (ui, passphrase_ui_cb, NULL, NULL);
  return ui;
}

 /* Operation implementations */

/* Load a packet from FILENAME using UI.
   Return the packet if OK, NULL on error. */
static struct libvk_volume *
open_packet_file (const char *filename, struct libvk_ui *ui, GError **error)
{
  gchar *packet;
  gsize size;
  struct libvk_volume *pack;

  if (g_file_get_contents (filename, &packet, &size, error) == FALSE)
    {
      g_prefix_error (error, _("Error reading `%s': "), filename);
      return NULL;
    }
  pack = libvk_packet_open (packet, size, ui, error);
  g_free (packet);
  if (pack == NULL)
    {
      g_prefix_error (error, _("Error decoding `%s': "), filename);
      return NULL;
    }
  return pack;
}

/* A user interaction state for all packet output methods. */
struct packet_output_state
{
  CERTCertificate *cert;
  char *passphrase;
};

/* Init POS, without user interaction.
   Return 0 if OK, -1 on error. */
static int
pos_init (struct packet_output_state *pos, GError **error)
{
  pos->cert = NULL;
  pos->passphrase = NULL;
  if (output_format_cleartext != 0)
    {
      /* Nothing */
    }
  else if (output_certificate != NULL)
    {
      gchar *data;
      gsize size;

      if (g_file_get_contents (output_certificate, &data, &size, error)
	  == FALSE)
	{
	  g_prefix_error (error, _("Error reading `%s': "), output_certificate);
	  return -1;
	}
      pos->cert = CERT_DecodeCertFromPackage (data, size);
      g_free (data);
      if (pos->cert == NULL)
	{
	  error_from_pr (error);
	  g_prefix_error (error, _("Error decoding `%s': "),
			  output_certificate);
	  return -1;
	}
    }
  else
    {
      /* Will ask for passphrase in pos_interact */
    }
  return 0;
}

/* Interact with the user about POS.
   Return 0 if OK, -1 on error. */
static int
pos_interact (struct packet_output_state *pos, GError **error)
{
  if (output_format_cleartext != 0 || output_certificate != NULL)
    {
      /* Nothing - pos_init () is enough. */
    }
  else
    {
      char *passphrase;
      unsigned failed;

      /* Ask twice even in batch mode, because that's what we do when
	 libvolume_key calls passphrase_ui_cb () as well. */
      for (failed = 0; failed < 64; failed++)
	{
	  char *passphrase2;
	  int passphrase_ok;

	  passphrase = passphrase_ui_cb (NULL,
					 failed == 0
					 ? _("New packet passphrase")
					 : _("Passphrases do not match.  "
					     "New packet passphrase"), failed);
	  if (passphrase == NULL)
	    goto no_passphrase;
	  /* The repeated passphrase is always considered a first attempt -
	     otherwise passphrase_ui_cb would prepend "Error, try again". */
	  passphrase2 = passphrase_ui_cb (NULL,
					  _("Repeat new packet passphrase"), 0);
	  if (passphrase2 == NULL)
	    {
	      memset (passphrase, 0, strlen (passphrase));
	      g_free (passphrase);
	      goto no_passphrase;
	    }
	  passphrase_ok = strcmp (passphrase, passphrase2) == 0;
	  memset (passphrase2, 0, strlen (passphrase2));
	  g_free (passphrase2);
	  if (passphrase_ok)
	    goto got_passphrase;
	  memset (passphrase, 0, strlen (passphrase));
	  g_free (passphrase);
	}
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_FAILED,
		   _("Too many attempts to get a passphrase"));
      return -1;

    got_passphrase:
      pos->passphrase = passphrase;
    }
  return 0;

 no_passphrase:
  g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_UI_NO_RESPONSE,
	       _("Passphrase not provided"));
  return -1;
}

/* Free data in POS */
static void
pos_free (struct packet_output_state *pos)
{
  if (pos->cert != NULL)
    CERT_DestroyCertificate (pos->cert);
  g_free (pos->passphrase);
}

/* Write a packet with SECRET_TYPE of VOL to FILENAME using UI.
   Return 0 if OK, -1 on error. */
static int
write_packet (struct packet_output_state *pos, const char *filename,
	      const struct libvk_volume *vol, enum libvk_secret secret_type,
	      const struct libvk_ui *ui, GError **error)
{
  void *packet;
  size_t size;

  if (output_format_cleartext != 0)
    packet = libvk_volume_create_packet_cleartext (vol, &size, secret_type,
						   error);
  else if (output_certificate != NULL)
    packet = libvk_volume_create_packet_asymmetric_with_format
      (vol, &size, secret_type, pos->cert, ui, output_format, error);
  else
    packet = libvk_volume_create_packet_with_passphrase (vol, &size,
							 secret_type,
							 pos->passphrase,
							 error);
  if (packet == NULL
      || g_file_set_contents (filename, packet, size, error) == FALSE)
    {
      g_prefix_error (error, _("Error creating `%s': "), filename);
      return -1;
    }
  if (output_format_cleartext != 0)
    memset (packet, 0, size);
  g_free (packet);
  return 0;
}

/* Write packet of VOL to destinations specified by --output-* using UI.
   Return 0 if OK, -1 on error. */
static int
output_packet (struct packet_output_state *pos, const struct libvk_volume *vol,
	       const struct libvk_ui *ui, GError **error)
{
  if (output_default != NULL
      && write_packet (pos, output_default, vol, LIBVK_SECRET_DEFAULT, ui,
		       error) != 0)
    return -1;
  if (output_data_encryption_key != NULL
      && write_packet (pos, output_data_encryption_key, vol,
		       LIBVK_SECRET_DATA_ENCRYPTION_KEY, ui, error) != 0)
    return -1;
  if (output_passphrase != NULL
      && write_packet (pos, output_passphrase, vol, LIBVK_SECRET_PASSPHRASE, ui,
		       error) != 0)
    return -1;
  return 0;
}

/* Genereate a random passphrase and return it (for g_free ()) */
static char *
generate_random_passphrase (void)
{
  /* Keep the character set size a power of two to make sure all characters are
     equally likely. */
  static const char charset[64] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz./";

  /* 20 chars * 6 bits per char = 120 "bits of security */
  unsigned char rnd[20];
  char *passphrase;
  size_t src, dest;

  if (PK11_GenerateRandom (rnd, sizeof (rnd)) != SECSuccess)
    {
      GError *error;

      error = NULL;
      error_from_pr (&error);
      error_exit (_("Error generating passphrase: %s"), error->message);
    }
  /* '-' characters: We only add '-' before another character, so there are
     (sizeof (rnd) - 1) possible places, and we add a '-' after each group of 5
     regular characters. */
  { /* To make sure (sizeof (rnd) - 1) does not overflow. */
    G_STATIC_ASSERT (sizeof (rnd) >= 1);
  }
  passphrase = g_malloc (sizeof (rnd) + (sizeof (rnd) - 1) / 5 + 1);
  dest = 0;
  for (src = 0; src < sizeof (rnd); src++)
    {
      if (src != 0 && src % 5 == 0)
	{
	  passphrase[dest] = '-';
	  dest++;
	}
      passphrase[dest] = charset[rnd[src] % sizeof (charset)];
      dest++;
    }
  passphrase[dest] = '\0';
  return passphrase;
}

/* Implement --save */
static void
do_save (int argc, char *argv[])
{
  GError *error;
  struct libvk_volume *v;
  struct libvk_ui *ui;
  struct packet_output_state pos;

  if (argc < 2 || argc > 3)
    error_exit (_("Usage: %s --save VOLUME [PACKET]"), g_get_prgname ());

  error = NULL;
  if (pos_init (&pos, &error) != 0)
    error_exit ("%s", error->message);

  v = libvk_volume_open (argv[1], &error);
  if (v == NULL)
    error_exit (_("Error opening `%s': %s"), argv[1], error->message);

  ui = create_ui ();
  if (argc == 3)
    {
      struct libvk_volume *pack;

      pack = open_packet_file (argv[2], ui, &error);
      if (pack == NULL)
	error_exit ("%s", error->message);
      if (libvk_volume_load_packet (v, pack, &error) != 0)
	error_exit (_("Error loading `%s': %s"), argv[2], error->message);
      libvk_volume_free (pack);
    }
  else if (libvk_volume_get_secret (v, LIBVK_SECRET_DEFAULT, ui, &error) != 0)
    error_exit (_("Error opening `%s': %s"), argv[1], error->message);

  if (pos_interact (&pos, &error) != 0
      || output_packet (&pos, v, ui, &error) != 0)
    error_exit ("%s", error->message);
  if (output_created_random_passphrase != NULL)
    {
      char *passphrase;
      size_t passphrase_len;

      passphrase = generate_random_passphrase ();
      passphrase_len = strlen (passphrase);
      if (libvk_volume_add_secret (v, LIBVK_SECRET_PASSPHRASE, passphrase,
				   passphrase_len, &error) != 0)
	error_exit (_("Error creating a passphrase: %s"), error->message);
      memset (passphrase, 0, passphrase_len);
      g_free (passphrase);
      if (write_packet (&pos, output_created_random_passphrase, v,
			LIBVK_SECRET_PASSPHRASE, ui, &error) != 0)
	error_exit ("%s", error->message);
    }
  pos_free (&pos);
  libvk_ui_free (ui);
  libvk_volume_free (v);
}

/* Return TRUE if PACKET (from PACKET_FILENAME) matches VOL (from VOL_FILENAME),
   FALSE if not or if the user has aborted the operation.
   Set ERROR unless the user has aborted the operation. */
static gboolean
packet_matches_volume (const struct libvk_volume *packet,
		       const struct libvk_volume *vol,
		       const char *packet_filename, const char *vol_filename,
		       GError **error)
{
  GPtrArray *warnings;
  gboolean res;

  warnings = g_ptr_array_new ();
  switch (libvk_packet_match_volume (packet, vol, warnings, error))
    {
    case LIBVK_PACKET_MATCH_OK:
      res = TRUE;
      break;

    case LIBVK_PACKET_MATCH_ERROR:
      g_prefix_error (error, _("`%s' does not match `%s': "), packet_filename,
		      vol_filename);
      res = FALSE;
      break;

    case LIBVK_PACKET_MATCH_UNSURE:
      {
	size_t i;

	fprintf (stderr, _("`%s' perhaps does not match `%s'\n"),
		 packet_filename, vol_filename);
	for (i = 0; i < warnings->len; i++)
	  {
	    char *s;

	    s = g_ptr_array_index (warnings, i);
	    fprintf (stderr, "  %s\n", s);
	    g_free (s);
	  }
	if (batch_mode != 0)
	  {
	    res = FALSE;
	    break;
	  }
	switch (yes_or_no (_("Are you sure you want to use this packet?")))
	  {
	  case 1:
	    res = TRUE;
	    break;

	  case 0:
	    res = FALSE;
	    break;

	  case -1:
	    g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_FAILED,
			 _("Error getting a yes/no answer"));
	    res = FALSE;
	    break;

	  default:
	    g_return_val_if_reached (0);
	  }
	break;
      }

    default:
      g_return_val_if_reached (0);
    }
  g_ptr_array_free (warnings, TRUE);
  return res;
}

/* Implement --restore */
static void
do_restore (int argc, char *argv[])
{
  GError *error;
  struct libvk_ui *ui;
  struct libvk_volume *v, *pack;

  if (argc != 3)
    error_exit (_("Usage: %s --%s VOLUME PACKET"), g_get_prgname (), "restore");

  error = NULL;
  v = libvk_volume_open (argv[1], &error);
  if (v == NULL)
    error_exit (_("Error opening `%s': %s"), argv[1], error->message);

  error = NULL;
  ui = create_ui ();
  pack = open_packet_file (argv[2], ui, &error);
  if (pack == NULL)
    error_exit ("%s", error->message);
  if (packet_matches_volume (pack, v, argv[2], argv[1], &error) == FALSE)
    {
      if (error != NULL)
	error_exit ("%s", error->message);
      exit (EXIT_FAILURE);
    }

  if (libvk_volume_apply_packet (v, pack, LIBVK_SECRET_DEFAULT, ui, &error)
      != 0)
    error_exit (_("Error restoring access to `%s': %s"), argv[1],
		error->message);
  libvk_volume_free (pack);
  libvk_ui_free (ui);
  libvk_volume_free (v);
}

/* Implement --setup-volume */
static void
do_setup_volume (int argc, char *argv[])
{
  GError *error;
  struct libvk_ui *ui;
  struct libvk_volume *v, *pack;

  if (argc != 4)
    error_exit (_("Usage: %s --%s VOLUME PACKET NAME"), g_get_prgname (),
		"setup-volume");

  error = NULL;
  v = libvk_volume_open (argv[1], &error);
  if (v == NULL)
    error_exit (_("Error opening `%s': %s"), argv[1], error->message);

  error = NULL;
  ui = create_ui ();
  pack = open_packet_file (argv[2], ui, &error);
  libvk_ui_free (ui);
  if (pack == NULL)
    error_exit ("%s", error->message);
  if (packet_matches_volume (pack, v, argv[2], argv[1], &error) == FALSE)
    {
      if (error != NULL)
	error_exit ("%s", error->message);
      exit (EXIT_FAILURE);
    }

  if (libvk_volume_open_with_packet (v, pack, argv[3], &error) != 0)
    error_exit (_("Error setting up `%s': %s"), argv[3], error->message);
  libvk_volume_free (v);
  libvk_volume_free (pack);
}

/* Implement --reencrypt */
static void
do_reencrypt (int argc, char *argv[])
{
  GError *error;
  struct libvk_ui *ui;
  struct libvk_volume *pack;
  struct packet_output_state pos;

  if (argc != 2)
    error_exit (_("Usage: %s --%s PACKET"), g_get_prgname (), "reencrypt");

  error = NULL;
  if (pos_init (&pos, &error) != 0)
    error_exit ("%s", error->message);

  ui = create_ui ();
  pack = open_packet_file (argv[1], ui, &error);
  if (pack == NULL)
    error_exit ("%s", error->message);

  if (pos_interact (&pos, &error) != 0
      || output_packet (&pos, pack, ui, &error) != 0)
    error_exit ("%s", error->message);
  pos_free (&pos);
  libvk_volume_free (pack);
  libvk_ui_free (ui);
}

/* Implement --dump and --secrets */
static void
do_dump (int argc, char *argv[])
{
  GError *error;
  gchar *packet;
  gsize size;
  const char *format;
  struct libvk_volume *pack;
  GSList *list;

  if (argc != 2)
    error_exit (_("Usage: %s --%s PACKET"), g_get_prgname (),
		mode_dump != 0 ? "dump" : "secrets");

  error = NULL;
  if (g_file_get_contents (argv[1], &packet, &size, &error) == FALSE)
    error_exit (_("Error reading `%s': %s"), argv[1], error->message);

  switch (libvk_packet_get_format (packet, size, &error))
    {
    case LIBVK_PACKET_FORMAT_UNKNOWN:
      error_exit (_("Invalid packet: %s"), error->message);

    case LIBVK_PACKET_FORMAT_CLEARTEXT:
      format = _("Unencrypted");
      break;

    case LIBVK_PACKET_FORMAT_ASYMMETRIC:
      format = _("Public key-encrypted");
      break;

    case LIBVK_PACKET_FORMAT_PASSPHRASE:
      format = _("Passphrase-encrypted");
      break;

    case LIBVK_PACKET_FORMAT_ASYMMETRIC_WRAP_SECRET_ONLY:
      format = _("Only secrets public key-encrypted");
      break;

    case LIBVK_PACKET_FORMAT_SYMMETRIC_WRAP_SECRET_ONLY:
      format = _("Only secrets symmetric key-encrypted");
      break;

    default:
      g_return_if_reached ();
    }
  if (mode_dump != 0)
    printf (_("%s:\t%s\n"), _("Packet format"), format);

  if (dump_unencrypted != 0)
    pack = libvk_packet_open_unencrypted (packet, size, &error);
  else
    {
      struct libvk_ui *ui;

      ui = create_ui ();
      pack = libvk_packet_open (packet, size, ui, &error);
      libvk_ui_free (ui);
    }
  g_free (packet);
  if (pack == NULL)
    error_exit (_("Error decoding `%s': %s"), argv[1], error->message);

  list = libvk_volume_dump_properties (pack, mode_secrets != 0
				       || dump_with_secrets != 0);
  while (list != NULL)
    {
      GSList *next;
      struct libvk_volume_property *prop;
      char *label, *value;

      prop = list->data;
      if (mode_secrets == 0 || libvk_vp_get_type (prop) == LIBVK_VP_SECRET)
	{
	  label = libvk_vp_get_label (prop);
	  value = libvk_vp_get_value (prop);
	  printf (_("%s:\t%s\n"), label, value);
	  g_free (label);
	  memset (value, 0, strlen (value));
	  g_free (value);
	}
      libvk_vp_free (prop);
      next = list->next;
      g_slist_free_1 (list);
      list = next;
    }

  libvk_volume_free (pack);
}

 /* Top level */

int
main (int argc, char *argv[])
{
  GError *error;
  SECStatus status;

  setlocale (LC_ALL, "");
  textdomain (PACKAGE_NAME);
  bindtextdomain (PACKAGE_NAME, LOCALEDIR);

  parse_options (&argc, &argv); /* May exit () */

  error = NULL;
  PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 0);
  PK11_SetPasswordFunc (nss_password_fn);
  if (nss_dir != NULL)
    status = NSS_Init (nss_dir);
  else
    status = NSS_NoDB_Init (NULL);
  if (status != SECSuccess)
    {
      error_from_pr (&error);
      error_exit ("Error initializing NSS: %s", error->message);
    }
  libvk_init ();

  if (mode_save != 0)
    do_save (argc, argv);
  else if (mode_restore != 0)
    do_restore (argc, argv);
  else if (mode_setup_volume != 0)
    do_setup_volume (argc, argv);
  else if (mode_reencrypt != 0)
    do_reencrypt (argc, argv);
  else if (mode_dump != 0 || mode_secrets != 0)
    do_dump (argc, argv);
  else
    g_return_val_if_reached (EXIT_FAILURE);

  NSS_Shutdown();

  return EXIT_SUCCESS;
}
