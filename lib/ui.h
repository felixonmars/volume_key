/* Internal user interface utilities.

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

#ifndef LIBVK_UI_H__
#define LIBVK_UI_H__

#include <config.h>

#include <glib.h>
#include <pk11pub.h>

struct libvk_ui
{
  char *(*generic_cb) (void *data, const char *prompt, int echo);
  void *generic_data;
  void (*generic_free_data) (void *data);
  char *(*passphrase_cb) (void *data, const char *prompt,
			  unsigned failed_attempts);
  void *passphrase_data;
  void (*passphrase_free_data) (void *data);
  void *nss_pwfn_arg;
  void (*nss_pwfn_free_arg) (void *arg);
  PK11SymKey *(*sym_key_cb) (void *data, unsigned failed_attempts);
  void *sym_key_data;
  void (*sym_key_free_data) (void *data);
};

/* Get a passphrase using UI, using PROMPT; there were FAILED_ATTEMPTS before.
   Return a passphrase (for g_free ()), or NULL. */
G_GNUC_INTERNAL
extern char *ui_get_passphrase (const struct libvk_ui *ui, const char *prompt,
				unsigned failed_attempts, GError **error);

/* Get a symmetric key using UI; there were FAILED_ATTEMPTS before.
   Return a symmetric key (for PK11_FreeSymKey ()), or NULL. */
G_GNUC_INTERNAL
extern PK11SymKey *ui_get_sym_key (const struct libvk_ui *ui,
				   unsigned failed_attempts, GError **error);

#endif
