/* Internal encryption utilities.

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

#ifndef LIBVK_CRYPTO_H__
#define LIBVK_CRYPTO_H__

#include <config.h>

#include <stddef.h>

#include <cert.h>
#include <glib.h>

/* FIXME: to use this, the caller must initialize NSS. */

/* Encrypt DATA of SIZE for CERT_DATA of CERT_SIZE.
   Return encrypted data (for g_free()), setting RES_SIZE to the size of the
   result, on success, NULL otherwise.
   Use PWFN_ARG for PK11 password callback. */
G_GNUC_INTERNAL
extern void *encrypt_assymetric (size_t *res_size, const void *data,
				 size_t size, CERTCertificate *cert,
				 void *pwfn_arg, GError **error);

/* Decrypt DATA of SIZE, assuming the private key is stored in a NSS database.
   Return plaintext data (for g_free()), setting RES_SIZE to the size of the
   result, on success, NULL otherwise.
   Use PWFN_ARG for PK11 password callback. */
G_GNUC_INTERNAL
extern void *decrypt_assymetric (size_t *res_size, const void *data,
				 size_t size, void *pwfn_arg, GError **error);

/* Encrypt DATA of SIZE using PASSPHRASE.
   Return encrypted data (for g_free()), setting RES_SIZE to the size of the
   result, on success, NULL otherwise. */
G_GNUC_INTERNAL
extern void *encrypt_with_passphrase (size_t *res_size, const void *data,
				      size_t size, const char *passphrase,
				      GError **error);

/* Decrypt DATA of SIZE using PASSPHRASE.
   Return decrypted data (for g_free()), setting RES_SIZE to the size of the
   result, on success, NULL otherwise. */
G_GNUC_INTERNAL
extern void *decrypt_with_passphrase (size_t *res_size, const void *data,
				      size_t size, const char *passphrase,
				      GError **error);

#endif
