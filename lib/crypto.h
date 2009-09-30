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

/* Encrypt DATA of SIZE for CERT.
   Return encrypted data (for g_free()), setting RES_SIZE to the size of the
   result, on success, NULL otherwise.
   Use PWFN_ARG for PK11 password callback. */
G_GNUC_INTERNAL
extern void *encrypt_asymmetric (size_t *res_size, const void *data,
				 size_t size, CERTCertificate *cert,
				 void *pwfn_arg, GError **error);

/* Decrypt DATA of SIZE, assuming the private key is stored in a NSS database.
   Return plaintext data (for g_free ()), setting RES_SIZE to the size of the
   result, on success, NULL otherwise.
   Use PWFN_ARG for PK11 password callback. */
G_GNUC_INTERNAL
extern void *decrypt_asymmetric (size_t *res_size, const void *data,
				 size_t size, void *pwfn_arg, GError **error);

/* Wrap CLEAR_SECRET_DATA of CLEAR_SECRET_SIZE for CERT.
   Store result into WRAPPED_SECRET, WRAPPED_SECRET_SIZE, encoded issuer into
   ISSUER, ISSUER_SIZE, encoded serial number into SN, SN_SIZE (all data for
   g_free ()), used mechanism to MECHANISM, and return 0 on success, -1
   otherwise.
   Use PWFN_ARG for PK11 password callback. */
G_GNUC_INTERNAL
extern int wrap_asymmetric (void **wrapped_secret, size_t *wrapped_secret_size,
			    void **issuer, size_t *issuer_size, void **sn,
			    size_t *sn_size, CK_MECHANISM_TYPE *mechanism,
			    const void *clear_secret_data,
			    size_t clear_secret_size, CERTCertificate *cert,
			    void *pwfn_arg, GError **error);

/* Unwrap WRAPPED_SECRET_DATA of WRAPPED_SECRET_SIZE, assuming the private key
   for ISSUER with ISSUER_SIZE and SN with SN_SIZE is stored in a NSS database.
   Return plaintext secret (for (g_free ()), setting CLEAR_SECRET_SIZE to the
   size of the result, on success, NULL otherwise.
   Use PWFN_ARG for PK11 password callback. */
G_GNUC_INTERNAL
extern void *unwrap_asymmetric (size_t *clear_secret_size,
				const void *wrapped_secret_data,
				size_t wrapped_secret_size, const void *issuer,
				size_t issuer_size, const void *sn,
				size_t sn_size, void *pwfn_arg, GError **error);

/* Wrap CLEAR_SECRET_DATA of CLEAR_SECRET_SIZE for WRAPPING_KEY using MECHANISM.
   Store result into WRAPPED_SECRET, WRAPPED_SECRET_SIZE, IV, IV_SIZE (both data
   for g_free ()), and return 0 on success, -1 otherwise.
   Use PWFN_ARG for PK11 password callback. */
G_GNUC_INTERNAL
extern int wrap_symmetric (void **wrapped_secret, size_t *wrapped_secret_size,
			   void **iv, size_t *iv_size, PK11SymKey *wrapping_key,
			   CK_MECHANISM_TYPE mechanism,
			   const void *clear_secret, size_t clear_secret_size,
			   void *pwfn_arg, GError **error);

/* Unwrap WRAPPED_SECRET_DATA of WRAPPED_SECRET_SIZE with IV of IV_SIZE with
   WRAPPING_KEY using MECHANISM.
   Return plaintext secret (for (g_free ()), setting CLEAR_SECRET_SIZE to the
   size of the result, on success, NULL otherwise. */
G_GNUC_INTERNAL
extern void *unwrap_symmetric (size_t *clear_secret_size,
			       PK11SymKey *wrapping_key,
			       CK_MECHANISM_TYPE mechanism,
			       const void *wrapped_secret_data,
			       size_t wrapped_secret_size, const void *iv,
			       size_t iv_size, GError **error);

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
