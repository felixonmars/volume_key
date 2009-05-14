/* A KMIP round-trip test.

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
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "../lib/kmip.h"
#include "../lib/libvolume_key.h"
#include "../lib/volume.h"

static int
test (const char *test_packet, enum libvk_secret secret_type)
{
  struct stat st;
  FILE *f;
  char *file_name;
  GError *error;
  struct libvk_volume *v;
  void *packet, *packet2;
  size_t size, size2;

  file_name = g_strconcat (getenv ("srcdir"), "/tests/", test_packet, NULL);
  if (stat (file_name, &st) != 0)
    {
      perror ("stat ()");
      return EXIT_FAILURE;
    }

  f = fopen (file_name, "rb");
  g_free (file_name);
  if (f == NULL)
    {
      perror ("fopen ()");
      return EXIT_FAILURE;
    }
  size = st.st_size;
  assert ((off_t)size == st.st_size);
  packet = g_malloc (st.st_size);
  if (fread (packet, 1, size, f) != size)
    {
      perror ("fread ()");
      return EXIT_FAILURE;
    }
  fclose (f);

  error = NULL;
  v = volume_load_escrow_packet (packet, size, &error);
  if (v == NULL)
    {
      fprintf (stderr, "Error loading escrow packet: %s\n", error->message);
      g_error_free (error);
      return EXIT_FAILURE;
    }
  packet2 = volume_create_escrow_packet (v, &size2, secret_type, &error);
  if (packet2 == NULL)
    {
      fprintf (stderr, "Error creating escrow packet: %s\n", error->message);
      g_error_free (error);
      return EXIT_FAILURE;
    }
  libvk_volume_free (v);

  if (size != size2)
    {
      fprintf (stderr, "Size mismatch: %zu vs. %zu\n", size, size2);
      return EXIT_FAILURE;
    }
  if (memcmp (packet, packet2, size) != 0)
    {
      fprintf (stderr, "Data difference:----------------------\n");
      kmip_dump (stderr, packet, size);
      fprintf (stderr, "--------------------------------------\n");
      kmip_dump (stderr, packet2, size2);
      return EXIT_FAILURE;
    }
  g_free (packet);
  g_free (packet2);
  return EXIT_SUCCESS;
}

int
main (void)
{
  int r;

  r = test ("kmip_roundtrip_luks_symmetric", LIBVK_SECRET_DEFAULT);
  if (r != EXIT_SUCCESS)
    return r;
  r = test ("kmip_roundtrip_luks_passphrase", LIBVK_SECRET_PASSPHRASE);
  if (r != EXIT_SUCCESS)
    return r;
  return EXIT_SUCCESS;
}
