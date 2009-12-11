/* Internal (library + application) error reporting utilities.

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

#ifndef NSS_ERROR_H__
#define NSS_ERROR_H__

#include <config.h>

#include <prerror.h>

/* Return a string describing ERROR, or NULL if unknown.
   This is an internal function that can be removed at any time! */
extern const char *libvk_nss_error_text__(PRErrorCode error);

#endif
