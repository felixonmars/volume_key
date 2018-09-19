/* volume_key Python bindings. -*- C -*-

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

%module volume_key

 /* Header, common helper functions. */

%runtime %{
#include <config.h>

#include <stdbool.h>

#include <glib/gi18n-lib.h>
#include <libintl.h>

#include "../../lib/libvolume_key.h"

#if PY_VERSION_HEX >= 0x03000000
#undef PyString_AsStringAndSize
#undef PyString_FromStringAndSize
static int
PyString_AsStringAndSize(PyObject *obj, char **buffer, Py_ssize_t *length)
{
  const char *b = PyUnicode_AsUTF8AndSize(obj, length);
  if (b == NULL)
    return -1;
  *buffer = b;
  return 0;
}
#define PyString_FromStringAndSize(u, len) PyUnicode_FromStringAndSize(u, len)
#endif

/* Drop a reference to a Python object. */
static void
python_free_data (void *data)
{
  PyObject *o;

  o = data;
  Py_DECREF (o);
}
%}

/* FIXME? Create a libvolume_key-specific Python exception type, and make the
   exception code available? */
%typemap(in, numinputs=0) GError **error (GError *err = NULL) "$1 = &err;";

%typemap(argout) GError **error %{
  if (err$argnum != NULL)
    {
      Py_XDECREF ($result);
      $result = NULL;
      SWIG_Error (SWIG_RuntimeError, err$argnum->message);
      g_error_free (err$argnum);
    }
%}

%init %{
  libvk_init ();
%}

 /* Basic interface from the header file, heavily edited. */

%include "cstring.i"
%include "constraints.i"
%include "exception.i"

#define G_BEGIN_DECLS
#define G_END_DECLS

%ignore libvk_init;
%ignore libvk_error_quark;
%ignore LIBVKError;

%rename(SECRET_DEFAULT) LIBVK_SECRET_DEFAULT;
%rename(SECRET_DATA_ENCRYPTION_KEY) LIBVK_SECRET_DATA_ENCRYPTION_KEY;
%rename(SECRET_PASSPHRASE) LIBVK_SECRET_PASSPHRASE;
%ignore LIBVK_SECRET_END__;

%rename(VP_IDENTIFICATION) LIBVK_VP_IDENTIFICATION;
%rename(VP_CONFIGURATION) LIBVK_VP_CONFIGURATION;
%rename(VP_SECRET) LIBVK_VP_SECRET;

%rename(VOLUME_FORMAT_LUKS) LIBVK_VOLUME_FORMAT_LUKS;

%rename(PACKET_FORMAT_UNKNOWN) LIBVK_PACKET_FORMAT_UNKNOWN;
%rename(PACKET_FORMAT_CLEARTEXT) LIBVK_PACKET_FORMAT_CLEARTEXT;
%rename(PACKET_FORMAT_ASYMMETRIC) LIBVK_PACKET_FORMAT_ASYMMETRIC;
%rename(PACKET_FORMAT_ASSYMETRIC) LIBVK_PACKET_FORMAT_ASSYMETRIC;
%rename(PACKET_FORMAT_PASSPHRASE) LIBVK_PACKET_FORMAT_PASSPHRASE;
%rename(PACKET_FORMAT_ASYMMETRIC_WRAP_SECRET_ONLY)
	LIBVK_PACKET_FORMAT_ASYMMETRIC_WRAP_SECRET_ONLY;
%rename(PACKET_FORMAT_SYMMETRIC_WRAP_SECRET_ONLY)
	LIBVK_PACKET_FORMAT_SYMMETRIC_WRAP_SECRET_ONLY;
%ignore LIBVK_PACKET_FORMAT_END__;

%rename(PACKET_MATCH_OK) LIBVK_PACKET_MATCH_OK;
%ignore LIBVK_PACKET_MATCH_ERROR;
%rename(PACKET_MATCH_UNSURE) LIBVK_PACKET_MATCH_UNSURE;

%ignore libvk_ui_new;
%ignore libvk_ui_free;
%ignore libvk_ui_set_generic_cb;
%ignore libvk_ui_set_passphrase_cb;
%ignore libvk_ui_set_nss_pwfn_arg;
/* Not available in Python at all, for now. */
%ignore libvk_ui_set_sym_key_cb;

%ignore libvk_vp_free;
%ignore libvk_vp_get_label;
%ignore libvk_vp_get_name;
%ignore libvk_vp_get_type;
%ignore libvk_vp_get_value;

%ignore libvk_volume_free;
%ignore libvk_volume_open;
%ignore libvk_volume_get_hostname;
%ignore libvk_volume_get_uuid;
%ignore libvk_volume_get_label;
%ignore libvk_volume_get_path;
%ignore libvk_volume_get_format;
%ignore libvk_volume_dump_properties;
%ignore libvk_volume_get_secret;
%ignore libvk_volume_add_secret;
%ignore libvk_volume_apply_packet;
%ignore libvk_volume_open_with_packet;
%ignore libvk_volume_load_packet;
%ignore libvk_volume_create_packet_cleartext;
%ignore libvk_volume_create_packet_assymetric;
%ignore libvk_volume_create_packet_asymmetric;
%ignore libvk_volume_create_packet_asymmetric_with_format;
%ignore libvk_volume_create_packet_with_passphrase;
/* Not available in Python at all, for now. */
%ignore libvk_volume_create_packet_wrap_secret_symmetric;

%ignore libvk_packet_get_format;
%ignore libvk_packet_open;
%ignore libvk_packet_open_unencrypted;
%ignore libvk_packet_match_volume;

%apply Pointer NONNULL { struct libvk_ui *, struct libvk_volume * };

%typemap(check) enum libvk_secret %{
   if ((unsigned)$1 >= LIBVK_SECRET_END__)
     SWIG_exception (SWIG_ValueError, "invalid secret type");
%}

%typemap(check) enum libvk_packet_format %{
   if ((unsigned)$1 >= LIBVK_PACKET_FORMAT_END__)
     SWIG_exception (SWIG_ValueError, "invalid packet format");
%}

%include "lib/libvolume_key.h"

 /* A more object-oriented struct libvk_ui interface */

%rename(UI) libvk_ui;
struct libvk_ui {};

%extend libvk_ui {
  libvk_ui () {
    return libvk_ui_new ();
  }
  ~libvk_ui () {
    libvk_ui_free ($self);
  }

  %typemap(in) PyObject * %{
    if (!PyCallable_Check ($input))
      SWIG_exception (SWIG_TypeError, "callback expected");
    $1 = $input;
  %}
  %typemap(out) PyObject * %{
    (void)$1;
    SWIG_exception (SWIG_AttributeError, "unreadable attribute");
  %}
  PyObject *generic_cb, *passphrase_cb;
  %typemap(in) PyObject *;
  %typemap(out) PyObject *;

  /* Python-NSS expects the pwfn_arg to be a tuple, and functions that take a
     pwfn_arg can be called from Python using one or more arguments.  Support
     only one argument for now, only wrap it in the requried tuple.
     FIXME? Support generic tuples? */
  %typemap(in) void *data "$1 = PyTuple_Pack (1, $input);";
  %typemap(in, numinputs=0) void (*free_data) (void *data)
     "$1 = python_free_data;";
  void set_nss_pwfn_arg (void *data, void (*free_data) (void *data));
  %typemap(in) void *data;
  %typemap(in) void (*free_data) (void *data);
};

%{
/* Call a "generic callback" implemented in Python */
static char *
python_generic_cb (void *data, const char *prompt, int echo)
{
  PyObject *fn, *res;
  char *str;

  /* On exception this callback returns NULL, leaving the "top-level" function
     wrapper to recognize the exception and return an error.  In the unlikely
     case the callback is called again after an error, just clear the error
     state and start anew. */
  PyErr_Clear ();
  fn = data;
  res = PyObject_CallFunction (fn, (char *)"sN", prompt,
			       PyBool_FromLong (echo));
  if (res == NULL)
    return NULL;
  if (res == Py_None)
    {
      Py_DECREF (res);
      return NULL;
    }
  str = PyString_AsString (res);
  if (str == NULL)
    {
      Py_DECREF (res);
      return NULL;
    }
  str = g_strdup (str);
  Py_DECREF (res);
  return str;
}

/* Call a "passphrase callback" implemented in Python */
static char *
python_passphrase_cb (void *data, const char *prompt, unsigned failed_attempts)
{
  PyObject *fn, *res;
  char *str;

  /* On exception this callback returns NULL, leaving the "top-level" function
     wrapper to recognize the exception and return an error.  In the unlikely
     case the callback is called again after an error, just clear the error
     state and start anew. */
  PyErr_Clear ();
  fn = data;
  res = PyObject_CallFunction (fn, (char *)"sI", prompt, failed_attempts);
  if (res == NULL)
    return NULL;
  if (res == Py_None)
    {
      Py_DECREF (res);
      return NULL;
    }
  str = PyString_AsString (res);
  if (str == NULL)
    {
      Py_DECREF (res);
      return NULL;
    }
  str = g_strdup (str);
  Py_DECREF (res);
  return str;
}

static PyObject *
libvk_ui_generic_cb_get (const struct libvk_ui *ui)
{
  (void)ui;
  return NULL;
}

static void
libvk_ui_generic_cb_set (struct libvk_ui *ui, PyObject *generic_cb)
{
  Py_INCREF (generic_cb);
  libvk_ui_set_generic_cb (ui, python_generic_cb, generic_cb, python_free_data);
}

static PyObject *
libvk_ui_passphrase_cb_get (const struct libvk_ui *ui)
{
  (void)ui;
  return NULL;
}

static void
libvk_ui_passphrase_cb_set (struct libvk_ui *ui, PyObject *passphrase_cb)
{
  Py_INCREF (passphrase_cb);
  libvk_ui_set_passphrase_cb (ui, python_passphrase_cb, passphrase_cb,
			      python_free_data);
}
%}

/* From now on, check for "silenced" exceptions from libvk_ui callbacks. */
%typemap(argout) struct libvk_ui * %{
  if (PyErr_Occurred()) {
    Py_XDECREF ($result);
    $result = NULL;
  }
%}

 /* A more object-oriented libvk_volume_property interface */

%nodefaultctor libvk_volume_property;
struct libvk_volume_property {};

%extend libvk_volume_property {
  ~libvk_volume_property () {
    libvk_vp_free ($self);
  }

  %typemap(newfree) char * "g_free ($1);";
  %immutable label;
  %newobject label;
  char *label;

  %immutable name;
  %newobject name;
  char *name;

  %immutable type;
  enum libvk_vp_type type;

  %immutable value;
  %newobject value;
  char *value;
  %typemap(newfree) char *;
}

%{
static char *
libvk_volume_property_label_get (const struct libvk_volume_property *prop)
{
  return libvk_vp_get_label(prop);
}

static char *
libvk_volume_property_name_get (const struct libvk_volume_property *prop)
{
  return libvk_vp_get_name(prop);
}

static enum libvk_vp_type
libvk_volume_property_type_get (const struct libvk_volume_property *prop)
{
  return libvk_vp_get_type (prop);
}

static char *
libvk_volume_property_value_get (const struct libvk_volume_property *prop)
{
  return libvk_vp_get_value(prop);
}
%}

 /* A more object-oriented libvk_volume interface */

%rename(Volume) libvk_volume;
%nodefaultctor libvk_volume;
struct libvk_volume {};

%runtime %{
static void *
libvk_volume_create_packet_asymmetric_from_cert_data
	(struct libvk_volume *vol, size_t *size, enum libvk_secret secret_type,
	 const void *cert_data, size_t cert_size, const struct libvk_ui *ui,
	 GError **error, enum libvk_packet_format format) {
  CERTCertificate *cert;
  void *res;

  cert = CERT_DecodeCertFromPackage ((char *)cert_data, cert_size);
  if (cert == NULL)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_FAILED,
		   _("Error decoding certificate"));
      return NULL;
    }
  res = libvk_volume_create_packet_asymmetric_with_format (vol, size,
							   secret_type, cert,
							   ui, format, error);
  CERT_DestroyCertificate (cert);
  return res;
}
%}

%extend libvk_volume {
  ~libvk_volume() {
    libvk_volume_free ($self);
  }

  %newobject open;
  %apply Pointer NONNULL { const char *path };
  static struct libvk_volume *open(const char *path, GError **error);
  %clear const char *path;

  %typemap(newfree) char * "g_free ($1);";
  %immutable hostname;
  %newobject hostname;
  char *hostname;

  %immutable uuid;
  %newobject uuid;
  char *uuid;

  %immutable label;
  %newobject label;
  char *label;

  %immutable path;
  %newobject path;
  char *path;

  %immutable format;
  %newobject format;
  char *format;
  %typemap(newfree) char *;

  %typemap(out) GSList * %{
    $result = PyList_New (0);
    while ($1 != NULL)
      {
	GSList *next;
	PyObject *p;

	p = SWIG_NewPointerObj($1->data, SWIGTYPE_p_libvk_volume_property,
			       SWIG_POINTER_OWN);
	PyList_Append ($result, p);
	next = $1->next;
	g_slist_free_1 ($1);
	$1 = next;
      }
  %}
  GSList *dump_properties (bool with_secrets);
  %typemap(out) GSList *;

  void get_secret (enum libvk_secret secret_type, const struct libvk_ui *ui,
		   GError **error);

  %typemap(in) (const void *secret, size_t size) {
    char *buf;
    Py_ssize_t len;

    if (PyString_AsStringAndSize ($input, &buf, &len) != 0)
      SWIG_exception (SWIG_TypeError, "(secret, size)");
    $1 = buf;
    $2 = len;
  }
  void add_secret (enum libvk_secret secret_type, const void *secret,
		   size_t size, GError **error);
  %typemap(in) (const void *secret, size_t size);

  void load_packet (const struct libvk_volume *packet, GError **error);

  void apply_packet (const struct libvk_volume *packet,
		     enum libvk_secret secret_type, const struct libvk_ui *ui,
		     GError **error);

  %apply Pointer NONNULL { const char *name };
  void open_with_packet (const struct libvk_volume *packet, const char *name,
			 GError **error);
  %clear const char *name;

  %typemap(in, numinputs=0) size_t *size (size_t sz = 0) "$1 = &sz;"
  %typemap(out) void * "";
  %typemap(argout) size_t *size
     "$result = PyString_FromStringAndSize (result, sz$argnum);";
  void *create_packet_cleartext (size_t *size, enum libvk_secret secret_type,
				 GError **error);

  // FIXME: this CERTCertificate can't be suppled using python-nss
  void *create_packet_assymetric (size_t *size, enum libvk_secret secret_type,
				  CERTCertificate *cert,
				  const struct libvk_ui *ui, GError **error);
  // FIXME: this CERTCertificate can't be suppled using python-nss
  void *create_packet_asymmetric (size_t *size, enum libvk_secret secret_type,
				  CERTCertificate *cert,
				  const struct libvk_ui *ui, GError **error);

  /* An ugly workaround for the above problem with interfacing to python-nss. */
  %typemap(in) (const void *cert_data, size_t cert_size) {
    char *buf;
    Py_ssize_t len;

    if (PyString_AsStringAndSize ($input, &buf, &len) != 0)
      SWIG_exception (SWIG_TypeError, "(cert_data, cert_size)");
    $1 = buf;
    $2 = len;
  }
  void *create_packet_assymetric_from_cert_data
    (size_t *size, enum libvk_secret secret_type, const void *cert_data,
     size_t cert_size, const struct libvk_ui *ui, GError **error,
     enum libvk_packet_format format
     = LIBVK_PACKET_FORMAT_ASYMMETRIC_WRAP_SECRET_ONLY) {
    return libvk_volume_create_packet_asymmetric_from_cert_data ($self, size,
								 secret_type,
								 cert_data,
								 cert_size, ui,
								 error, format);
  }
  void *create_packet_asymmetric_from_cert_data
    (size_t *size, enum libvk_secret secret_type, const void *cert_data,
     size_t cert_size, const struct libvk_ui *ui, GError **error,
     enum libvk_packet_format format
     = LIBVK_PACKET_FORMAT_ASYMMETRIC_WRAP_SECRET_ONLY);
  %typemap(in) (const void *cert_data, size_t cert_size);

  %apply Pointer NONNULL { const char *passphrase };
  void *create_packet_with_passphrase (size_t *size,
				       enum libvk_secret secret_type,
				       const char *passphrase, GError **error);
  %clear const char *passphrase;
  %typemap(in) size_t *size;
  %typemap(out) void *;
  %typemap(argout) size_t *size;

  %typemap(in, numinputs=0) GPtrArray *warnings
     "$1 = g_ptr_array_new ();";
  %typemap(argout) GPtrArray *warnings {
    PyObject *warnings;
    size_t i;

    warnings = PyList_New ($1->len);
    if (warnings == NULL)
      SWIG_fail;
    for (i = 0; i < $1->len; i++)
      PyList_SetItem (warnings, i,
		      PyString_FromString (g_ptr_array_index ($1, i)));
    %append_output (warnings);
  }
  %typemap(freearg) GPtrArray *warnings {
    size_t i;

    for (i = 0; i < $1->len; i++)
      g_free (g_ptr_array_index ($1, i));
    g_ptr_array_free ($1, TRUE);
  }
  enum libvk_packet_match_result packet_match_volume
    (const struct libvk_volume *vol, GPtrArray *warnings, GError **error) {
    return libvk_packet_match_volume ($self, vol, warnings, error);
  }
}

%{
static char *
libvk_volume_hostname_get (const struct libvk_volume *vol)
{
  return libvk_volume_get_hostname (vol);
}

static char *
libvk_volume_uuid_get (const struct libvk_volume *vol)
{
  return libvk_volume_get_uuid (vol);
}

static char *
libvk_volume_label_get (const struct libvk_volume *vol)
{
  return libvk_volume_get_label (vol);
}

static char *
libvk_volume_path_get (const struct libvk_volume *vol)
{
  return libvk_volume_get_path (vol);
}

static char *
libvk_volume_format_get (const struct libvk_volume *vol)
{
  return libvk_volume_get_format (vol);
}
%}

 /* A "Packet" class - doesn't correspond to anything in <libvolume_key.h> */

%rename(Packet) libvk_packet;
%nodefaultctor libvk_packet;
%nodefaultdtor libvk_packet;
struct libvk_packet {};

%extend libvk_packet {

  %typemap(in) (const void *packet, size_t size) {
    char *buf;
    Py_ssize_t len;

    if (PyString_AsStringAndSize ($input, &buf, &len) != 0)
      SWIG_exception (SWIG_TypeError, "(packet, size)");
    $1 = buf;
    $2 = len;
  }
  static enum libvk_packet_format get_format (const void *packet, size_t size,
					      GError **error);

  static struct libvk_volume *open (const void *packet, size_t size,
				    const struct libvk_ui *ui,
				    GError **error);

  static struct libvk_volume *open_unencrypted (const void *packet, size_t size,
						GError **error);
  %typemap(in) (const void *packet, size_t size);
}
