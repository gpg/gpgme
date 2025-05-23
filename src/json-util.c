/* json-util.c - Helper funtions for the JSON based interface to gpgme
 * Copyright (C) 2018, 2025 g10 Code GmbH
 *
 * This file is part of GPGME.
 *
 * GPGME is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * GPGME is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <https://gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif

#include "json-common.h"


void
xoutofcore (const char *type)
{
  gpg_error_t err = gpg_error_from_syserror ();
  log_error ("%s failed: %s\n", type, gpg_strerror (err));
  exit (2);
}

/* Free a NULL terminated array */
void
xfree_array (char **array)
{
  if (array)
    {
      int idx;
      for (idx = 0; array[idx]; idx++)
        xfree (array[idx]);
      xfree (array);
    }
}


const char *
data_type_to_string (gpgme_data_type_t dt)
{
  const char *s = "[?]";

  switch (dt)
    {
    case GPGME_DATA_TYPE_INVALID      : s = "invalid"; break;
    case GPGME_DATA_TYPE_UNKNOWN      : s = "unknown"; break;
    case GPGME_DATA_TYPE_PGP_SIGNED   : s = "PGP-signed"; break;
    case GPGME_DATA_TYPE_PGP_SIGNATURE: s = "PGP-signature"; break;
    case GPGME_DATA_TYPE_PGP_ENCRYPTED: s = "PGP-encrypted"; break;
    case GPGME_DATA_TYPE_PGP_OTHER    : s = "PGP"; break;
    case GPGME_DATA_TYPE_PGP_KEY      : s = "PGP-key"; break;
    case GPGME_DATA_TYPE_CMS_SIGNED   : s = "CMS-signed"; break;
    case GPGME_DATA_TYPE_CMS_ENCRYPTED: s = "CMS-encrypted"; break;
    case GPGME_DATA_TYPE_CMS_OTHER    : s = "CMS"; break;
    case GPGME_DATA_TYPE_X509_CERT    : s = "X.509"; break;
    case GPGME_DATA_TYPE_PKCS12       : s = "PKCS12"; break;
    }
  return s;
}


/* Create a JSON error object.  If JSON is not NULL the error message
 * is appended to that object.  An existing "type" item will be replaced. */
static cjson_t
error_object_v (cjson_t json, const char *message, va_list arg_ptr,
                gpg_error_t err)
{
  cjson_t response, j_tmp;
  char *msg;

  msg = gpgrt_vbsprintf (message, arg_ptr);
  if (!msg)
    xoutofcore ("error_object");

  response = json? json : xjson_CreateObject ();

  if (!(j_tmp = cJSON_GetObjectItem (response, "type")))
    xjson_AddStringToObject (response, "type", "error");
  else /* Replace existing "type".  */
    {
      j_tmp = cJSON_CreateString ("error");
      if (!j_tmp)
        xoutofcore ("cJSON_CreateString");
      cJSON_ReplaceItemInObject (response, "type", j_tmp);
     }
  xjson_AddStringToObject (response, "msg", msg);
  xfree (msg);

  xjson_AddNumberToObject (response, "code", err);

  return response;
}


/* Call cJSON_Print but terminate in case of an error.  */
char *
xjson_Print (cjson_t object)
{
  char *buf;
  buf = cJSON_Print (object);
  if (!buf)
    xoutofcore ("cJSON_Print");
  return buf;
}

/* Call cJSON_CreateObject but terminate in case of an error.  */
cjson_t
xjson_CreateObject (void)
{
  cjson_t json = cJSON_CreateObject ();
  if (!json)
    xoutofcore ("cJSON_CreateObject");
  return json;
}

/* Call cJSON_CreateArray but terminate in case of an error.  */
cjson_t
xjson_CreateArray (void)
{
  cjson_t json = cJSON_CreateArray ();
  if (!json)
    xoutofcore ("cJSON_CreateArray");
  return json;
}


/* Wrapper around cJSON_AddStringToObject which returns an gpg-error
 * code instead of the NULL or the new object.  */
gpg_error_t
cjson_AddStringToObject (cjson_t object, const char *name, const char *string)
{
  if (!cJSON_AddStringToObject (object, name, string))
    return gpg_error_from_syserror ();
  return 0;
}


/* Same as cjson_AddStringToObject but prints an error message and
 * terminates the process.  */
void
xjson_AddStringToObject (cjson_t object, const char *name, const char *string)
{
  if (!cJSON_AddStringToObject (object, name, string))
    xoutofcore ("cJSON_AddStringToObject");
}


/* Same as xjson_AddStringToObject but ignores NULL strings */
void
xjson_AddStringToObject0 (cjson_t object, const char *name, const char *string)
{
  if (!string)
    return;
  xjson_AddStringToObject (object, name, string);
}

/* Wrapper around cJSON_AddBoolToObject which terminates the process
 * in case of an error.  */
void
xjson_AddBoolToObject (cjson_t object, const char *name, int abool)
{
  if (!cJSON_AddBoolToObject (object, name, abool))
    xoutofcore ("cJSON_AddStringToObject");
  return ;
}

/* Wrapper around cJSON_AddNumberToObject which terminates the process
 * in case of an error.  */
void
xjson_AddNumberToObject (cjson_t object, const char *name, double dbl)
{
  if (!cJSON_AddNumberToObject (object, name, dbl))
    xoutofcore ("cJSON_AddNumberToObject");
  return ;
}

/* Wrapper around cJSON_AddItemToObject which terminates the process
 * in case of an error.  */
void
xjson_AddItemToObject (cjson_t object, const char *name, cjson_t item)
{
  if (!cJSON_AddItemToObject (object, name, item))
    xoutofcore ("cJSON_AddItemToObject");
  return ;
}


cjson_t
error_object (cjson_t json, const char *message, ...)
{
  cjson_t response;
  va_list arg_ptr;

  va_start (arg_ptr, message);
  response = error_object_v (json, message, arg_ptr, 0);
  va_end (arg_ptr);
  return response;
}


cjson_t
gpg_error_object (cjson_t json, gpg_error_t err, const char *message, ...)
{
  cjson_t response;
  va_list arg_ptr;

  va_start (arg_ptr, message);
  response = error_object_v (json, message, arg_ptr, err);
  va_end (arg_ptr);
  return response;
}


char *
error_object_string (const char *message, ...)
{
  cjson_t response;
  va_list arg_ptr;
  char *msg;

  va_start (arg_ptr, message);
  response = error_object_v (NULL, message, arg_ptr, 0);
  va_end (arg_ptr);

  msg = xjson_Print (response);
  cJSON_Delete (response);
  return msg;
}
