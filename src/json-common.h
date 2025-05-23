/* json-common.h - Common defs for gpgme-json et al.
 * Copyright (C) 2025 g10 Code GmbH
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

#ifndef GPGME_JSON_COMMON_H
#define GNUPG_JSON_COMMON_H


#ifndef BUILD_COMMITID
# error config.h not yet included
#endif
#ifdef GPGME_VERSION_NUMBER
# error gpgme.h already included
#endif

#define GPGRT_ENABLE_ES_MACROS 1
#define GPGRT_ENABLE_LOG_MACROS 1
#define GPGRT_ENABLE_ARGPARSE_MACROS 1
#include "gpgme.h"
#include "cJSON.h"


/* Only use calloc. */
#define CALLOC_ONLY 1


/* An object to keep state for the gpgme-json tools.  For the classic
 * gpgme-json tool tehre is just one instance of it but for a server
 * there will be one per connection.  */
struct json_common_s
{
  /* True if interactive mode is active - this changes the way json
   * objects are formatted.  */
  int interactive;


  /* Pending data to be returned by a getmore command.  */
  struct
  {
    char  *buffer;   /* Malloced data or NULL if not used.  */
    size_t length;   /* Length of that data.  */
    size_t written;  /* # of already written bytes from BUFFER.  */
  } pending_data;

};
typedef struct json_common_s *ctrl_t;


#define xtrystrdup(a)  gpgrt_strdup ((a))
#define xcalloc(a,b) ({                         \
      void *_r = gpgrt_calloc ((a), (b));       \
      if (!_r)                                  \
        xoutofcore ("calloc");                  \
      _r; })
#define xstrdup(a) ({                           \
      char *_r = gpgrt_strdup ((a));            \
      if (!_r)                                  \
        xoutofcore ("strdup");                  \
      _r; })
#define xstrconcat(a, ...) ({                           \
      char *_r = gpgrt_strconcat ((a), __VA_ARGS__);    \
      if (!_r)                                          \
        xoutofcore ("strconcat");                       \
      _r; })
#define xfree(a) gpgrt_free ((a))


#if CALLOC_ONLY
#define xtrymalloc(a)  gpgrt_calloc (1, (a))
#define xmalloc(a) xcalloc(1, (a))
#else
#define xtrymalloc(a)  gpgrt_malloc ((a))
#define xmalloc(a) ({                           \
      void *_r = gpgrt_malloc ((a));            \
      if (!_r)                                  \
        xoutofcore ("malloc");                  \
      _r; })
#endif

#define spacep(p)   (*(p) == ' ' || *(p) == '\t')

#ifndef HAVE_STPCPY
static GPGRT_INLINE char *
_my_stpcpy (char *a, const char *b)
{
  while (*b)
    *a++ = *b++;
  *a = 0;
  return a;
}
#define stpcpy(a,b) _my_stpcpy ((a), (b))
#endif /*!HAVE_STPCPY*/


/*-- json-util.c --*/

void xoutofcore (const char *type) GPGRT_ATTR_NORETURN;
void xfree_array (char **array);

const char *data_type_to_string (gpgme_data_type_t dt);

char *xjson_Print (cjson_t object);
cjson_t xjson_CreateObject (void);
cjson_t xjson_CreateArray (void);
gpg_error_t cjson_AddStringToObject (cjson_t object, const char *name,
                                     const char *string);
void xjson_AddStringToObject (cjson_t object, const char *name,
                              const char *string);
void xjson_AddStringToObject0 (cjson_t object, const char *name,
                               const char *string);
void xjson_AddBoolToObject (cjson_t object, const char *name, int abool);
void xjson_AddNumberToObject (cjson_t object, const char *name, double dbl);
void xjson_AddItemToObject (cjson_t object, const char *name, cjson_t item);

cjson_t error_object (cjson_t json, const char *message, ...);
cjson_t gpg_error_object (cjson_t json, gpg_error_t err,
                          const char *message, ...);
char *error_object_string (const char *message, ...);


/*-- json-core.c --*/


char *json_core_process_request (ctrl_t ctrl, const char *request);



#endif /*GNUPG_JSON_COMMON_H*/
