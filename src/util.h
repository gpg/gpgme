/* util.h
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003, 2004, 2005 g10 Code GmbH

   This file is part of GPGME.

   GPGME is free software; you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   GPGME is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#ifndef UTIL_H
#define UTIL_H

#ifdef HAVE_W32_SYSTEM
# ifdef HAVE_W32CE_SYSTEM
#  include "w32-ce.h"
# else
#  include "windows.h"
# endif
#endif

/* For pid_t.  */
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
/* We must see the symbol ttyname_r before a redefinition. */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include "gpgme.h"


#define DIM(v) (sizeof(v)/sizeof((v)[0]))


/*-- {posix,w32}-util.c --*/
const char *_gpgme_get_gpg_path (void);
const char *_gpgme_get_gpgsm_path (void);
const char *_gpgme_get_gpgconf_path (void);
const char *_gpgme_get_g13_path (void);
const char *_gpgme_get_uiserver_socket_path (void);

int _gpgme_get_conf_int (const char *key, int *value);
void _gpgme_allow_set_foreground_window (pid_t pid);

/*-- dirinfo.c --*/
const char *_gpgme_get_default_homedir (void);
const char *_gpgme_get_default_agent_socket (void);



/*-- replacement functions in <funcname>.c --*/
#ifdef HAVE_CONFIG_H

#ifndef HAVE_STPCPY
static _GPGME_INLINE char *
_gpgme_stpcpy (char *a, const char *b)
{
  while (*b)
    *a++ = *b++;
  *a = 0;
  return a;
}
#define stpcpy(a,b) _gpgme_stpcpy ((a), (b))
#endif /*!HAVE_STPCPY*/

#if !HAVE_VASPRINTF
#include <stdarg.h>
int vasprintf (char **result, const char *format, va_list args);
int asprintf (char **result, const char *format, ...);
#endif

#if REPLACE_TTYNAME_R
int _gpgme_ttyname_r (int fd, char *buf, size_t buflen);
#undef  ttyname_r
#define ttyname_r(a,b,c) _gpgme_ttyname_r ((a), (b), (c))
#endif

#endif /*HAVE_CONFIG_H*/


/*-- conversion.c --*/
/* Convert two hexadecimal digits from STR to the value they
   represent.  Returns -1 if one of the characters is not a
   hexadecimal digit.  */
int _gpgme_hextobyte (const char *str);

/* Decode the C formatted string SRC and store the result in the
   buffer *DESTP which is LEN bytes long.  If LEN is zero, then a
   large enough buffer is allocated with malloc and *DESTP is set to
   the result.  Currently, LEN is only used to specify if allocation
   is desired or not, the caller is expected to make sure that *DESTP
   is large enough if LEN is not zero.  */
gpgme_error_t _gpgme_decode_c_string (const char *src, char **destp,
				      size_t len);

/* Decode the percent escaped string SRC and store the result in the
   buffer *DESTP which is LEN bytes long.  If LEN is zero, then a
   large enough buffer is allocated with malloc and *DESTP is set to
   the result.  Currently, LEN is only used to specify if allocation
   is desired or not, the caller is expected to make sure that *DESTP
   is large enough if LEN is not zero.  If BINARY is 1, then '\0'
   characters are allowed in the output.  */
gpgme_error_t _gpgme_decode_percent_string (const char *src, char **destp,
					    size_t len, int binary);

gpgme_error_t _gpgme_encode_percent_string (const char *src, char **destp,
					    size_t len);


/* Parse the string TIMESTAMP into a time_t.  The string may either be
   seconds since Epoch or in the ISO 8601 format like
   "20390815T143012".  Returns 0 for an empty string or seconds since
   Epoch. Leading spaces are skipped. If ENDP is not NULL, it will
   point to the next non-parsed character in TIMESTRING. */
time_t _gpgme_parse_timestamp (const char *timestamp, char **endp);


gpgme_error_t _gpgme_map_gnupg_error (char *err);


/* Retrieve the environment variable NAME and return a copy of it in a
   malloc()'ed buffer in *VALUE.  If the environment variable is not
   set, return NULL in *VALUE.  */
gpgme_error_t _gpgme_getenv (const char *name, char **value);


/*-- status-table.c --*/
/* Convert a status string to a status code.  */
void _gpgme_status_init (void);
gpgme_status_code_t _gpgme_parse_status (const char *name);


#ifdef HAVE_W32_SYSTEM
int _gpgme_mkstemp (int *fd, char **name);
const char *_gpgme_get_w32spawn_path (void);
#endif /*HAVE_W32_SYSTEM*/
#ifdef HAVE_W32CE_SYSTEM
char *_gpgme_w32ce_get_debug_envvar (void);
#endif /*HAVE_W32CE_SYSTEM*/

/*--  Error codes not yet available in current gpg-error.h.   --*/
#ifndef GPG_ERR_UNFINISHED
#define GPG_ERR_UNFINISHED 199
#endif
#ifndef GPG_ERR_NOT_OPERATIONAL
#define GPG_ERR_NOT_OPERATIONAL 176
#endif
#ifndef GPG_ERR_MISSING_ISSUER_CERT
#define GPG_ERR_MISSING_ISSUER_CERT 185
#endif


#ifdef ENABLE_ASSUAN
#include <assuan.h>
/* System hooks for assuan integration.  */
extern struct assuan_system_hooks _gpgme_assuan_system_hooks;
extern struct assuan_malloc_hooks _gpgme_assuan_malloc_hooks;
int _gpgme_assuan_log_cb (assuan_context_t ctx, void *hook,
			  unsigned int cat, const char *msg);
#endif

#endif /* UTIL_H */
