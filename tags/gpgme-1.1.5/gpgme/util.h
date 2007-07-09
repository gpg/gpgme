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

#include "gpgme.h"


#define DIM(v) (sizeof(v)/sizeof((v)[0]))


/*-- {posix,w32}-util.c --*/
const char *_gpgme_get_gpg_path (void);
const char *_gpgme_get_gpgsm_path (void);
int _gpgme_get_conf_int (const char *key, int *value);


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

#ifndef HAVE_TTYNAME_R
int ttyname_r (int fd, char *buf, size_t buflen);
#endif
#endif


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

#endif /* UTIL_H */
