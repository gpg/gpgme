/* util.h 
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003 g10 Code GmbH

   This file is part of GPGME.
 
   GPGME is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
 
   GPGME is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with GPGME; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#ifndef UTIL_H
#define UTIL_H

#include "types.h"
#include "debug.h"

#define DIM(v) (sizeof(v)/sizeof((v)[0]))
#define DIMof(type,member)   DIM(((type *)0)->member)


#ifndef HAVE_STPCPY
char *stpcpy (char *a, const char *b);
#endif

#define return_if_fail(expr) do {                        \
    if (!(expr)) {                                       \
        fprintf (stderr, "%s:%d: assertion `%s' failed", \
                 __FILE__, __LINE__, #expr );            \
        return;	                                         \
    } } while (0)
#define return_null_if_fail(expr) do {                   \
    if (!(expr)) {                                       \
        fprintf (stderr, "%s:%d: assertion `%s' failed", \
                 __FILE__, __LINE__, #expr );            \
        return NULL;	                                 \
    } } while (0)
#define return_val_if_fail(expr,val) do {                \
    if (!(expr)) {                                       \
        fprintf (stderr, "%s:%d: assertion `%s' failed", \
                 __FILE__, __LINE__, #expr );            \
        return (val);	                                 \
    } } while (0)



/*-- {posix,w32}-util.c --*/
const char *_gpgme_get_gpg_path (void);
const char *_gpgme_get_gpgsm_path (void);

/*-- replacement functions in <funcname>.c --*/
#ifdef HAVE_CONFIG_H
#if !HAVE_VASPRINTF
#include <stdarg.h>
int vasprintf (char **result, const char *format, va_list args);
int asprintf (char **result, const char *format, ...);
#endif

#if !HAVE_FOPENCOOKIE
#include <fcntl.h> /* make sure that ssize_t and off_t are defined */
typedef struct
{
  ssize_t (*read)(void*,char*,size_t);
  ssize_t (*write)(void*,const char*,size_t);
  int (*seek)(void*,off_t*,int);
  int (*close)(void*);
} _IO_cookie_io_functions_t;
typedef _IO_cookie_io_functions_t cookie_io_functions_t;
FILE *fopencookie (void *cookie, const char *opentype,
                   cookie_io_functions_t funclist);
#endif /*!HAVE_FOPENCOOKIE*/
#endif /*HAVE_CONFIG_H*/


/*-- conversion.c --*/
/* Decode the C formatted string SRC and store the result in the
   buffer *DESTP which is LEN bytes long.  If LEN is zero, then a
   large enough buffer is allocated with malloc and *DESTP is set to
   the result.  Currently, LEN is only used to specify if allocation
   is desired or not, the caller is expected to make sure that *DESTP
   is large enough if LEN is not zero.  */
GpgmeError _gpgme_decode_c_string (const char *src, char **destp, int len);
int _gpgme_hextobyte (const byte *str);

#endif /* UTIL_H */
