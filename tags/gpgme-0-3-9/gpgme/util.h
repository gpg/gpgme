/* util.h 
 *	Copyright (C) 2000 Werner Koch (dd9jn)
 *      Copyright (C) 2001 g10 Code GmbH
 *
 * This file is part of GPGME.
 *
 * GPGME is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GPGME is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifndef UTIL_H
#define UTIL_H

#include "types.h"
#include "debug.h"

void *_gpgme_malloc (size_t n );
void *_gpgme_calloc (size_t n, size_t m );
void *_gpgme_realloc (void *p, size_t n);
char *_gpgme_strdup (const char *p);
void  _gpgme_free ( void *a );

#define xtrymalloc(a)    _gpgme_malloc((a))
#define xtrycalloc(a,b)  _gpgme_calloc((a),(b))
#define xtryrealloc(a,b) _gpgme_realloc((a),(b))
#define xtrystrdup(a)    _gpgme_strdup((a))
#define xfree(a)         _gpgme_free((a))


#define mk_error(a) ( GPGME_##a )

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




#endif /* UTIL_H */
