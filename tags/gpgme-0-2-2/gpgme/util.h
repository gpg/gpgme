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
#ifndef STR
  #define STR(v) #v
#endif
#define STR2(v) STR(v)


void _gpgme_debug (int level, const char *format, ...);
int  _gpgme_debug_level (void);
void _gpgme_debug_begin ( void **helper, int level, const char *text);
int  _gpgme_debug_enabled ( void **helper );
void _gpgme_debug_add (void **helper, const char *format, ...);
void _gpgme_debug_end (void **helper, const char *text);

#define DEBUG0(x)                     _gpgme_debug (1,  __FILE__ ":" \
     STR2 (__LINE__) ": " x )
#define DEBUG1(x,a)                   _gpgme_debug (1,  __FILE__ ":" \
     STR2 (__LINE__)": " x, (a) )
#define DEBUG2(x,a,b)                 _gpgme_debug (1,  __FILE__ ":" \
     STR2 (__LINE__) ": " x, (a), (b) )
#define DEBUG3(x,a,b,c)               _gpgme_debug (1,  __FILE__ ":" \
     STR2 (__LINE__) ": " x, (a), (b), (c) )
#define DEBUG4(x,a,b,c,d)             _gpgme_debug (1,  __FILE__ ":" \
     STR2 (__LINE__) ": " x, (a), (b), (c), (d) )
#define DEBUG5(x,a,b,c,d,e)           _gpgme_debug (1,  __FILE__ ":" \
     STR2 (__LINE__) ": " x, (a), (b), (c), (d), (e) )
#define DEBUG6(x,a,b,c,d,e,f)         _gpgme_debug (1,  __FILE__ ":" \
     STR2 (__LINE__) ": " x, (a), (b), (c), (d), (e), (f) )
#define DEBUG7(x,a,b,c,d,e,f,g)       _gpgme_debug (1,  __FILE__ ":" \
     STR2 (__LINE__) ": " x, (a), (b), (c), (d), (e), (f), (g) )
#define DEBUG8(x,a,b,c,d,e,f,g,h)      _gpgme_debug (1,  __FILE__ ":" \
     STR2 (__LINE__) ": " x, (a), (b), (c), (d), (e), (f), (g), (h) )
#define DEBUG9(x,a,b,c,d,e,f,g,h,i)    _gpgme_debug (1,  __FILE__ ":" \
     STR2 (__LINE__) ": " x, (a), (b), (c), (d), (e), (f), (g), (h), (i) )
#define DEBUG10(x,a,b,c,d,e,f,g,h,i,j) _gpgme_debug (1,  __FILE__ ":" \
     STR2 (__LINE__) ": " x, (a), (b), (c), (d), (e), (f), (g), (h), (i), (j) )

#define DEBUG_BEGIN(y,x)  _gpgme_debug_begin (&(y), 1,  __FILE__ ":" \
     STR2 (__LINE__) ": " x )
#define DEBUG_ENABLED(y)  _gpgme_debug_enabled(&(y))
#define DEBUG_ADD0(y,x)                 _gpgme_debug_add (&(y), (x), \
                       )
#define DEBUG_ADD1(y,x,a)               _gpgme_debug_add (&(y), (x), \
                      (a) )
#define DEBUG_ADD2(y,x,a,b)             _gpgme_debug_add (&(y), (x), \
                      (a), (b) )
#define DEBUG_ADD3(y,x,a,b,c)           _gpgme_debug_add (&(y), (x), \
                      (a), (b), (c) )
#define DEBUG_ADD4(y,x,a,b,c,d)         _gpgme_debug_add (&(y), (x), \
                      (a), (b), (c), (d) )
#define DEBUG_ADD5(y,x,a,b,c,d,e)       _gpgme_debug_add (&(y), (x), \
                      (a), (b), (c), (d), (e) )
#define DEBUG_END(y,x)  _gpgme_debug_end (&(y), (x) )



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



#endif /* UTIL_H */




