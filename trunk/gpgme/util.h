/* util.h 
 *	Copyright (C) 2000 Werner Koch (dd9jn)
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


#endif /* UTIL_H */




