/* key.c - Key and keyList objects
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "util.h"
#include "ops.h"
#include "key.h"

#define ALLOC_CHUNK 1024
#define my_isdigit(a) ( (a) >='0' && (a) <= '9' )


GpgmeError
_gpgme_key_new( GpgmeKey *r_key )
{
    GpgmeKey key;

    *r_key = NULL;
    key = xtrycalloc ( 1, sizeof *key );
    if (!key)
        return mk_error (Out_Of_Core);

    *r_key = key;
    return 0;
}

void
_gpgme_key_release ( GpgmeKey key )
{
    struct user_id_s *u, *u2;

    if (!key)
        return;

    xfree (key->fingerprint);
    for ( u = key->uids; u; u = u2 ) {
        u2 = u->next;
        xfree (u);
    }
    xfree (key);
}

/* 
 * Take a name from the --with-colon listing, remove certain escape sequences
 * sequences and put it into the list of UIDs
 */
GpgmeError
_gpgme_key_append_name ( GpgmeKey key, const char *s )
{
    struct user_id_s *uid;
    char *d;

    assert (key);
    /* we can malloc a buffer of the same length, because the converted
     * string will never be larger */
    uid = xtrymalloc ( sizeof *uid + strlen (s) );
    if ( !uid )
        return mk_error (Out_Of_Core);
    uid->validity = 0;
    d = uid->name;

    while ( *s ) {
        if ( *s != '\\' )
            *d++ = *s++;
        else if ( s[1] == '\\' ) {
            s++;
            *d++ = *s++; 
        }
        else if ( s[1] == 'n' ) {
            s += 2;
            *d++ = '\n'; 
        }
        else if ( s[1] == 'r' ) {
            s += 2;
            *d++ = '\r'; 
        }
        else if ( s[1] == 'v' ) {
            s += 2;
            *d++ = '\v'; 
        }
        else if ( s[1] == 'b' ) {
            s += 2;
            *d++ = '\b'; 
        }
        else if ( s[1] == '0' ) {
            /* Hmmm: no way to express this */
            s += 2;
            *d++ = '\\';
            *d++ = '\0'; 
        }
        else if ( s[1] == 'x' && my_isdigit (s[2]) && my_isdigit (s[3]) ) {
            unsigned int val = (s[2]-'0')*16 + (s[3]-'0');
            if ( !val ) {
                *d++ = '\\';
                *d++ = '\0'; 
            }
            else 
                *(byte*)d++ = val;
            s += 3;
        }
        else { /* should not happen */
            s++;
            *d++ = '\\'; 
            *d++ = *s++;
        } 
    }

    uid->next = key->uids;
    key->uids = uid;
    return 0;
}



