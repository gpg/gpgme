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


static void
add_otag ( GpgmeData d, const char *tag )
{
    _gpgme_data_append_string ( d, "    <" );
    _gpgme_data_append_string ( d, tag );
    _gpgme_data_append_string ( d, ">" );
}

static void
add_ctag ( GpgmeData d, const char *tag )
{
    _gpgme_data_append_string ( d, "</" );
    _gpgme_data_append_string ( d, tag );
    _gpgme_data_append_string ( d, ">\n" );
}

static void
add_tag_and_string ( GpgmeData d, const char *tag, const char *string )
{
    add_otag (d, tag);
    _gpgme_data_append_string_for_xml ( d, string );
    add_ctag (d, tag); 
}

static void
add_user_id_name ( GpgmeData d, const char *buf, size_t len )
{
    while ( len && (buf[len-1] == ' ' || buf[len-1] == '\t') ) 
        len--;
    if (len) {
        add_otag (d, "name" );
        _gpgme_data_append_for_xml ( d, buf, len );
        add_ctag (d, "name");
    }
}


static void
add_user_id ( GpgmeData d, const char *string )
{
    const char *s, *start=NULL;
    int in_name = 0;
    int in_email = 0;
    int in_comment = 0;

    for (s=string; *s; s++ ) {
        if ( in_email ) {
            if ( *s == '<' )
                in_email++; /* not legal but anyway */
            else if (*s== '>') {
                if ( !--in_email ) {
                    _gpgme_data_append_for_xml ( d, start, s-start );
                    add_ctag (d, "email");
                }
            }
        }
        else if ( in_comment ) {
            if ( *s == '(' )
                in_comment++;
            else if (*s== ')') {
                if ( !--in_comment ) {
                    _gpgme_data_append_for_xml ( d, start, s-start );
                    add_ctag (d, "comment");
                }
            }
        }
        else if ( *s == '<' ) {
            if ( in_name ) {
                add_user_id_name (d, start, s-start );
                in_name = 0;
            }
            in_email = 1;
            add_otag ( d, "email" );
            start = s+1;
        }
        else if ( *s == '(' ) {
            if ( in_name ) {
                add_user_id_name (d, start, s-start );
                in_name = 0;
            }
            in_comment = 1;
            add_otag ( d, "comment" );
            start = s+1;
        }
        else if ( !in_name && *s != ' ' && *s != '\t' ) {
            in_name = 1;
            start = s;
        }    
    }

    if ( in_name ) 
        add_user_id_name (d, start, s-start );
}

static void
add_tag_and_uint ( GpgmeData d, const char *tag, unsigned int val )
{
    char buf[30];
    sprintf (buf, "%u", val );
    add_tag_and_string ( d, tag, buf );
}

static void
add_tag_and_time ( GpgmeData d, const char *tag, time_t val )
{
    char buf[30];

    if (!val || val == (time_t)-1 )
        return;
    sprintf (buf, "%lu", (unsigned long)val );
    add_tag_and_string ( d, tag, buf );
}

char *
gpgme_key_get_as_xml ( GpgmeKey key )
{
    GpgmeData d;
    struct user_id_s *u;

    if ( !key )
        return NULL;
    
    if ( gpgme_data_new ( &d, NULL, 0, 0 ) )
        return NULL;
    
    _gpgme_data_append_string ( d, "<GnupgKeyblock>\n"
                                   "  <mainkey>\n" );
    add_tag_and_string (d, "keyid", key->keyid );   
    if (key)
        add_tag_and_string (d, "fpr", key->fingerprint );
    add_tag_and_uint (d, "algo", key->key_algo );
    add_tag_and_uint (d, "len", key->key_len );
    add_tag_and_time (d, "created", key->timestamp );
    /*add_tag_and_time (d, "expires", key->expires );*/
    _gpgme_data_append_string (d, "  </mainkey>\n");

    /* No the user IDs */
    for ( u = key->uids; u; u = u->next ) {
        _gpgme_data_append_string (d, "  <userid>\n");
        add_tag_and_string ( d, "raw", u->name );
        add_user_id ( d, u->name );
        _gpgme_data_append_string (d, "  </userid>\n");
    }
    _gpgme_data_append_string (d, "  <subkey>\n");
    _gpgme_data_append_string (d, "  </subkey>\n");
    
    _gpgme_data_append_string ( d, "</GnupgKeyblock>\n" );

    return _gpgme_data_release_and_return_string (d);
}



