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


static const char *
pkalgo_to_string ( int algo )
{
    switch (algo) {
      case 1: 
      case 2:
      case 3: return "RSA";
      case 16:
      case 20: return "ElG";
      case 17: return "DSA";
      default: return "Unknown";
    }
}




static GpgmeError
key_new ( GpgmeKey *r_key, int secret )
{
    GpgmeKey key;

    *r_key = NULL;
    key = xtrycalloc ( 1, sizeof *key );
    if (!key)
        return mk_error (Out_Of_Core);
    key->ref_count = 1;
    *r_key = key;
    if (secret)
        key->secret = 1;
    return 0;
}

GpgmeError
_gpgme_key_new ( GpgmeKey *r_key )
{
    return key_new ( r_key, 0 );
}

GpgmeError
_gpgme_key_new_secret ( GpgmeKey *r_key )
{
    return key_new ( r_key, 1 );
}

void
gpgme_key_ref ( GpgmeKey key )
{
    return_if_fail (key);
    key->ref_count++;
}


static struct subkey_s *
add_subkey (GpgmeKey key, int secret)
{
    struct subkey_s *k, *kk;

    k = xtrycalloc (1, sizeof *k);
    if (!k)
        return NULL;

    if( !(kk=key->keys.next) )
        key->keys.next = k;
    else {
        while ( kk->next )
            kk = kk->next;
        kk->next = k;
    }
    if (secret)
        k->secret = 1;
    return k;
}

struct subkey_s *
_gpgme_key_add_subkey (GpgmeKey key)
{
    return add_subkey (key, 0);
}

struct subkey_s *
_gpgme_key_add_secret_subkey (GpgmeKey key)
{
    return add_subkey (key, 1);
}

void
gpgme_key_release ( GpgmeKey key )
{
    struct user_id_s *u, *u2;
    struct subkey_s *k, *k2;

    if (!key)
        return;

    assert (key->ref_count);
    if ( --key->ref_count )
        return;

    xfree (key->keys.fingerprint);
    for (k = key->keys.next; k; k = k2 ) {
        k2 = k->next;
        xfree (k->fingerprint);
        xfree (k);
    }
    for (u = key->uids; u; u = u2 ) {
        u2 = u->next;
        xfree (u);
    }
    xfree (key);
}

void
gpgme_key_unref (GpgmeKey key)
{
    gpgme_key_release (key);
}


static char *
set_user_id_part ( char *tail, const char *buf, size_t len )
{
    while ( len && (buf[len-1] == ' ' || buf[len-1] == '\t') ) 
        len--;
    for ( ; len; len--)
        *tail++ = *buf++;
    *tail++ = 0;
    return tail;
}


static void
parse_user_id ( struct user_id_s *uid, char *tail )
{
    const char *s, *start=NULL;
    int in_name = 0;
    int in_email = 0;
    int in_comment = 0;

    for (s=uid->name; *s; s++ ) {
        if ( in_email ) {
            if ( *s == '<' )
                in_email++; /* not legal but anyway */
            else if (*s== '>') {
                if ( !--in_email ) {
                    if (!uid->email_part) {
                        uid->email_part = tail;
                        tail = set_user_id_part ( tail, start, s-start );
                    }
                }
            }
        }
        else if ( in_comment ) {
            if ( *s == '(' )
                in_comment++;
            else if (*s== ')') {
                if ( !--in_comment ) {
                    if (!uid->comment_part) {
                        uid->comment_part = tail;
                        tail = set_user_id_part ( tail, start, s-start );
                    }
                }
            }
        }
        else if ( *s == '<' ) {
            if ( in_name ) {
                if ( !uid->name_part ) {
                    uid->name_part = tail;
                    tail = set_user_id_part (tail, start, s-start );
                }
                in_name = 0;
            }
            in_email = 1;
            start = s+1;
        }
        else if ( *s == '(' ) {
            if ( in_name ) {
                if ( !uid->name_part ) {
                    uid->name_part = tail;
                    tail = set_user_id_part (tail, start, s-start );
                }
                in_name = 0;
            }
            in_comment = 1;
            start = s+1;
        }
        else if ( !in_name && *s != ' ' && *s != '\t' ) {
            in_name = 1;
            start = s;
        }    
    }

    if ( in_name ) {
        if ( !uid->name_part ) {
            uid->name_part = tail;
            tail = set_user_id_part (tail, start, s-start );
        }
    }

    /* let unused parts point to an EOS */ 
    tail--;
    if (!uid->name_part)
        uid->name_part = tail;
    if (!uid->email_part)
        uid->email_part = tail;
    if (!uid->comment_part)
        uid->comment_part = tail;

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
    /* we can malloc a buffer of the same length, because the
     * converted string will never be larger. Actually we allocate it
     * twice the size, so that we are able to store the parsed stuff
     * there too */
    uid = xtrymalloc ( sizeof *uid + 2*strlen (s)+3 );
    if ( !uid )
        return mk_error (Out_Of_Core);
    uid->revoked = 0;
    uid->invalid = 0;
    uid->validity = 0;
    uid->name_part = NULL;
    uid->email_part = NULL;
    uid->comment_part = NULL;
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
    *d++ = 0;
    parse_user_id ( uid, d );

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

static void
one_uid_as_xml (GpgmeData d, struct user_id_s *u)
{
    _gpgme_data_append_string (d, "  <userid>\n");
    if ( u->invalid )
        _gpgme_data_append_string ( d, "    <invalid/>\n");
    if ( u->revoked )
        _gpgme_data_append_string ( d, "    <revoked/>\n");
    add_tag_and_string ( d, "raw", u->name );
    if ( *u->name_part )
        add_tag_and_string ( d, "name", u->name_part );
    if ( *u->email_part )
        add_tag_and_string ( d, "email", u->email_part );
    if ( *u->comment_part )
        add_tag_and_string ( d, "comment", u->comment_part );
    _gpgme_data_append_string (d, "  </userid>\n");
}


char *
gpgme_key_get_as_xml ( GpgmeKey key )
{
    GpgmeData d;
    struct user_id_s *u;
    struct subkey_s *k;

    if ( !key )
        return NULL;
    
    if ( gpgme_data_new ( &d ) )
        return NULL;
    
    _gpgme_data_append_string ( d, "<GnupgKeyblock>\n"
                                   "  <mainkey>\n" );
    if ( key->keys.secret )
        _gpgme_data_append_string ( d, "    <secret/>\n");
    if ( key->keys.flags.invalid )
        _gpgme_data_append_string ( d, "    <invalid/>\n");
    if ( key->keys.flags.revoked )
        _gpgme_data_append_string ( d, "    <revoked/>\n");
    if ( key->keys.flags.expired )
        _gpgme_data_append_string ( d, "    <expired/>\n");
    if ( key->keys.flags.disabled )
        _gpgme_data_append_string ( d, "    <disabled/>\n");
    add_tag_and_string (d, "keyid", key->keys.keyid );   
    if (key->keys.fingerprint)
        add_tag_and_string (d, "fpr", key->keys.fingerprint );
    add_tag_and_uint (d, "algo", key->keys.key_algo );
    add_tag_and_uint (d, "len", key->keys.key_len );
    add_tag_and_time (d, "created", key->keys.timestamp );
    /*add_tag_and_time (d, "expires", key->expires );*/
    _gpgme_data_append_string (d, "  </mainkey>\n");

    /* Now the user IDs.  We are listing the last one firs becuase this is
     * the primary one. */
    for (u = key->uids; u && u->next; u = u->next )
        ;
    if (u) {
        one_uid_as_xml (d,u);
        for ( u = key->uids; u && u->next; u = u->next ) {
            one_uid_as_xml (d,u);
        }
    }

    /* and now the subkeys */
    for (k=key->keys.next; k; k = k->next ) {
        _gpgme_data_append_string (d, "  <subkey>\n");
        if ( k->secret )
            _gpgme_data_append_string ( d, "    <secret/>\n");
        if ( k->flags.invalid )
            _gpgme_data_append_string ( d, "    <invalid/>\n");
        if ( k->flags.revoked )
            _gpgme_data_append_string ( d, "    <revoked/>\n");
        if ( k->flags.expired )
            _gpgme_data_append_string ( d, "    <expired/>\n");
        if ( k->flags.disabled )
            _gpgme_data_append_string ( d, "    <disabled/>\n");
        add_tag_and_string (d, "keyid", k->keyid );   
        if (k->fingerprint)
            add_tag_and_string (d, "fpr", k->fingerprint );
        add_tag_and_uint (d, "algo", k->key_algo );
        add_tag_and_uint (d, "len", k->key_len );
        add_tag_and_time (d, "created", k->timestamp );
        _gpgme_data_append_string (d, "  </subkey>\n");
    }
    _gpgme_data_append_string ( d, "</GnupgKeyblock>\n" );

    return _gpgme_data_release_and_return_string (d);
}


static const char *
capabilities_to_string (struct subkey_s *k)
{
    static char *strings[8] = {
        "",
        "c",
        "s",
        "sc",
        "e",
        "ec",
        "es",
        "esc"
    };
    return strings[  (!!k->flags.can_encrypt << 2)
                   | (!!k->flags.can_sign    << 1)
                   | (!!k->flags.can_certify     ) ];
}

const char *
gpgme_key_get_string_attr ( GpgmeKey key, GpgmeAttr what,
                            const void *reserved, int idx )
{
    const char *val = NULL;
    struct subkey_s *k;
    struct user_id_s *u;

    if (!key)
        return NULL;
    if (reserved)
        return NULL;
    if (idx < 0)
        return NULL;

    switch (what) {
      case GPGME_ATTR_KEYID:
        for (k=&key->keys; k && idx; k=k->next, idx-- )
            ;
        if (k) 
            val = k->keyid;
        break;
      case GPGME_ATTR_FPR:
        for (k=&key->keys; k && idx; k=k->next, idx-- )
            ;
        if (k) 
            val = k->fingerprint;
        break;
      case GPGME_ATTR_ALGO:    
        for (k=&key->keys; k && idx; k=k->next, idx-- )
            ;
        if (k) 
            val = pkalgo_to_string (k->key_algo);
        break;
      case GPGME_ATTR_LEN:     
      case GPGME_ATTR_CREATED: 
      case GPGME_ATTR_EXPIRE:  
        break; /* use another get function */
      case GPGME_ATTR_OTRUST:  
        val = "[fixme]";
        break;
      case GPGME_ATTR_USERID:  
        for (u=key->uids; u && idx; u=u->next, idx-- )
            ;
        val = u? u->name : NULL;
        break;
      case GPGME_ATTR_NAME:   
        for (u=key->uids; u && idx; u=u->next, idx-- )
            ;
        val = u? u->name_part : NULL;
        break;
      case GPGME_ATTR_EMAIL:
        for (u=key->uids; u && idx; u=u->next, idx-- )
            ;
        val = u? u->email_part : NULL;
        break;
      case GPGME_ATTR_COMMENT:
        for (u=key->uids; u && idx; u=u->next, idx-- )
            ;
        val = u? u->comment_part : NULL;
        break;
      case GPGME_ATTR_VALIDITY:
        for (u=key->uids; u && idx; u=u->next, idx-- )
            ;
        if (u) {
            switch (u->validity) {
              case GPGME_VALIDITY_UNKNOWN:   val = "?"; break;
              case GPGME_VALIDITY_UNDEFINED: val = "q"; break;
              case GPGME_VALIDITY_NEVER:     val = "n"; break;
              case GPGME_VALIDITY_MARGINAL:  val = "m"; break;
              case GPGME_VALIDITY_FULL:      val = "f"; break;
              case GPGME_VALIDITY_ULTIMATE:  val = "u"; break;
            }
        }
        break;
      case GPGME_ATTR_LEVEL:  /* not used here */
      case GPGME_ATTR_TYPE:
      case GPGME_ATTR_KEY_REVOKED:
      case GPGME_ATTR_KEY_INVALID:
      case GPGME_ATTR_UID_REVOKED:
      case GPGME_ATTR_UID_INVALID:
      case GPGME_ATTR_CAN_ENCRYPT:
      case GPGME_ATTR_CAN_SIGN:
      case GPGME_ATTR_CAN_CERTIFY:
        break;
      case GPGME_ATTR_IS_SECRET:
        if (key->secret)
            val = "1";
        break;
      case GPGME_ATTR_KEY_CAPS:    
        for (k=&key->keys; k && idx; k=k->next, idx-- )
            ;
        if (k) 
            val = capabilities_to_string (k);
        break;
    }
    return val;
}


unsigned long
gpgme_key_get_ulong_attr ( GpgmeKey key, GpgmeAttr what,
                           const void *reserved, int idx )
{
    unsigned long val = 0;
    struct subkey_s *k;
    struct user_id_s *u;

    if (!key)
        return 0;
    if (reserved)
        return 0;
    if (idx < 0)
        return 0;

    switch (what) {
      case GPGME_ATTR_ALGO:    
        for (k=&key->keys; k && idx; k=k->next, idx-- )
            ;
        if (k) 
            val = (unsigned long)k->key_algo;
        break;
      case GPGME_ATTR_LEN:     
        for (k=&key->keys; k && idx; k=k->next, idx-- )
            ;
        if (k) 
            val = (unsigned long)k->key_len;
        break;
      case GPGME_ATTR_CREATED: 
        for (k=&key->keys; k && idx; k=k->next, idx-- )
            ;
        if (k) 
            val = k->timestamp < 0? 0L:(unsigned long)k->timestamp;
        break;
      case GPGME_ATTR_VALIDITY:
        for (u=key->uids; u && idx; u=u->next, idx-- )
            ;
        if (u)
            val = u->validity;
        break;
      case GPGME_ATTR_IS_SECRET:
        val = !!key->secret;
        break;
      case GPGME_ATTR_KEY_REVOKED:
        for (k=&key->keys; k && idx; k=k->next, idx-- )
            ;
        if (k) 
            val = k->flags.revoked;
        break;
      case GPGME_ATTR_KEY_INVALID:
        for (k=&key->keys; k && idx; k=k->next, idx-- )
            ;
        if (k) 
            val = k->flags.invalid;
        break;
      case GPGME_ATTR_UID_REVOKED:
        for (u=key->uids; u && idx; u=u->next, idx-- )
            ;
        if (u)
            val = u->revoked;
        break;
      case GPGME_ATTR_UID_INVALID:
        for (u=key->uids; u && idx; u=u->next, idx-- )
            ;
        if (u)
            val = u->invalid;
        break;
      case GPGME_ATTR_CAN_ENCRYPT:
        val = key->gloflags.can_encrypt;
        break;
      case GPGME_ATTR_CAN_SIGN:
        val = key->gloflags.can_sign;
        break;
      case GPGME_ATTR_CAN_CERTIFY:
        val = key->gloflags.can_encrypt;
        break;
      default:
        break;
    }
    return val;
}


