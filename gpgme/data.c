/* data.c
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
#include "context.h"
#include "ops.h"

#define ALLOC_CHUNK 1024
#define my_isdigit(a)  ( (a) >='0' && (a) <= '9' )
#define my_isxdigit(a) ( my_isdigit((a))               \
                         || ((a) >= 'A' && (a) <= 'F') \
                         || ((a) >= 'f' && (a) <= 'f') )



/**
 * gpgme_data_new:
 * @r_dh:   Returns a new data object.
 * @buffer: If not NULL, used to initialize the data object.
 * @size: Size of the buffer
 * @copy: Flag wether a copy of the buffer should be used.
 * 
 * Create a new data object and optionally initialize with data
 * from the memory.  A @copy with value %TRUE creates a copy of the
 * memory, a value of %FALSE uses the original memory of @buffer and the
 * caller has to make sure that this buffer is valid until gpgme_release_data()
 * is called.
 * 
 * Return value: 
 **/
GpgmeError
gpgme_data_new ( GpgmeData *r_dh, const char *buffer, size_t size, int copy )
{
    GpgmeData dh;

    *r_dh = NULL;
    dh = xtrycalloc ( 1, sizeof *dh );
    if (!dh)
        return mk_error (Out_Of_Core);
    if ( buffer ) {
        dh->len  = size;
        if (copy) {
            dh->private_buffer = xtrymalloc ( size );
            if ( !dh->private_buffer ) {
                xfree (dh);
                return mk_error (Out_Of_Core);
            }
            dh->private_len = size;
            memcpy (dh->private_buffer, buffer, size );
            dh->data = dh->private_buffer;
            dh->writepos = size;
        }
        else {
            dh->data = buffer;
        }
        dh->type = GPGME_DATA_TYPE_MEM;
    }
    dh->mode = GPGME_DATA_MODE_INOUT; 
    *r_dh = dh;
    return 0;
}

/**
 * gpgme_data_release:
 * @dh: Data object 
 * 
 * Release the data object @dh.  @dh may be NULL in which case nothing
 * happens.
 **/
void
gpgme_data_release ( GpgmeData dh )
{
    if (dh) {
        xfree (dh->private_buffer); 
        xfree (dh);
    }
}

char *
_gpgme_data_release_and_return_string ( GpgmeData dh )
{
    char *val = NULL;

    if (dh) {
        if ( _gpgme_data_append ( dh, "", 0 ) ) /* append EOS */
            xfree (dh->private_buffer );
        else {
            val = dh->private_buffer;
            if ( !val && dh->data ) {
                val = xtrymalloc ( dh->len );
                if ( val )
                    memcpy ( val, dh->data, dh->len );
            }
        }
        xfree (dh);
    }
    return val;
}


GpgmeDataType
gpgme_data_get_type ( GpgmeData dh )
{
    if ( !dh || !dh->data )
        return GPGME_DATA_TYPE_NONE;
            
    return dh->type;
}

void 
_gpgme_data_set_mode ( GpgmeData dh, GpgmeDataMode mode )
{
    assert (dh);
    dh->mode = mode;
}


GpgmeDataMode
_gpgme_data_get_mode ( GpgmeData dh )
{
    assert (dh);
    return dh->mode;
}

GpgmeError
gpgme_data_rewind ( GpgmeData dh )
{
    if ( !dh )
        return mk_error (Invalid_Value);
    /* Fixme: We should check whether rewinding does make sense for the
     * data type */
    dh->readpos = 0;
    return 0;
}

GpgmeError
gpgme_data_read ( GpgmeData dh, char *buffer, size_t length, size_t *nread )
{
    size_t nbytes;

    if ( !dh )
        return mk_error (Invalid_Value);
    nbytes = dh->len - dh->readpos;
    if ( !nbytes ) {
        *nread = 0;
        return mk_error(EOF);
    }
    if (nbytes > length)
        nbytes = length;
    memcpy ( buffer, dh->data + dh->readpos, nbytes );
    *nread = nbytes;
    dh->readpos += nbytes;
    return 0;
} 

/* 
 * This function does make sense when we know that it contains no nil chars.
 */
char *
_gpgme_data_get_as_string ( GpgmeData dh )
{
    char *val = NULL;

    if (dh) {
        val = xtrymalloc ( dh->len+1 );
        if ( val ) {
            memcpy ( val, dh->data, dh->len );
            val[dh->len] = 0;
        }
    }
    return val;
}



GpgmeError
_gpgme_data_append ( GpgmeData dh, const char *buffer, size_t length )
{
    assert (dh);

    if ( dh->type == GPGME_DATA_TYPE_NONE ) {
        /* convert it to a mem data type */
        assert (!dh->private_buffer);
        dh->type = GPGME_DATA_TYPE_MEM;
        dh->private_len = length < ALLOC_CHUNK? ALLOC_CHUNK : length;
        dh->private_buffer = xtrymalloc ( dh->private_len );
        if (!dh->private_buffer) {
            dh->private_len = 0;
            return mk_error (Out_Of_Core);
        }
        dh->writepos = 0;
        dh->data = dh->private_buffer;
    }
    else if ( dh->type != GPGME_DATA_TYPE_MEM ) 
        return mk_error (Invalid_Type);
    
    if ( dh->mode != GPGME_DATA_MODE_INOUT 
         && dh->mode != GPGME_DATA_MODE_IN  )
        return mk_error (Invalid_Mode);

    if ( !dh->private_buffer ) {
        /* we have to copy it now */
        assert (dh->data);
        dh->private_len = dh->len+length;
        if (dh->private_len < ALLOC_CHUNK)
            dh->private_len = ALLOC_CHUNK;
        dh->private_buffer = xtrymalloc ( dh->private_len );
        if (!dh->private_buffer) {
            dh->private_len = 0;
            return mk_error (Out_Of_Core);
        }
        memcpy ( dh->private_buffer, dh->data, dh->len );
        dh->writepos = dh->len;
        dh->data = dh->private_buffer;
    }

    /* allocate more memory if needed */
    if ( dh->writepos + length > dh->private_len ) {
        char *p;
        size_t newlen = dh->private_len
                        + (dh->len < ALLOC_CHUNK? ALLOC_CHUNK : length);
        p = xtryrealloc ( dh->private_buffer, newlen );
        if ( !p ) 
            return mk_error (Out_Of_Core);
        dh->private_buffer = p;
        dh->private_len = newlen;
        dh->data = dh->private_buffer;
        assert ( !(dh->writepos + length > dh->private_len) );      
    }

    memcpy ( dh->private_buffer + dh->writepos, buffer, length );
    dh->writepos += length;
    dh->len += length;

    return 0;
}

GpgmeError
_gpgme_data_append_string ( GpgmeData dh, const char *s )
{
    return _gpgme_data_append ( dh, s, s? strlen(s):0 );
}


GpgmeError
_gpgme_data_append_for_xml ( GpgmeData dh,
                             const char *buffer, size_t len )
{
    const char *text, *s;
    size_t n;
    int rc = 0; 
       
    if ( !dh || !buffer )
        return mk_error (Invalid_Value);

    do {
        for (text=NULL, s=buffer, n=len; n && !text; s++, n-- ) {
            if ( *s == '<' ) 
                text = "&lt;";
            else if ( *s == '>' ) 
                text = "&gt;";  /* not sure whether this is really needed */
            else if ( *s == '&' ) 
                text = "&amp;";
            else if ( !*s )
                text = "&#00;";
        }
        if (text) {
            s--; n++;
        }
        if (s != buffer) 
            rc = _gpgme_data_append ( dh, buffer, s-buffer );
        if ( !rc && text) {
            rc = _gpgme_data_append_string ( dh, text );
            s++; n--;
        }
        buffer = s;
        len = n;
    } while ( !rc && len );
    return rc;
}


/*
 * Append a string to DATA and convert it so that the result will be 
 * valid XML. 
 */
GpgmeError
_gpgme_data_append_string_for_xml ( GpgmeData dh, const char *string )
{
    return _gpgme_data_append_for_xml ( dh, string, strlen (string) );
}


static int
hextobyte( const byte *s )
{
    int c;

    if( *s >= '0' && *s <= '9' )
	c = 16 * (*s - '0');
    else if( *s >= 'A' && *s <= 'F' )
	c = 16 * (10 + *s - 'A');
    else if( *s >= 'a' && *s <= 'f' )
	c = 16 * (10 + *s - 'a');
    else
	return -1;
    s++;
    if( *s >= '0' && *s <= '9' )
	c += *s - '0';
    else if( *s >= 'A' && *s <= 'F' )
	c += 10 + *s - 'A';
    else if( *s >= 'a' && *s <= 'f' )
	c += 10 + *s - 'a';
    else
	return -1;
    return c;
}




/* 
 * Append a string with percent style (%XX) escape characters as XML
 */
GpgmeError
_gpgme_data_append_percentstring_for_xml ( GpgmeData dh, const char *string )
{
    const byte *s;
    byte *buf, *d;
    int val;
    GpgmeError err;

    d = buf = xtrymalloc ( strlen (string) );
    for (s=string; *s; s++ ) {
        if ( *s == '%' && (val=hextobyte (s+1)) != -1 ) {
            *d++ = val;
            s += 2;
        }
        else
            *d++ = *s;
    }

    err = _gpgme_data_append_for_xml ( dh, buf, d - buf );
    xfree (buf);
    return err;
}







