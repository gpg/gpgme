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
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "syshdr.h"

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
 * @r_dh: returns the new data object 
 * 
 * Create a new data object without any content. 
 * 
 * Return value: An error value or 0 on success
 **/
GpgmeError
gpgme_data_new ( GpgmeData *r_dh )
{
    GpgmeData dh;

    if (!r_dh)
        return mk_error (Invalid_Value);
    *r_dh = NULL;
    dh = xtrycalloc ( 1, sizeof *dh );
    if (!dh)
        return mk_error (Out_Of_Core);
    dh->mode = GPGME_DATA_MODE_INOUT; 
    *r_dh = dh;
    return 0;
}


/**
 * gpgme_data_new_from_mem:
 * @r_dh:   Returns a new data object.
 * @buffer: Initialize with this.
 * @size: Size of the buffer
 * @copy: Flag wether a copy of the buffer should be used.
 * 
 * Create a new data object and initialize with data
 * from the memory.  A @copy with value %TRUE creates a copy of the
 * memory, a value of %FALSE uses the original memory of @buffer and the
 * caller has to make sure that this buffer is valid until gpgme_release_data()
 * is called.
 * 
 * Return value: 
 **/
GpgmeError
gpgme_data_new_from_mem ( GpgmeData *r_dh,
                          const char *buffer, size_t size, int copy )
{
    GpgmeData dh;
    GpgmeError err;

    if (!r_dh || !buffer)
        return mk_error (Invalid_Value);
    *r_dh = NULL;
    err = gpgme_data_new ( &dh );
    if (err)
        return err;
    dh->len = size;
    if (copy) {
        dh->private_buffer = xtrymalloc ( size );
        if ( !dh->private_buffer ) {
            gpgme_data_release (dh);
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
    
    *r_dh = dh;
    return 0;
}


GpgmeError
gpgme_data_new_with_read_cb ( GpgmeData *r_dh,
                              int (*read_cb)(void*,char *,size_t,size_t*),
                              void *read_cb_value )
{
    GpgmeData dh;
    GpgmeError err;

    if (!r_dh || !read_cb)
        return mk_error (Invalid_Value);
    *r_dh = NULL;
    err = gpgme_data_new ( &dh );
    if (err)
        return err;
    dh->type = GPGME_DATA_TYPE_CB;
    dh->mode = GPGME_DATA_MODE_OUT;
    dh->read_cb = read_cb;
    dh->read_cb_value = read_cb_value;
    
    *r_dh = dh;
    return 0;
}

/**
 * gpgme_data_new_from_file:
 * @r_dh: returns the new data object
 * @fname: filename
 * @copy: Flag, whether the file should be copied.
 * 
 * Create a new data object and initialize it with the content of 
 * the file @file.  If @copy is %True the file is immediately read in
 * adn closed.  @copy of %False is not yet supportted.
 * 
 * Return value: An error code or 0 on success. If the error code is
 * %GPGME_File_Error, the OS error code is held in %errno.
 **/
GpgmeError
gpgme_data_new_from_file ( GpgmeData *r_dh, const char *fname, int copy )
{
    GpgmeData dh;
    GpgmeError err;
    struct stat st;
    FILE *fp;

    if (!r_dh)
        return mk_error (Invalid_Value);
    *r_dh = NULL;
    /* We only support copy for now - in future we might want to honor the 
     * copy flag and just store a file pointer */
    if (!copy)
        return mk_error (Not_Implemented);
    if (!fname)
        return mk_error (Invalid_Value);

    err = gpgme_data_new ( &dh );
    if (err)
        return err;

    fp = fopen (fname, "rb");
    if (!fp) {
        int save_errno = errno;
        gpgme_data_release (dh);
        errno = save_errno;
        return mk_error (File_Error);
    }

    if( fstat(fileno(fp), &st) ) {
        int save_errno = errno;
        fclose (fp);
        gpgme_data_release (dh);
        errno = save_errno;
        return mk_error (File_Error);
    }

    /* We should check the length of the file and don't allow for to
     * large files */
    dh->private_buffer = xtrymalloc ( st.st_size );
    if ( !dh->private_buffer ) {
        fclose (fp);
        gpgme_data_release (dh);
        return mk_error (Out_Of_Core);
    }
    dh->private_len = st.st_size;

    if ( fread ( dh->private_buffer, dh->private_len, 1, fp ) != 1 ) {
        int save_errno = errno;
        fclose (fp);
        gpgme_data_release (dh);
        errno = save_errno;
        return mk_error (File_Error);
    }

    fclose (fp);

    dh->len = dh->private_len;
    dh->data = dh->private_buffer;
    dh->writepos = dh->len;
    dh->type = GPGME_DATA_TYPE_MEM;
    
    *r_dh = dh;
    return 0;
}


GpgmeError
gpgme_data_new_from_filepart ( GpgmeData *r_dh, const char *fname, FILE *fp,
                               off_t offset, off_t length )
{
    GpgmeData dh;
    GpgmeError err;

    if (!r_dh)
        return mk_error (Invalid_Value);
    *r_dh = NULL;
    if ( fname && fp ) /* these are mutual exclusive */
        return mk_error (Invalid_Value);
    if (!fname && !fp)
        return mk_error (Invalid_Value);
    if (!length)
        return mk_error (Invalid_Value);

    err = gpgme_data_new ( &dh );
    if (err)
        return err;

    if (!fp) {
        fp = fopen (fname, "rb");
        if (!fp) {
            int save_errno = errno;
            gpgme_data_release (dh);
            errno = save_errno;
            return mk_error (File_Error);
        }
    }

    if ( fseek ( fp, (long)offset, SEEK_SET) ) {
        int save_errno = errno;
        if (fname)
            fclose (fp);
        gpgme_data_release (dh);
        errno = save_errno;
        return mk_error (File_Error);
    }


    dh->private_buffer = xtrymalloc ( length );
    if ( !dh->private_buffer ) {
        if (fname)
            fclose (fp);
        gpgme_data_release (dh);
        return mk_error (Out_Of_Core);
    }
    dh->private_len = length;

    if ( fread ( dh->private_buffer, dh->private_len, 1, fp ) != 1 ) {
        int save_errno = errno;
        if (fname)
            fclose (fp);
        gpgme_data_release (dh);
        errno = save_errno;
        return mk_error (File_Error);
    }

    if (fname)
        fclose (fp);

    dh->len = dh->private_len;
    dh->data = dh->private_buffer;
    dh->writepos = dh->len;
    dh->type = GPGME_DATA_TYPE_MEM;
    
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
        if ( _gpgme_data_append ( dh, "", 1 ) ) /* append EOS */
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

/**
 * gpgme_data_release_and_get_mem:
 * @dh: the data object
 * @r_len: returns the length of the memory
 * 
 * Release the data object @dh and return its content and the length
 * of that content.  The caller has to free this data.  @dh maybe NULL
 * in which case NULL is returned.  If there is not enough memory for
 * allocating the return value, NULL is returned and the object is
 * released.
 * 
 * Return value: a pointer to an allocated buffer of length @r_len.
 **/
char *
gpgme_data_release_and_get_mem ( GpgmeData dh, size_t *r_len )
{
    char *val = NULL;

    if (r_len)
        *r_len = 0;
    if (dh) {
        size_t len = dh->len;
        val = dh->private_buffer;
        if ( !val && dh->data ) {
            val = xtrymalloc ( len );
            if ( val )
                memcpy ( val, dh->data, len );
        }
        xfree (dh);
        if (val && r_len )
            *r_len = len;
    }
    return val;
}


/**
 * gpgme_data_get_type:
 * @dh: the data object
 * 
 * Get the type of the data object.
 * Data types are prefixed with %GPGME_DATA_TYPE_
 * 
 * Return value: the data type
 **/
GpgmeDataType
gpgme_data_get_type ( GpgmeData dh )
{
    if ( !dh || (!dh->data && !dh->read_cb))
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

/**
 * gpgme_data_rewind:
 * @dh: the data object 
 * 
 * Prepare the data object in a way, that a gpgme_data_read() does start
 * at the beginning of the data.  This has to be done for all types
 * of data objects.
 * 
 * Return value: An error code or 0 on success
 **/
GpgmeError
gpgme_data_rewind ( GpgmeData dh )
{
    if ( !dh )
        return mk_error (Invalid_Value);

    if ( dh->type == GPGME_DATA_TYPE_NONE 
         || dh->type == GPGME_DATA_TYPE_MEM ) {
        dh->readpos = 0;
    }
    else if (dh->type == GPGME_DATA_TYPE_CB) {
        dh->len = dh->readpos = 0;
        dh->read_cb_eof = 0;
        /* FIXME: do a special call to the read function to trigger a rewind
           there */
    }
    else
        return mk_error (General_Error);
    return 0;
}

/**
 * gpgme_data_read:
 * @dh: the data object
 * @buffer: A buffer 
 * @length: The length of that bufer
 * @nread: Returns the number of bytes actually read.
 * 
 * Copy data from the current read position (which may be set by
 * gpgme_data_rewind()) to the supplied @buffer, max. @length bytes
 * are copied and the actual number of bytes are returned in @nread.
 * If there are no more bytes available %GPGME_EOF is returned and @nread
 * is set to 0.
 * 
 * Return value: An errorcode or 0 on success, EOF is indcated by the
 * error code GPGME_EOF.
 **/
GpgmeError
gpgme_data_read ( GpgmeData dh, char *buffer, size_t length, size_t *nread )
{
    size_t nbytes;

    if ( !dh )
        return mk_error (Invalid_Value);
    if (dh->type == GPGME_DATA_TYPE_MEM ) {
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
    }
    else if (dh->type == GPGME_DATA_TYPE_CB) {
        nbytes = dh->len - dh->readpos;
        if ( nbytes ) {
            /* we have unread data - return this */
            if (nbytes > length)
                nbytes = length;
            memcpy ( buffer, dh->data + dh->readpos, nbytes );
            *nread = nbytes;
            dh->readpos += nbytes;
        }
        else { /* get the data from the callback */
            if (!dh->read_cb || dh->read_cb_eof) { 
                *nread = 0;
                return mk_error (EOF);
            }
            if (dh->read_cb (dh->read_cb_value, buffer, length, nread )) {
                *nread = 0;
                dh->read_cb_eof = 1;
                return mk_error (EOF);
            }
        }
    }
    else
        return mk_error (General_Error);
    return 0;
} 

GpgmeError
_gpgme_data_unread (GpgmeData dh, const char *buffer, size_t length )
{
   if ( !dh )
        return mk_error (Invalid_Value);

   if (dh->type == GPGME_DATA_TYPE_MEM ) {
       /* check that we don't unread more than we have yet read */
       if ( dh->readpos < length )
           return mk_error (Invalid_Value);
       /* No need to use the buffer for this data type */
       dh->readpos -= length;
   }
   else {
       return mk_error (General_Error);
   }

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


/**
 * gpgme_data_write:
 * @dh: the context
 * @buffer: data to be written to the data object
 * @length: length o this data
 * 
 * Write the content of @buffer to the data object @dh at the current write
 * position. 
 * 
 * Return value: 0 on succress or an errorcode
 **/
GpgmeError
gpgme_data_write ( GpgmeData dh, const char *buffer, size_t length )
{
    if (!dh || !buffer)
        return mk_error (Invalid_Value);
      
    return _gpgme_data_append (dh, buffer, length );
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







