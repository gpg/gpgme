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


/**
 * gpgme_new_data:
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
gpgme_new_data ( GpgmeData *r_dh, const char *buffer, size_t size, int copy )
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
            memcpy (dh->private_buffer, buffer, size );
            dh->data = dh->private_buffer;
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
 * gpgme_release_data:
 * @dh: Data object 
 * 
 * Release the data object @dh.  @dh may be NULL in which case nothing
 * happens.
 **/
void
gpgme_release_data ( GpgmeData dh )
{
    if (dh) {
        xfree (dh->private_buffer); 
        xfree (dh);
    }
}


GpgmeDataType
gpgme_query_data_type ( GpgmeData dh )
{
    if ( !dh || !dh->data )
        return GPGME_DATA_TYPE_NONE;
            
    return dh->type;
}

void 
_gpgme_set_data_mode ( GpgmeData dh, GpgmeDataMode mode )
{
    assert (dh);
    dh->mode = mode;
}


GpgmeDataMode
_gpgme_query_data_mode ( GpgmeData dh )
{
    assert (dh);
    return dh->mode;
}



GpgmeError
_gpgme_append_data ( GpgmeData dh, const char *buf, size_t length )
{
    assert (dh);

    if ( dh->type == GPGME_DATA_TYPE_NONE ) {
        /* convert it to a mem data type */
    }
    else if ( dh->type != GPGME_DATA_TYPE_MEM ) {
        return mk_error (Invalid_Type);
    }

    if ( dh->mode != GPGME_DATA_MODE_INOUT 
         && dh->mode != GPGME_DATA_MODE_IN  )
        return mk_error (Invalid_Mode);


    return 0;
}



