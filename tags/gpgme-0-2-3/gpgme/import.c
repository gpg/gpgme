/* import.c -  encrypt functions
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "util.h"
#include "context.h"
#include "ops.h"

static void
import_status_handler ( GpgmeCtx ctx, GpgStatusCode code, char *args )
{
    DEBUG2 ("import_status: code=%d args=`%s'\n", code, args );
    /* FIXME: We have to check here whether the import actually worked 
     * and maybe it is a good idea to save some statistics and provide
     * a progress callback */
}



GpgmeError
gpgme_op_import_start ( GpgmeCtx c, GpgmeData keydata )
{
    int rc = 0;
    int i;

    fail_on_pending_request( c );
    c->pending = 1;

    /* create a process object */
    _gpgme_gpg_release (c->gpg); c->gpg = NULL;
    rc = _gpgme_gpg_new ( &c->gpg );
    if (rc)
        goto leave;

    _gpgme_gpg_set_status_handler ( c->gpg, import_status_handler, c );

    /* build the commandline */
    _gpgme_gpg_add_arg ( c->gpg, "--import" );
    for ( i=0; i < c->verbosity; i++ )
        _gpgme_gpg_add_arg ( c->gpg, "--verbose" );
    
    /* Check the supplied data */
    if ( gpgme_data_get_type (keydata) == GPGME_DATA_TYPE_NONE ) {
        rc = mk_error (No_Data);
        goto leave;
    }
    _gpgme_data_set_mode (keydata, GPGME_DATA_MODE_OUT );

    _gpgme_gpg_add_data ( c->gpg, keydata, 0 );

    rc = _gpgme_gpg_spawn ( c->gpg, c );

 leave:
    if (rc) {
        c->pending = 0; 
        _gpgme_gpg_release ( c->gpg ); c->gpg = NULL;
    }
    return rc;
}


/**
 * gpgme_op_import:
 * @c: Context 
 * @keydata: Data object
 * 
 * Import all key material from @keydata into the key database.
 * 
 * Return value: o on success or an error code.
 **/
GpgmeError
gpgme_op_import ( GpgmeCtx c, GpgmeData keydata )
{
    int rc = gpgme_op_import_start ( c, keydata );
    if ( !rc ) {
        gpgme_wait (c, 1);
        c->pending = 0;
    }
    return rc;
}




