/* export.c -  encrypt functions
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
export_status_handler ( GpgmeCtx ctx, GpgStatusCode code, char *args )
{
    DEBUG2 ("export_status: code=%d args=`%s'\n", code, args );
    /* FIXME: Need to do more */
}


GpgmeError
gpgme_op_export_start ( GpgmeCtx c, GpgmeRecipients recp,
                         GpgmeData keydata )
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

    _gpgme_gpg_set_status_handler ( c->gpg, export_status_handler, c );

    /* build the commandline */
    _gpgme_gpg_add_arg ( c->gpg, "--export" );
    if ( c->use_armor )
        _gpgme_gpg_add_arg ( c->gpg, "--armor" );
    for ( i=0; i < c->verbosity; i++ )
        _gpgme_gpg_add_arg ( c->gpg, "--verbose" );

    if ( !keydata || gpgme_data_get_type (keydata) != GPGME_DATA_TYPE_NONE ) {
        rc = mk_error (Invalid_Value);
        goto leave;
    }
    _gpgme_data_set_mode (keydata, GPGME_DATA_MODE_IN );
    _gpgme_gpg_add_data ( c->gpg, keydata, 1 );
    _gpgme_gpg_add_arg ( c->gpg, "--" );

    { 
       void *ec;
       const char *s;
    
       rc = gpgme_recipients_enum_open ( recp, &ec );
       if ( rc )
           goto leave;
       while ( (s = gpgme_recipients_enum_read ( recp, &ec )) )
           _gpgme_gpg_add_arg (c->gpg, s);
       rc = gpgme_recipients_enum_close ( recp, &ec );
       if ( rc )
           goto leave;
    }

    rc = _gpgme_gpg_spawn ( c->gpg, c );

 leave:
    if (rc) {
        c->pending = 0; 
        _gpgme_gpg_release ( c->gpg ); c->gpg = NULL;
    }
    return rc;
}



/**
 * gpgme_op_export:
 * @c: the context
 * @recp: a list of recipients or NULL
 * @keydata: Returns the keys
 * 
 * This function can be used to extract public keys from the GnuPG key
 * database either in armored (by using gpgme_set_armor()) or in plain
 * binary form.  The function expects a list of user IDs in @recp for
 * whom the public keys are to be exportedkinit
 *
 * 
 * Return value: 0 for success or an error code
 **/
GpgmeError
gpgme_op_export ( GpgmeCtx c, GpgmeRecipients recp, GpgmeData keydata )
{
    int rc = gpgme_op_export_start ( c, recp, keydata );
    if ( !rc ) {
        gpgme_wait (c, 1);
        c->pending = 0;
    }
    return rc;
}



