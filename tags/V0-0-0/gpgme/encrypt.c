/* encrypt.c -  encrypt functions
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
#include <string.h>
#include <assert.h>

#include "util.h"
#include "context.h"
#include "ops.h"

static void
encrypt_status_handler ( GpgmeCtx ctx, GpgStatusCode code, char *args )
{
    fprintf (stderr, "encrypt_status: code=%d args=`%s'\n",
             code, args );

}



GpgmeError
gpgme_op_encrypt_start ( GpgmeCtx c, GpgmeRecipients recp,
                         GpgmeData plain, GpgmeData ciph )
{
    int rc = 0;
    int i;

    fail_on_pending_request( c );
    c->pending = 1;

    /* do some checks */
    assert ( !c->gpg );
    if ( !gpgme_recipients_count ( recp ) ) {
        /* Fixme: In this case we should do symmentric encryption */
        rc = mk_error (No_Recipients);
        goto leave;
    }
        
    /* create a process object */
    rc = _gpgme_gpg_new ( &c->gpg );
    if (rc)
        goto leave;

    _gpgme_gpg_set_status_handler ( c->gpg, encrypt_status_handler, c );

    /* build the commandline */
    _gpgme_gpg_add_arg ( c->gpg, "--encrypt" );
    if ( c->use_armor )
        _gpgme_gpg_add_arg ( c->gpg, "--armor" );
    for ( i=0; i < c->verbosity; i++ )
        _gpgme_gpg_add_arg ( c->gpg, "--verbose" );
    
    _gpgme_append_gpg_args_from_recipients ( recp, c->gpg );

    /* Check the supplied data */
    if ( gpgme_data_get_type (plain) == GPGME_DATA_TYPE_NONE ) {
        rc = mk_error (No_Data);
        goto leave;
    }
    _gpgme_data_set_mode (plain, GPGME_DATA_MODE_OUT );
    if ( !ciph || gpgme_data_get_type (ciph) != GPGME_DATA_TYPE_NONE ) {
        rc = mk_error (Invalid_Value);
        goto leave;
    }
    _gpgme_data_set_mode (ciph, GPGME_DATA_MODE_IN );
    /* Tell the gpg object about the data */
    _gpgme_gpg_add_arg ( c->gpg, "--output" );
    _gpgme_gpg_add_arg ( c->gpg, "-" );
    _gpgme_gpg_add_data ( c->gpg, ciph, 1 );
    _gpgme_gpg_add_arg ( c->gpg, "--" );
    _gpgme_gpg_add_data ( c->gpg, plain, 0 );

    /* and kick off the process */
    rc = _gpgme_gpg_spawn ( c->gpg, c );

 leave:
    if (rc) {
        c->pending = 0; 
        _gpgme_gpg_release ( c->gpg ); c->gpg = NULL;
    }
    return rc;
}


/**
 * gpgme_op_encrypt:
 * @c: The context
 * @recp: A set of recipients 
 * @in: plaintext input
 * @out: ciphertext output
 * 
 * This function encrypts @in to @out for all recipients from
 * @recp.  Other parameters are take from the context @c.
 * The function does wait for the result.
 * 
 * Return value:  0 on success or an errorcode. 
 **/
GpgmeError
gpgme_op_encrypt ( GpgmeCtx c, GpgmeRecipients recp,
                   GpgmeData in, GpgmeData out )
{
    int rc = gpgme_op_encrypt_start ( c, recp, in, out );
    if ( !rc ) {
        gpgme_wait (c, 1);
        c->pending = 0;
    }
    return rc;
}




