/* verify.c -  signature verification
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

typedef enum {
    VERIFY_STATUS_NONE = 0,
    VERIFY_STATUS_NOSIG,
    VERIFY_STATUS_NOKEY,
    VERIFY_STATUS_ERROR,
    VERIFY_STATUS_BAD,
    VERIFY_STATUS_GOOD
} VerifyStatus;

struct verify_result_s {
    VerifyStatus status;

};


void
_gpgme_release_verify_result ( VerifyResult res )
{
    xfree (res);
}


static void
verify_status_handler ( GpgmeCtx ctx, GpgStatusCode code, char *args )
{
    if ( ctx->out_of_core )
        return;
    if ( ctx->result_type == RESULT_TYPE_NONE ) {
        assert ( !ctx->result.verify );
        ctx->result.verify = xtrycalloc ( 1, sizeof *ctx->result.verify );
        if ( !ctx->result.verify ) {
            ctx->out_of_core = 1;
            return;
        }
        ctx->result_type = RESULT_TYPE_VERIFY;
    }
    assert ( ctx->result_type == RESULT_TYPE_VERIFY );

    /* FIXME: For now we handle only one signature */
    /* FIXME: Collect useful information */
    switch (code) {
      case STATUS_GOODSIG:
        ctx->result.verify->status = VERIFY_STATUS_GOOD;
        break;
      case STATUS_BADSIG:
        ctx->result.verify->status = VERIFY_STATUS_BAD;
        break;
      case STATUS_ERRSIG:
        ctx->result.verify->status = VERIFY_STATUS_ERROR;
        /* FIXME: distinguish between a regular error and a missing key.
         * this is encoded in the args. */
        break;
      default:
        /* ignore all other codes */
        fprintf (stderr, "verify_status: code=%d not handled\n", code );
        break;
    }
}



GpgmeError
gpgme_start_verify ( GpgmeCtx c,  GpgmeData sig, GpgmeData text )
{
    int rc = 0;
    int i;

    fail_on_pending_request( c );
    c->pending = 1;

    _gpgme_release_result (c);
    c->out_of_core = 0;

    /* create a process object.
     * To optimize this, we should reuse an existing one and
     * run gpg in the new --pipemode (I started with this but it is
     * not yet finished) */
    if ( c->gpg ) {
        _gpgme_gpg_release_object ( c->gpg ); 
        c->gpg = NULL;
    }
    rc = _gpgme_gpg_new_object ( &c->gpg );
    if (rc)
        goto leave;

    _gpgme_gpg_set_status_handler ( c->gpg, verify_status_handler, c );

    /* build the commandline */
    _gpgme_gpg_add_arg ( c->gpg, "--verify" );
    for ( i=0; i < c->verbosity; i++ )
        _gpgme_gpg_add_arg ( c->gpg, "--verbose" );
    

    /* Check the supplied data */
    if ( gpgme_query_data_type (sig) == GPGME_DATA_TYPE_NONE ) {
        rc = mk_error (No_Data);
        goto leave;
    }
    if ( text && gpgme_query_data_type (text) == GPGME_DATA_TYPE_NONE ) {
        rc = mk_error (No_Data);
        goto leave;
    }
    _gpgme_set_data_mode (sig, GPGME_DATA_MODE_OUT );
    if (text) /* detached signature */
        _gpgme_set_data_mode (text, GPGME_DATA_MODE_OUT );
    /* Tell the gpg object about the data */
    _gpgme_gpg_add_arg ( c->gpg, "--" );
    _gpgme_gpg_add_data ( c->gpg, sig, -1 );
    if (text)
        _gpgme_gpg_add_data ( c->gpg, text, 0 );

    /* and kick off the process */
    rc = _gpgme_gpg_spawn ( c->gpg, c );

 leave:
    if (rc) {
        c->pending = 0; 
        _gpgme_gpg_release_object ( c->gpg ); c->gpg = NULL;
    }
    return rc;
}



GpgmeError
gpgme_verify ( GpgmeCtx c, GpgmeData sig, GpgmeData text )
{
    int rc = gpgme_start_verify ( c, sig, text );
    if ( !rc ) {
        gpgme_wait (c, 1);
        if ( c->result_type != RESULT_TYPE_VERIFY )
            rc = mk_error (General_Error);
        else if ( c->out_of_core )
            rc = mk_error (Out_Of_Core);
        else {
            assert ( c->result.verify );
            switch ( c->result.verify->status ) {
              case VERIFY_STATUS_NONE:
                fputs ("Verification Status: None\n", stdout);
                break;
              case VERIFY_STATUS_NOSIG:
                fputs ("Verification Status: No Signature\n", stdout);
                break;
              case VERIFY_STATUS_GOOD:
                fputs ("Verification Status: Good\n", stdout);
                break;
              case VERIFY_STATUS_BAD:
                fputs ("Verification Status: Bad\n", stdout);
                break;
              case VERIFY_STATUS_NOKEY:
                fputs ("Verification Status: No Key\n", stdout);
                break;
              case VERIFY_STATUS_ERROR:
                fputs ("Verification Status: Error\n", stdout);
                break;
            }
        }
        c->pending = 0;
    }
    return rc;
}







