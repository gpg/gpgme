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

struct verify_result_s {
    GpgmeSigStat status;
    GpgmeData notation; /* we store an XML fragment here */

    int notation_in_data; /* private to add_notation() */
};


void
_gpgme_release_verify_result ( VerifyResult res )
{
    gpgme_data_release ( res->notation );
    xfree (res);
}


static void
add_notation ( GpgmeCtx ctx, GpgStatusCode code, const char *data )
{
    GpgmeData dh = ctx->result.verify->notation;

    if ( !dh ) {
        if ( gpgme_data_new ( &dh ) ) {
            ctx->out_of_core = 1;
            return;
        }
        ctx->result.verify->notation = dh;
        _gpgme_data_append_string (dh, "  <notation>\n");
    }

    if ( code == STATUS_NOTATION_DATA ) {
        if ( !ctx->result.verify->notation_in_data )
            _gpgme_data_append_string (dh, "  <data>");
        _gpgme_data_append_percentstring_for_xml (dh, data);
        ctx->result.verify->notation_in_data = 1;
        return;
    }

    if ( ctx->result.verify->notation_in_data ) {
        _gpgme_data_append_string (dh, "</data>\n");
        ctx->result.verify->notation_in_data = 0;
    }

    if ( code == STATUS_NOTATION_NAME ) {
        _gpgme_data_append_string (dh, "  <name>");
        _gpgme_data_append_percentstring_for_xml (dh, data);
        _gpgme_data_append_string (dh, "</name>\n");
    }
    else if ( code == STATUS_POLICY_URL ) {
        _gpgme_data_append_string (dh, "  <policy>");
        _gpgme_data_append_percentstring_for_xml (dh, data);
        _gpgme_data_append_string (dh, "</policy>\n");
    }
    else {
        assert (0);
    }
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
    /* FIXME: Collect useful information
       and return them as XML */
    switch (code) {
      case STATUS_GOODSIG:
        ctx->result.verify->status = GPGME_SIG_STAT_GOOD;
        break;
      case STATUS_BADSIG:
        ctx->result.verify->status = GPGME_SIG_STAT_BAD;
        break;
      case STATUS_ERRSIG:
        ctx->result.verify->status = GPGME_SIG_STAT_ERROR;
        /* FIXME: distinguish between a regular error and a missing key.
         * this is encoded in the args. */
        break;

      case STATUS_NOTATION_NAME:
      case STATUS_NOTATION_DATA:
      case STATUS_POLICY_URL:
        add_notation ( ctx, code, args );
        break;

      default:
        /* ignore all other codes */
        fprintf (stderr, "verify_status: code=%d not handled\n", code );
        break;
    }
}



GpgmeError
gpgme_op_verify_start ( GpgmeCtx c,  GpgmeData sig, GpgmeData text )
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
        _gpgme_gpg_release ( c->gpg ); 
        c->gpg = NULL;
    }
    rc = _gpgme_gpg_new ( &c->gpg );
    if (rc)
        goto leave;

    _gpgme_gpg_set_status_handler ( c->gpg, verify_status_handler, c );

    /* build the commandline */
    _gpgme_gpg_add_arg ( c->gpg, "--verify" );
    for ( i=0; i < c->verbosity; i++ )
        _gpgme_gpg_add_arg ( c->gpg, "--verbose" );

    /* Check the supplied data */
    if ( gpgme_data_get_type (sig) == GPGME_DATA_TYPE_NONE ) {
        rc = mk_error (No_Data);
        goto leave;
    }
    if ( text && gpgme_data_get_type (text) == GPGME_DATA_TYPE_NONE ) {
        rc = mk_error (No_Data);
        goto leave;
    }
    _gpgme_data_set_mode (sig, GPGME_DATA_MODE_OUT );
    if (text) /* detached signature */
        _gpgme_data_set_mode (text, GPGME_DATA_MODE_OUT );
    /* Tell the gpg object about the data */
    _gpgme_gpg_add_arg ( c->gpg, "--" );
    _gpgme_gpg_add_data ( c->gpg, sig, -1 );
    if (text) {
        _gpgme_gpg_add_arg ( c->gpg, "-" );
        _gpgme_gpg_add_data ( c->gpg, text, 0 );
    }

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
 * gpgme_op_verify:
 * @c: the context
 * @sig: the signature data
 * @text: the signed text
 * @r_stat: returns the status of the signature
 * 
 * Perform a signature check on the signature given in @sig. Currently it is
 * assumed that this is a detached signature for the material given in @text.
 * The result of this operation is returned in @r_stat which can take these
 * values:
 *  GPGME_SIG_STAT_NONE:  No status - should not happen
 *  GPGME_SIG_STAT_GOOD:  The signature is valid 
 *  GPGME_SIG_STAT_BAD:   The signature is not valid
 *  GPGME_SIG_STAT_NOKEY: The signature could not be checked due to a
 *                        missing key
 *  GPGME_SIG_STAT_NOSIG: This is not a signature
 *  GPGME_SIG_STAT_ERROR: Due to some other error the check could not be done.
 *
 * Return value: 0 on success or an errorcode if something not related to
 *               the signature itself did go wrong.
 **/
GpgmeError
gpgme_op_verify ( GpgmeCtx c, GpgmeData sig, GpgmeData text,
                  GpgmeSigStat *r_stat )
{
    int rc;

    if ( !r_stat )
        return mk_error (Invalid_Value);

    gpgme_data_release (c->notation);
    c->notation = NULL;
    
    *r_stat = GPGME_SIG_STAT_NONE;
    rc = gpgme_op_verify_start ( c, sig, text );
    if ( !rc ) {
        gpgme_wait (c, 1);
        if ( c->result_type != RESULT_TYPE_VERIFY )
            rc = mk_error (General_Error);
        else if ( c->out_of_core )
            rc = mk_error (Out_Of_Core);
        else {
            assert ( c->result.verify );
            if ( c->result.verify->notation ) {
                GpgmeData dh = c->result.verify->notation;
                
                if ( c->result.verify->notation_in_data ) {
                    _gpgme_data_append_string (dh, "</data>\n");
                    c->result.verify->notation_in_data = 0;
                }
                _gpgme_data_append_string (dh, "</notation>\n");
                c->notation = dh;
                c->result.verify->notation = NULL;
            }
            *r_stat = c->result.verify->status;
        }
        c->pending = 0;
    }
    return rc;
}







