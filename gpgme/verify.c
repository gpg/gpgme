/* verify.c -  signature verification
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
#include "key.h"

struct verify_result_s {
    struct verify_result_s *next;
    GpgmeSigStat status;
    GpgmeData notation; /* we store an XML fragment here */
    int collecting;       /* private to finish_sig() */
    int notation_in_data; /* private to add_notation() */
    char fpr[41];    /* fingerprint of a good signature or keyid of a bad one*/
    ulong timestamp; /* signature creation time */
};


void
_gpgme_release_verify_result ( VerifyResult res )
{
    while (res) {
        VerifyResult r2 = res->next;
        gpgme_data_release ( res->notation );
        xfree (res);
        res = r2;
    }
}

/* fixme: check that we are adding this to the correct signature */
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


/* 
 * finish a pending signature info collection and prepare for a new
 * signature info collection
 */
static void
finish_sig (GpgmeCtx ctx, int stop)
{
    if (stop)
        return; /* nothing to do */

    if (ctx->result.verify->collecting) {
        VerifyResult res2;

        ctx->result.verify->collecting = 0;
        /* create a new result structure */
        res2 = xtrycalloc ( 1, sizeof *res2 );
        if ( !res2 ) {
            ctx->out_of_core = 1;
            return;
        }

        res2->next = ctx->result.verify;
        ctx->result.verify = res2;
    }
    
    ctx->result.verify->collecting = 1;
}


static void
verify_status_handler ( GpgmeCtx ctx, GpgStatusCode code, char *args )
{
    char *p;
    int i;

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

    if (code == STATUS_GOODSIG
        || code == STATUS_BADSIG || code == STATUS_ERRSIG) {
        finish_sig (ctx,0);
        if ( ctx->out_of_core )
            return;
    }

    switch (code) {
      case STATUS_NODATA:
        ctx->result.verify->status = GPGME_SIG_STAT_NOSIG;
        break;

      case STATUS_GOODSIG:
        /* We only look at VALIDSIG */
        break;

      case STATUS_VALIDSIG:
        ctx->result.verify->status = GPGME_SIG_STAT_GOOD;
        p = ctx->result.verify->fpr;
        for (i=0; i < DIM(ctx->result.verify->fpr)
                 && args[i] && args[i] != ' ' ; i++ )
            *p++ = args[i];
        *p = 0;
        /* skip the formatted date */
        while ( args[i] && args[i] == ' ')
            i++;
        while ( args[i] && args[i] != ' ')
            i++;
        /* and get the timestamp */
        ctx->result.verify->timestamp = strtoul (args+i, NULL, 10);
        break;

      case STATUS_BADSIG:
        ctx->result.verify->status = GPGME_SIG_STAT_BAD;
        /* store the keyID in the fpr field */
        p = ctx->result.verify->fpr;
        for (i=0; i < DIM(ctx->result.verify->fpr)
                 && args[i] && args[i] != ' ' ; i++ )
            *p++ = args[i];
        *p = 0;
        break;

      case STATUS_ERRSIG:
        ctx->result.verify->status = GPGME_SIG_STAT_ERROR;
        /* FIXME: distinguish between a regular error and a missing key.
         * this is encoded in the args. */
        /* store the keyID in the fpr field */
        p = ctx->result.verify->fpr;
        for (i=0; i < DIM(ctx->result.verify->fpr)
                 && args[i] && args[i] != ' ' ; i++ )
            *p++ = args[i];
        *p = 0;
        break;

      case STATUS_NOTATION_NAME:
      case STATUS_NOTATION_DATA:
      case STATUS_POLICY_URL:
        add_notation ( ctx, code, args );
        break;

      case STATUS_END_STREAM:
        break;

      case STATUS_EOF:
        finish_sig(ctx,1);
        break;

      default:
        /* ignore all other codes */
        break;
    }
}



GpgmeError
gpgme_op_verify_start ( GpgmeCtx c,  GpgmeData sig, GpgmeData text )
{
    int rc = 0;
    int i;
    int pipemode = 0; /*!!text; use pipemode for detached sigs */

    fail_on_pending_request( c );
    c->pending = 1;

    _gpgme_release_result (c);
    c->out_of_core = 0;
    
    if ( !pipemode ) {
        _gpgme_gpg_release ( c->gpg );
        c->gpg = NULL;
    }

    if ( !c->gpg ) 
        rc = _gpgme_gpg_new ( &c->gpg );
    if (rc)
        goto leave;

    if (pipemode)
        _gpgme_gpg_enable_pipemode ( c->gpg ); 
    _gpgme_gpg_set_status_handler ( c->gpg, verify_status_handler, c );

    /* build the commandline */
    _gpgme_gpg_add_arg ( c->gpg, pipemode?"--pipemode" : "--verify" );
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
    if (pipemode) {
        _gpgme_gpg_add_pm_data ( c->gpg, sig, 0 );
        _gpgme_gpg_add_pm_data ( c->gpg, text, 1 );
    }
    else {
        _gpgme_gpg_add_data ( c->gpg, sig, -1 );
        if (text) {
            _gpgme_gpg_add_arg ( c->gpg, "-" );
            _gpgme_gpg_add_data ( c->gpg, text, 0 );
        }
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


/* 
 * Figure out a common status value for all signatures 
 */
static GpgmeSigStat
intersect_stati ( VerifyResult res )
{
    GpgmeSigStat status = res->status;

    for (res=res->next; res; res = res->next) {
        if (status != res->status ) 
            return GPGME_SIG_STAT_DIFF;
    }
    return status;
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
 *  GPGME_SIG_STAT_DIFF:  There is more than 1 signature and they have not
 *                        the same status.
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
            /* fixme: Put all notation data into one XML fragment */
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
            *r_stat = intersect_stati (c->result.verify);
        }
        c->pending = 0;
    }
    return rc;
}


/**
 * gpgme_get_sig_status:
 * @c: Context
 * @idx: Index of the signature starting at 0
 * @r_stat: Returns the status
 * @r_created: Returns the creation timestamp
 * 
 * Return information about an already verified signatures. 
 * 
 * Return value: The fingerprint or NULL in case of an problem or
 *               when there are no more signatures.
 **/
const char *
gpgme_get_sig_status (GpgmeCtx c, int idx,
                      GpgmeSigStat *r_stat, time_t *r_created )
{
    VerifyResult res;

    if (!c || c->pending || c->result_type != RESULT_TYPE_VERIFY )
        return NULL; /* No results yet or verification error */

    for (res = c->result.verify; res && idx>0 ; res = res->next, idx--)
        ;
    if (!res)
        return NULL; /* No more signatures */

    if (r_stat)
        *r_stat = res->status;
    if (r_created)
        *r_created = res->timestamp;
    return res->fpr;
}


/**
 * gpgme_get_sig_key:
 * @c: context
 * @idx: Index of the signature starting at 0
 * @r_key: Returns the key object
 * 
 * Return a key object which was used to check the signature. 
 * 
 * Return value: An Errorcode or 0 for success. GPGME_EOF is returned to
 *               indicate that there are no more signatures. 
 **/
GpgmeError
gpgme_get_sig_key (GpgmeCtx c, int idx, GpgmeKey *r_key)
{
    VerifyResult res;
    GpgmeError err = 0;

    if (!c || !r_key)
        return mk_error (Invalid_Value);
    if (c->pending || c->result_type != RESULT_TYPE_VERIFY )
        return mk_error (Busy);

    for (res = c->result.verify; res && idx>0 ; res = res->next, idx--)
        ;
    if (!res)
        return mk_error (EOF);

    if (strlen(res->fpr) < 16) /* we have at least an key ID */
        return mk_error (Invalid_Key);

    *r_key = _gpgme_key_cache_get (res->fpr);
    if (!*r_key) {
        GpgmeCtx listctx;

        /* Fixme: This can be optimized by keeping
         *        an internal context used for such key listings */
        if ( (err=gpgme_new (&listctx)) )
            return err;
        gpgme_set_keylist_mode( listctx, c->keylist_mode );
        if ( !(err=gpgme_op_keylist_start (listctx, res->fpr, 0 )) )
            err=gpgme_op_keylist_next ( listctx, r_key );
        gpgme_release (listctx);
    }
    return err;
}






