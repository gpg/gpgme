/* decrypt.c -  decrypt functions
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


struct decrypt_result_s {
    int no_passphrase;
    int okay;
    int failed;

};


void
_gpgme_release_decrypt_result ( DecryptResult res )
{
    xfree (res);
}


static GpgmeError
create_result_struct ( GpgmeCtx ctx )
{
    assert ( !ctx->result.decrypt );
    ctx->result.decrypt = xtrycalloc ( 1, sizeof *ctx->result.decrypt );
    if ( !ctx->result.decrypt ) {
        return mk_error (Out_Of_Core);
    }
    ctx->result_type = RESULT_TYPE_DECRYPT;
    return 0;    
}

static void
decrypt_status_handler ( GpgmeCtx ctx, GpgStatusCode code, char *args )
{
    if ( ctx->out_of_core )
        return;
    if ( ctx->result_type == RESULT_TYPE_NONE ) {
        if ( create_result_struct ( ctx ) ) {
            ctx->out_of_core = 1;
            return;
        }
    }
    assert ( ctx->result_type == RESULT_TYPE_DECRYPT );

    switch (code) {
      case STATUS_EOF:
        break;

      case STATUS_NEED_PASSPHRASE:
      case STATUS_NEED_PASSPHRASE_SYM:
        fprintf (stderr, "need a passphrase ...\n" );
        _gpgme_set_prompt (ctx, 1, "Hey! We need your passphrase!");
        /* next thing gpg has to do is to read it from the passphrase-fd */
        break;

      case STATUS_MISSING_PASSPHRASE:
        fprintf (stderr, "Missing passphrase - stop\n");;
        ctx->result.decrypt->no_passphrase = 1;
        break;

      case STATUS_DECRYPTION_OKAY:
        ctx->result.decrypt->okay = 1;
        break;

      case STATUS_DECRYPTION_FAILED:
        ctx->result.decrypt->failed = 1;
        break;
        

      default:
        /* ignore all other codes */
        fprintf (stderr, "decrypt_status: code=%d not handled\n", code );
        break;
    }
}


GpgmeError
gpgme_op_decrypt_start ( GpgmeCtx c, GpgmeData passphrase,
                         GpgmeData ciph, GpgmeData plain   )
{
    int rc = 0;
    int i;

    fail_on_pending_request( c );
    c->pending = 1;

    _gpgme_release_result (c);
    c->out_of_core = 0;

    /* do some checks */
    assert ( !c->gpg );
        
    /* create a process object */
    rc = _gpgme_gpg_new ( &c->gpg );
    if (rc)
        goto leave;

    _gpgme_gpg_set_status_handler ( c->gpg, decrypt_status_handler, c );

    /* build the commandline */
    _gpgme_gpg_add_arg ( c->gpg, "--decrypt" );
    for ( i=0; i < c->verbosity; i++ )
        _gpgme_gpg_add_arg ( c->gpg, "--verbose" );
    if (passphrase) {
        _gpgme_gpg_add_arg (c->gpg, "--passphrase-fd" );
        _gpgme_gpg_add_data (c->gpg, passphrase, -2 );
    }


    /* Check the supplied data */
    if ( !ciph || gpgme_data_get_type (ciph) == GPGME_DATA_TYPE_NONE ) {
        rc = mk_error (No_Data);
        goto leave;
    }
    _gpgme_data_set_mode (ciph, GPGME_DATA_MODE_OUT );

    if ( gpgme_data_get_type (plain) != GPGME_DATA_TYPE_NONE ) {
        rc = mk_error (Invalid_Value);
        goto leave;
    }
    _gpgme_data_set_mode (plain, GPGME_DATA_MODE_IN );

    /* Tell the gpg object about the data */
    _gpgme_gpg_add_arg ( c->gpg, "--output" );
    _gpgme_gpg_add_arg ( c->gpg, "-" );
    _gpgme_gpg_add_data ( c->gpg, plain, 1 );
    _gpgme_gpg_add_data ( c->gpg, ciph, 0 );

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
 * gpgme_op_decrypt:
 * @c: The context
 * @passphrase: A data object with the passphrase or NULL.
 * @in: ciphertext input
 * @out: plaintext output
 * 
 * This function decrypts @in to @out.
 * Other parameters are take from the context @c.
 * The function does wait for the result.
 * 
 * Return value:  0 on success or an errorcode. 
 **/
GpgmeError
gpgme_op_decrypt ( GpgmeCtx c, GpgmeData passphrase,
                   GpgmeData in, GpgmeData out )
{
    GpgmeError err = gpgme_op_decrypt_start ( c, passphrase, in, out );
    if ( !err ) {
        gpgme_wait (c, 1);
        if ( c->result_type != RESULT_TYPE_DECRYPT )
            err = mk_error (General_Error);
        else if ( c->out_of_core )
            err = mk_error (Out_Of_Core);
        else {
            assert ( c->result.decrypt );
            if ( c->result.decrypt->no_passphrase ) 
                err = mk_error (No_Passphrase);
            else if ( c->result.decrypt->failed ) 
                err = mk_error (Decryption_Failed);
            else if (!c->result.decrypt->okay)
                err = mk_error (No_Data);
        }
        c->pending = 0;
    }
    return err;
}









