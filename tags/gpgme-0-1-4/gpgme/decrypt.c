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
    void *last_pw_handle;
    char *userid_hint;
    char *passphrase_info;
    int bad_passphrase;
};


void
_gpgme_release_decrypt_result ( DecryptResult res )
{
    if (!res )
        return;
    xfree (res->passphrase_info);
    xfree (res->userid_hint);
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

      case STATUS_USERID_HINT:
        xfree (ctx->result.decrypt->userid_hint);
        if (!(ctx->result.decrypt->userid_hint = xtrystrdup (args)) )
            ctx->out_of_core = 1;
        break;

      case STATUS_BAD_PASSPHRASE:
        ctx->result.decrypt->bad_passphrase++;
        break;

      case STATUS_GOOD_PASSPHRASE:
        ctx->result.decrypt->bad_passphrase = 0;
        break;

      case STATUS_NEED_PASSPHRASE:
      case STATUS_NEED_PASSPHRASE_SYM:
        xfree (ctx->result.decrypt->passphrase_info);
        if (!(ctx->result.decrypt->passphrase_info = xtrystrdup (args)) )
            ctx->out_of_core = 1;
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
        break;
    }
}


static const char *
command_handler ( void *opaque, GpgStatusCode code, const char *key )
{
    GpgmeCtx c = opaque;

    if ( c->result_type == RESULT_TYPE_NONE ) {
        if ( create_result_struct ( c ) ) {
            c->out_of_core = 1;
            return NULL;
        }
    }

    if ( !code ) {
        /* We have been called for cleanup */
        if ( c->passphrase_cb ) { 
            /* Fixme: take the key in account */
            c->passphrase_cb (c->passphrase_cb_value, NULL, 
                              &c->result.decrypt->last_pw_handle );
        }
        
        return NULL;
    }

    if ( !key || !c->passphrase_cb )
        return NULL;
    
    if ( code == STATUS_GET_HIDDEN && !strcmp (key, "passphrase.enter") ) {
        const char *userid_hint = c->result.decrypt->userid_hint;
        const char *passphrase_info = c->result.decrypt->passphrase_info;
        int bad_passphrase = c->result.decrypt->bad_passphrase;
        char *buf;
        const char *s;

        c->result.decrypt->bad_passphrase = 0;
        if (!userid_hint)
            userid_hint = "[User ID hint missing]";
        if (!passphrase_info)
            passphrase_info = "[passphrase info missing]";
        buf = xtrymalloc ( 20 + strlen (userid_hint)
                           + strlen (passphrase_info) + 3);
        if (!buf) {
            c->out_of_core = 1;
            return NULL;
        }
        sprintf (buf, "%s\n%s\n%s",
                 bad_passphrase? "TRY_AGAIN":"ENTER",
                 userid_hint, passphrase_info );

        s = c->passphrase_cb (c->passphrase_cb_value,
                              buf, &c->result.decrypt->last_pw_handle );
        xfree (buf);
        return s;
   }
    
    return NULL;
}


GpgmeError
gpgme_op_decrypt_start ( GpgmeCtx c, 
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
    if (c->passphrase_cb) {
        rc = _gpgme_gpg_set_command_handler ( c->gpg, command_handler, c );
        if (rc)
            goto leave;
    }

    /* build the commandline */
    _gpgme_gpg_add_arg ( c->gpg, "--decrypt" );
    for ( i=0; i < c->verbosity; i++ )
        _gpgme_gpg_add_arg ( c->gpg, "--verbose" );

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
gpgme_op_decrypt ( GpgmeCtx c,
                   GpgmeData in, GpgmeData out )
{
    GpgmeError err = gpgme_op_decrypt_start ( c, in, out );
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









