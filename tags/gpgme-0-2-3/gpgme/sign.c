/* sign.c -  signing functions
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

#define SKIP_TOKEN_OR_RETURN(a) do { \
    while (*(a) && *(a) != ' ') (a)++; \
    while (*(a) == ' ') (a)++; \
    if (!*(a)) \
        return; /* oops */ \
} while (0)




struct  sign_result_s {
    int no_passphrase;
    int okay;
    void *last_pw_handle;
    char *userid_hint;
    char *passphrase_info;
    int bad_passphrase;
    GpgmeData xmlinfo;
};


void
_gpgme_release_sign_result ( SignResult res )
{
    gpgme_data_release (res->xmlinfo);
    xfree (res->userid_hint);
    xfree (res->passphrase_info);
    xfree (res);
}


/* parse the args and save the information 
 * <type> <pubkey algo> <hash algo> <class> <timestamp> <key fpr>
 * in an XML structure.  With args of NULL the xml structure is closed.
 */
static void
append_xml_siginfo (GpgmeData *rdh, char *args)
{
    GpgmeData dh;
    char helpbuf[100];
    int i;
    char *s;
    unsigned long ul;

    if ( !*rdh ) {
        if (gpgme_data_new (rdh)) {
            return; /* fixme: We are ignoring out-of-core */
        }
        dh = *rdh;
        _gpgme_data_append_string (dh, "<GnupgOperationInfo>\n");
    }
    else {
        dh = *rdh;
        _gpgme_data_append_string (dh, "  </signature>\n");
    }

    if (!args) { /* just close the XML containter */
        _gpgme_data_append_string (dh, "</GnupgOperationInfo>\n");
        return;
    }

    _gpgme_data_append_string (dh, "  <signature>\n");
    
    _gpgme_data_append_string (dh,
                               *args == 'D'? "    <detached/>\n":
                               *args == 'C'? "    <cleartext/>\n":
                               *args == 'S'? "    <standard/>\n":"");
    SKIP_TOKEN_OR_RETURN (args);

    sprintf (helpbuf, "    <algo>%d</algo>\n", atoi (args));
    _gpgme_data_append_string (dh, helpbuf);
    SKIP_TOKEN_OR_RETURN (args);

    i = atoi (args);
    sprintf (helpbuf, "    <hashalgo>%d</hashalgo>\n", atoi (args));
    _gpgme_data_append_string (dh, helpbuf);
    switch (i) {
      case  1: s = "pgp-md5"; break;
      case  2: s = "pgp-sha1"; break;
      case  3: s = "pgp-ripemd160"; break;
      case  5: s = "pgp-md2"; break;
      case  6: s = "pgp-tiger192"; break;
      case  7: s = "pgp-haval-5-160"; break;
      case  8: s = "pgp-sha256"; break;
      case  9: s = "pgp-sha384"; break;
      case 10: s = "pgp-sha512"; break;
      default: s = "pgp-unknown"; break;
    }
    sprintf (helpbuf, "    <micalg>%s</micalg>\n", s);
    _gpgme_data_append_string (dh,helpbuf);
    SKIP_TOKEN_OR_RETURN (args);
    
    sprintf (helpbuf, "    <sigclass>%.2s</sigclass>\n", args);
    _gpgme_data_append_string (dh, helpbuf);
    SKIP_TOKEN_OR_RETURN (args);

    ul = strtoul (args, NULL, 10);
    sprintf (helpbuf, "    <created>%lu</created>\n", ul);
    _gpgme_data_append_string (dh, helpbuf);
    SKIP_TOKEN_OR_RETURN (args);

    /* count the length of the finperprint */
    for (i=0; args[i] && args[i] != ' '; i++)
        ;
    _gpgme_data_append_string (dh, "    <fpr>");
    _gpgme_data_append (dh, args, i);
    _gpgme_data_append_string (dh, "</fpr>\n");
}



static void
sign_status_handler ( GpgmeCtx ctx, GpgStatusCode code, char *args )
{
    if ( ctx->out_of_core )
        return;
    if ( ctx->result_type == RESULT_TYPE_NONE ) {
        assert ( !ctx->result.sign );
        ctx->result.sign = xtrycalloc ( 1, sizeof *ctx->result.sign );
        if ( !ctx->result.sign ) {
            ctx->out_of_core = 1;
            return;
        }
        ctx->result_type = RESULT_TYPE_SIGN;
    }
    assert ( ctx->result_type == RESULT_TYPE_SIGN );

    switch (code) {
      case STATUS_EOF:
        if (ctx->result.sign->okay) {
            append_xml_siginfo (&ctx->result.sign->xmlinfo, NULL);
            _gpgme_set_op_info (ctx, ctx->result.sign->xmlinfo);
            ctx->result.sign->xmlinfo = NULL;
        }
        break;

      case STATUS_USERID_HINT:
        xfree (ctx->result.sign->userid_hint);
        if (!(ctx->result.sign->userid_hint = xtrystrdup (args)) )
            ctx->out_of_core = 1;
        break;

      case STATUS_BAD_PASSPHRASE:
        ctx->result.sign->bad_passphrase++;
        break;

      case STATUS_GOOD_PASSPHRASE:
        ctx->result.sign->bad_passphrase = 0;
        break;

      case STATUS_NEED_PASSPHRASE:
      case STATUS_NEED_PASSPHRASE_SYM:
        xfree (ctx->result.sign->passphrase_info);
        if (!(ctx->result.sign->passphrase_info = xtrystrdup (args)) )
            ctx->out_of_core = 1;
        break;

      case STATUS_MISSING_PASSPHRASE:
        DEBUG0 ("missing passphrase - stop\n");
        ctx->result.sign->no_passphrase = 1;
        break;

      case STATUS_SIG_CREATED: 
        /* fixme: we have no error return for multiple signatures */
        append_xml_siginfo (&ctx->result.sign->xmlinfo, args);
        ctx->result.sign->okay =1;
        break;

      default:
        break;
    }
}

static const char *
command_handler ( void *opaque, GpgStatusCode code, const char *key )
{
    GpgmeCtx c = opaque;

    if ( c->result_type == RESULT_TYPE_NONE ) {
        assert ( !c->result.sign );
        c->result.sign = xtrycalloc ( 1, sizeof *c->result.sign );
        if ( !c->result.sign ) {
            c->out_of_core = 1;
            return NULL;
        }
        c->result_type = RESULT_TYPE_SIGN;
    }

    if ( !code ) {
        /* We have been called for cleanup */
        if ( c->passphrase_cb ) { 
            /* Fixme: take the key in account */
            c->passphrase_cb (c->passphrase_cb_value, 0, 
                              &c->result.sign->last_pw_handle );
        }
        
        return NULL;
    }

    if ( !key || !c->passphrase_cb )
        return NULL;
    
    if ( code == STATUS_GET_HIDDEN && !strcmp (key, "passphrase.enter") ) {
        const char *userid_hint = c->result.sign->userid_hint;
        const char *passphrase_info = c->result.sign->passphrase_info;
        int bad_passphrase = c->result.sign->bad_passphrase;
        char *buf;
        const char *s;

        c->result.sign->bad_passphrase = 0;
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
                              buf, &c->result.sign->last_pw_handle );
        xfree (buf);
        return s;
    }
    
    return NULL;
}


GpgmeError
gpgme_op_sign_start ( GpgmeCtx c, GpgmeData in, GpgmeData out,
                      GpgmeSigMode mode )
{
    int rc = 0;
    int i;
    GpgmeKey key;

    fail_on_pending_request( c );
    c->pending = 1;

    _gpgme_release_result (c);
    c->out_of_core = 0;


    if ( mode != GPGME_SIG_MODE_NORMAL
         && mode != GPGME_SIG_MODE_DETACH
         && mode != GPGME_SIG_MODE_CLEAR )
        return mk_error (Invalid_Value);
        
    /* create a process object */
    _gpgme_gpg_release (c->gpg);
    c->gpg = NULL;
    rc = _gpgme_gpg_new ( &c->gpg );
    if (rc)
        goto leave;

    _gpgme_gpg_set_status_handler ( c->gpg, sign_status_handler, c );
    if (c->passphrase_cb) {
        rc = _gpgme_gpg_set_command_handler ( c->gpg, command_handler, c );
        if (rc)
            goto leave;
    }

    /* build the commandline */
    if ( mode == GPGME_SIG_MODE_CLEAR ) {
        _gpgme_gpg_add_arg ( c->gpg, "--clearsign" );
    }
    else {
        _gpgme_gpg_add_arg ( c->gpg, "--sign" );
        if ( mode == GPGME_SIG_MODE_DETACH )
            _gpgme_gpg_add_arg ( c->gpg, "--detach" );
        if ( c->use_armor )
            _gpgme_gpg_add_arg ( c->gpg, "--armor" );
        if ( c->use_textmode )
            _gpgme_gpg_add_arg ( c->gpg, "--textmode" );
    }
    for (i=0; i < c->verbosity; i++)
        _gpgme_gpg_add_arg ( c->gpg, "--verbose" );
    for (i=0; (key = gpgme_signers_enum (c, i)); i++ ) {
        const char *s = gpgme_key_get_string_attr (key, GPGME_ATTR_KEYID,
                                                   NULL, 0);
        if (s) {
            _gpgme_gpg_add_arg (c->gpg, "-u");
            _gpgme_gpg_add_arg (c->gpg, s);
        }
        gpgme_key_unref (key);
    }

    
    /* Check the supplied data */
    if ( gpgme_data_get_type (in) == GPGME_DATA_TYPE_NONE ) {
        rc = mk_error (No_Data);
        goto leave;
    }
    _gpgme_data_set_mode (in, GPGME_DATA_MODE_OUT );
    if ( !out || gpgme_data_get_type (out) != GPGME_DATA_TYPE_NONE ) {
        rc = mk_error (Invalid_Value);
        goto leave;
    }
    _gpgme_data_set_mode (out, GPGME_DATA_MODE_IN );

    /* tell the gpg object about the data */
    _gpgme_gpg_add_data ( c->gpg, in, 0 );
    _gpgme_gpg_add_data ( c->gpg, out, 1 );

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
 * gpgme_op_sign:
 * @c: The context
 * @in: Data to be signed
 * @out: Detached signature
 * @mode: Signature creation mode
 * 
 * Create a detached signature for @in and write it to @out.
 * The data will be signed using either the default key or the ones
 * defined through @c.
 * The defined modes for signature create are:
 * <literal>
 * GPGME_SIG_MODE_NORMAL (or 0) 
 * GPGME_SIG_MODE_DETACH
 * GPGME_SIG_MODE_CLEAR
 * </literal>
 * Note that the settings done by gpgme_set_armor() and gpgme_set_textmode()
 * are ignore for @mode GPGME_SIG_MODE_CLEAR.
 * 
 * Return value: 0 on success or an error code.
 **/
GpgmeError
gpgme_op_sign ( GpgmeCtx c, GpgmeData in, GpgmeData out, GpgmeSigMode mode )
{
    GpgmeError err = gpgme_op_sign_start ( c, in, out, mode );
    if ( !err ) {
        gpgme_wait (c, 1);
        if ( c->result_type != RESULT_TYPE_SIGN )
            err = mk_error (General_Error);
        else if ( c->out_of_core )
            err = mk_error (Out_Of_Core);
        else {
            assert ( c->result.sign );
            if ( c->result.sign->no_passphrase ) 
                err = mk_error (No_Passphrase);
            else if (!c->result.sign->okay)
                err = mk_error (No_Data); /* Hmmm: choose a better error? */
            
        }
        c->pending = 0;
    }
    return err;
}









