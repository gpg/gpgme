/* genkey.c -  key generation
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
genkey_status_handler ( GpgmeCtx ctx, GpgStatusCode code, char *args )
{
    if ( code == STATUS_PROGRESS && *args ) {
        if (ctx->progress_cb) {
            char *p;
            int type=0, current=0, total=0;
            
            if ( (p = strchr (args, ' ')) ) {
                *p++ = 0;
                if (*p) {
                    type = *(byte*)p;
                    if ( (p = strchr (p+1, ' ')) ) {
                        *p++ = 0;
                        if (*p) {
                            current = atoi (p);
                            if ( (p = strchr (p+1, ' ')) ) {
                                *p++ = 0;
                                total = atoi (p);
                            }
                        }
                    }
                }
            }           
            if ( type != 'X' )
                ctx->progress_cb ( ctx->progress_cb_value, args, type,
                                   current, total );
        }
        return;
    }

    DEBUG2 ("genkey_status: code=%d args=`%s'\n", code, args );
    /* FIXME: Need to do more */
}



/* 
 * Here is how the parms should be formatted:
<GnupgKeyParms format="internal">
Key-Type: DSA
Key-Length: 1024
Subkey-Type: ELG-E
Subkey-Length: 1024
Name-Real: Joe Tester
Name-Comment: with stupid passphrase
Name-Email: joe@foo.bar
Expire-Date: 0
Passphrase: abc
</GnupgKeyParms>
 * Strings should be given in UTF-8 encoding.  The format we support for now
 * "internal".  The content of the <GnupgKeyParms> container is passed 
 * verbatim to GnuPG.  Control statements (e.g. %pubring) are not allowed.
 */

GpgmeError
gpgme_op_genkey_start ( GpgmeCtx c, const char *parms,
                        GpgmeData pubkey, GpgmeData seckey )
{
    int rc = 0;
    int i;
    const char *s, *s2, *sx;

    fail_on_pending_request( c );
    c->pending = 1;

    gpgme_data_release (c->help_data_1); c->help_data_1 = NULL;

    /* create a process object */
    _gpgme_gpg_release (c->gpg); c->gpg = NULL;
    rc = _gpgme_gpg_new ( &c->gpg );
    if (rc)
        goto leave;

    /* We need a special mechanism to get the fd of a pipe here, so
     * that we can use this for the %pubring and %secring parameters.
     * We don't have this yet, so we implement only the adding to the
     * standard keyrings */
    if ( pubkey || seckey ) {
        rc = mk_error (Not_Implemented);
        goto leave;
    }

    _gpgme_gpg_set_status_handler ( c->gpg, genkey_status_handler, c );

    /* build the commandline */
    _gpgme_gpg_add_arg ( c->gpg, "--gen-key" );
    if ( c->use_armor )
        _gpgme_gpg_add_arg ( c->gpg, "--armor" );
    for ( i=0; i < c->verbosity; i++ )
        _gpgme_gpg_add_arg ( c->gpg, "--verbose" );

    if ( !pubkey && !seckey )
        ; /* okay: Add key to the keyrings */
    else if ( !pubkey
              || gpgme_data_get_type (pubkey) != GPGME_DATA_TYPE_NONE ) {
        rc = mk_error (Invalid_Value);
        goto leave;
    }
    else if ( !seckey
              || gpgme_data_get_type (seckey) != GPGME_DATA_TYPE_NONE ) {
        rc = mk_error (Invalid_Value);
        goto leave;
    }
    
    if ( pubkey ) {
        _gpgme_data_set_mode (pubkey, GPGME_DATA_MODE_IN );
        _gpgme_data_set_mode (seckey, GPGME_DATA_MODE_IN );
        /* need some more things here */
    }


    if ( (parms = strstr (parms, "<GnupgKeyParms ")) 
         && (s = strchr (parms, '>'))
         && (sx = strstr (parms, "format=\"internal\""))
         && sx < s
         && (s2 = strstr (s+1, "</GnupgKeyParms>")) ) {
        /* fixme: check that there are no control statements inside */
        rc = gpgme_data_new_from_mem ( &c->help_data_1, s+1, s2-s-1, 1 );
    }
    else 
        rc = mk_error (Invalid_Value);

    if (rc )
        goto leave;
    
    _gpgme_data_set_mode (c->help_data_1, GPGME_DATA_MODE_OUT );
    _gpgme_gpg_add_data (c->gpg, c->help_data_1, 0);

    rc = _gpgme_gpg_spawn ( c->gpg, c );
    
 leave:
    if (rc) {
        c->pending = 0; 
        _gpgme_gpg_release ( c->gpg ); c->gpg = NULL;
    }
    return rc;
}



/**
 * gpgme_op_genkey:
 * @c: the context
 * @parms: XML string with the key parameters
 * @pubkey: Returns the public key
 * @seckey: Returns the secret key
 * 
 * Generate a new key and store the key in the default keyrings if both
 * @pubkey and @seckey are NULL.  If @pubkey and @seckey are given, the newly
 * created key will be returned in these data objects.
 * See gpgme_op_genkey_start() for a description of @parms.
 * 
 * Return value: 0 for success or an error code
 **/
GpgmeError
gpgme_op_genkey( GpgmeCtx c, const char *parms,
                 GpgmeData pubkey, GpgmeData seckey )
{
    int rc = gpgme_op_genkey_start ( c, parms, pubkey, seckey );
    if ( !rc ) {
        gpgme_wait (c, 1);
        c->pending = 0;
    }
    return rc;
}





