/* delete.c -  delete a key 
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
#include <time.h>
#include <assert.h>

#include "util.h"
#include "context.h"
#include "ops.h"
#include "key.h"

static void
delete_status_handler ( GpgmeCtx ctx, GpgStatusCode code, char *args )
{
    if ( ctx->out_of_core )
        return;

    switch (code) {
      case STATUS_EOF:
        break;

      default:
        /* ignore all other codes */
        break;
    }
}


GpgmeError
gpgme_op_delete_start ( GpgmeCtx c, const GpgmeKey key, int allow_secret )
{
    GpgmeError rc = 0;
    int i;
    const char *s;

    fail_on_pending_request( c );
    c->pending = 1;

    if (!key) {
        rc = mk_error (Invalid_Value);
        goto leave;
    }

    if ( c->gpg ) {
        _gpgme_gpg_release ( c->gpg ); 
        c->gpg = NULL;
    }
    
    rc = _gpgme_gpg_new ( &c->gpg );
    if (rc)
        goto leave;

    _gpgme_gpg_set_status_handler ( c->gpg, delete_status_handler, c );

    /* build the commandline */
    for ( i=0; i < c->verbosity; i++ )
        _gpgme_gpg_add_arg ( c->gpg, "--verbose" );
    _gpgme_gpg_add_arg ( c->gpg, allow_secret?
                         "--delete-secret-and-public-key":"--delete-key" );
    
    _gpgme_gpg_add_arg ( c->gpg, "--" );
    s = gpgme_key_get_string_attr ( key, GPGME_ATTR_FPR, NULL, 0 );
    if (!s) {
        rc = mk_error (Invalid_Key);
        goto leave;
    }
    _gpgme_gpg_add_arg ( c->gpg, s );

    /* do it */
    rc = _gpgme_gpg_spawn ( c->gpg, c );

 leave:
    if (rc) {
        c->pending = 0; 
        _gpgme_gpg_release ( c->gpg ); c->gpg = NULL;
    }
    return rc;
}


/**
 * gpgme_op_delete:
 * @c: Context 
 * @key: A Key Object
 * @allow_secret: Allow secret key delete
 * 
 * Delete the give @key from the key database.  To delete a secret
 * along with the public key, @allow_secret must be true.
 * 
 * Return value: 0 on success or an error code.
 **/
GpgmeError
gpgme_op_delete ( GpgmeCtx c, const GpgmeKey key, int allow_secret )
{
    int rc = gpgme_op_delete_start ( c, key, allow_secret );
    if ( !rc ) {
        gpgme_wait (c, 1);
        c->pending = 0;
        /* FIXME: check for success */
    }
    return rc;
}




