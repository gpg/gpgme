/* t-trustlist.c  - regression test
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../gpgme/gpgme.h"

#define fail_if_err(a) do { if(a) {                                       \
                               fprintf (stderr, "%s:%d: GpgmeError %s\n", \
                                __FILE__, __LINE__, gpgme_strerror(a));   \
                                exit (1); }                               \
                             } while(0)

static void
doit ( GpgmeCtx ctx, const char *pattern )
{
    GpgmeError err;
    GpgmeTrustItem item;

    err = gpgme_op_trustlist_start (ctx, pattern, 0 );
    fail_if_err (err);
    
    while ( !(err = gpgme_op_trustlist_next ( ctx, &item )) ) {
        printf ("l=%d k=%s t=%d o=%s v=%s u=%s\n",
        gpgme_trust_item_get_int_attr    (item, GPGME_ATTR_LEVEL, NULL, 0 ),
        gpgme_trust_item_get_string_attr (item, GPGME_ATTR_KEYID, NULL, 0 ),
        gpgme_trust_item_get_int_attr    (item, GPGME_ATTR_TYPE, NULL, 0 ),
        gpgme_trust_item_get_string_attr (item, GPGME_ATTR_OTRUST, NULL, 0 ),
        gpgme_trust_item_get_string_attr (item, GPGME_ATTR_VALIDITY, NULL, 0 ),
        gpgme_trust_item_get_string_attr (item, GPGME_ATTR_USERID, NULL, 0 )
                );
        gpgme_trust_item_release (item);
    }
    if ( err != GPGME_EOF )
        fail_if_err (err);
}


int 
main (int argc, char **argv )
{
    GpgmeCtx ctx;
    GpgmeError err;
    int loop = 0;
    const char *pattern;
    
    if( argc ) {
        argc--; argv++;
    }
    
    if (argc && !strcmp( *argv, "--loop" ) ) {
        loop = 1;
        argc--; argv++;
    }
    pattern = argc? *argv : "alice";

    err = gpgme_new (&ctx);
    fail_if_err (err);
    do {
        fprintf (stderr, "** pattern=`%s'\n", pattern );
        doit ( ctx, pattern );
    } while ( loop );
    gpgme_release (ctx);

    return 0;
}



