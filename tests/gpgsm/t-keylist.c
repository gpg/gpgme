/* t-keylist.c  - regression test
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

#include <gpgme.h>

#define fail_if_err(a) do { if(a) {                                       \
                               fprintf (stderr, "%s:%d: GpgmeError %s\n", \
                                __FILE__, __LINE__, gpgme_strerror(a));   \
                                exit (1); }                               \
                             } while(0)

static void
doit ( GpgmeCtx ctx, const char *pattern, int secret )
{
    GpgmeError err;
    GpgmeKey key;

    err = gpgme_op_keylist_start (ctx, pattern, secret );
    fail_if_err (err);
    
    while ( !(err = gpgme_op_keylist_next ( ctx, &key )) ) {
        char *p;
        const char *s;
        int i;

        printf ("<!-- Begin key object (%p) -->\n", key );
        p = gpgme_key_get_as_xml ( key );
        if ( p ) {
            fputs ( p, stdout );
            free (p);
        }
        else
            fputs("<!-- Ooops: gpgme_key_get_as_xml failed -->\n", stdout );

        
        for (i=0; ; i++ ) {
            s = gpgme_key_get_string_attr (key, GPGME_ATTR_KEYID, NULL, i );
            if (!s)
                break;
            printf ("<!-- keyid.%d=%s -->\n", i, s );
            s = gpgme_key_get_string_attr (key, GPGME_ATTR_ALGO, NULL, i );
            printf ("<!-- algo.%d=%s -->\n", i, s );
            s = gpgme_key_get_string_attr (key, GPGME_ATTR_KEY_CAPS, NULL, i );
            printf ("<!-- caps.%d=%s -->\n", i, s );
        }
        for (i=0; ; i++ ) {
            s = gpgme_key_get_string_attr (key, GPGME_ATTR_NAME, NULL, i );
            if (!s)
                break;
            printf ("<!-- name.%d=%s -->\n", i, s );
            s = gpgme_key_get_string_attr (key, GPGME_ATTR_EMAIL, NULL, i );
            printf ("<!-- email.%d=%s -->\n", i, s );
            s = gpgme_key_get_string_attr (key, GPGME_ATTR_COMMENT, NULL, i );
            printf ("<!-- comment.%d=%s -->\n", i, s );
        }
        
        fputs ("<!-- usable for:", stdout );
        if ( gpgme_key_get_ulong_attr (key, GPGME_ATTR_CAN_ENCRYPT, NULL, 0 ))
            fputs (" encryption", stdout);
        if ( gpgme_key_get_ulong_attr (key, GPGME_ATTR_CAN_SIGN, NULL, 0 ))
            fputs (" signing", stdout);
        if ( gpgme_key_get_ulong_attr (key, GPGME_ATTR_CAN_CERTIFY, NULL, 0 ))
            fputs (" certification", stdout);
        fputs (" -->\n", stdout );

        printf ("<!-- End key object (%p) -->\n", key );
        gpgme_key_release (key);
    }
    if ( err != GPGME_EOF )
        fail_if_err (err);

    {
      char *p;

      p = gpgme_get_op_info (ctx, 0);
      if (p)
        {
          fputs ("<!-- begin operation info -->\n", stdout);
          fputs (p, stdout);
          fputs ("<!-- end operation info -->\n", stdout);
          free (p);
        }
    }
}


/* 
 * Check that there are no problems when we are using two context for
 * listing keys. 
 */
static void
check_two_contexts (void)
{
    GpgmeError err;
    GpgmeCtx ctx1, ctx2;
    GpgmeKey key;
	
    err = gpgme_new(&ctx1);
    fail_if_err (err);
    gpgme_set_protocol (ctx1, GPGME_PROTOCOL_CMS);

    err = gpgme_op_keylist_start(ctx1, "", 1);
    fail_if_err (err);
    err = gpgme_new(&ctx2); fail_if_err (err);
    gpgme_set_protocol (ctx2, GPGME_PROTOCOL_CMS);
    err = gpgme_op_keylist_start(ctx2, "", 1);
    fail_if_err (err);

    while ( (err=gpgme_op_keylist_next(ctx2, &key)) != GPGME_EOF) {
        gpgme_key_release (key);
    }
    if (err != GPGME_EOF)
        fail_if_err (err);
    while ( (err=gpgme_op_keylist_next(ctx1, &key)) != GPGME_EOF) {
        gpgme_key_release (key);
    }
    if (err != GPGME_EOF)
        fail_if_err (err);
}

int 
main (int argc, char **argv )
{
    GpgmeCtx ctx;
    GpgmeError err;
    int loop = 0;
    int secret = 0;
    const char *pattern;

    if( argc ) {
        argc--; argv++;
    }
    
    if (argc && !strcmp( *argv, "--loop" ) ) {
        loop = 1;
        argc--; argv++;
    }
    if (argc && !strcmp( *argv, "--secret" ) ) {
        secret = 1;
        argc--; argv++;
    }
    pattern = argc? *argv : NULL;

    err = gpgme_engine_check_version (GPGME_PROTOCOL_CMS);
    fail_if_err (err);

    err = gpgme_new (&ctx);
    fail_if_err (err);
    gpgme_set_protocol (ctx, GPGME_PROTOCOL_CMS);

    gpgme_set_keylist_mode (ctx, 1); /* no validity calculation */
    do {
        fprintf (stderr, "** pattern=`%s'\n", pattern );
        doit ( ctx, pattern, secret );
    } while ( loop );
    gpgme_release (ctx);

    check_two_contexts ();

    return 0;
}
