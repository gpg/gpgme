/* t-genkey.c  - regression test
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
progress ( void *self, const char *what, int type, int current, int total)
{
    fprintf (stderr, "progress `%s' %d %d %d\n", what, type, current, total);
}


int 
main (int argc, char **argv )
{
    GpgmeCtx ctx;
    GpgmeError err;
    const char *format;
    char *parms;
    int count = 0;

  do {
    err = gpgme_new (&ctx);
    fail_if_err (err);

    gpgme_set_progress_cb (ctx, progress, NULL);

    format = "<GnupgKeyParms format=\"internal\">\n"
             "Key-Type: DSA\n"
             "Key-Length: 1024\n"
             "Subkey-Type: ELG-E\n"
             "Subkey-Length: 1024\n"
             "Name-Real: Joe Tester\n"
             "Name-Comment: (pp=abc,try=%d)\n"
             "Name-Email: joe@foo.bar\n"
             "Expire-Date: 0\n"
             "Passphrase: abc\n"
             "</GnupgKeyParms>\n";
    parms = malloc ( strlen (format) + 1 + 20 );
    if (!parms)
        exit (8);
    sprintf (parms, format, ++count );
    err = gpgme_op_genkey (ctx, parms, NULL, NULL );
    fail_if_err (err);
    free (parms);

    gpgme_release (ctx);
  } while ( argc > 1 && !strcmp( argv[1], "--loop" ) );
   
    return 0;
}



