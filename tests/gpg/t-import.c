/* t-import.c  - regression test
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
#include <errno.h>

#include <gpgme.h>


#define fail_if_err(a) do { if(a) { int my_errno = errno; \
            fprintf (stderr, "%s:%d: GpgmeError %s\n", \
                 __FILE__, __LINE__, gpgme_strerror(a));   \
            if ((a) == GPGME_File_Error)                       \
                   fprintf (stderr, "\terrno=`%s'\n", strerror (my_errno)); \
                   exit (1); }                               \
                             } while(0)


static char *
mk_fname ( const char *fname )
{
    const char *srcdir = getenv ("srcdir");
    char *buf;

    if (!srcdir)
        srcdir = ".";
    buf = malloc (strlen(srcdir) + strlen(fname) + 2 );
    if (!buf ) 
        exit (8);
    strcpy (buf, srcdir);
    strcat (buf, "/");
    strcat (buf, fname );
    return buf;
}


static void
print_op_info (GpgmeCtx c)
{
  char *s = gpgme_get_op_info (c, 0);

  if (!s)
    puts ("<!-- no operation info available -->");
  else {
    puts (s);
    free (s);
  }
}


int 
main (int argc, char **argv )
{
    GpgmeCtx ctx;
    GpgmeError err;
    GpgmeData in;
    const char *pubkey_1_asc = mk_fname ("pubkey-1.asc");
    const char *seckey_1_asc = mk_fname ("seckey-1.asc");

  do {
    err = gpgme_new (&ctx);
    fail_if_err (err);

    err = gpgme_data_new_from_file ( &in, pubkey_1_asc, 1 );
    fail_if_err (err);

    err = gpgme_op_import (ctx, in );
    fail_if_err (err);
    print_op_info (ctx);

    gpgme_data_release (in);

    err = gpgme_data_new_from_file ( &in, seckey_1_asc, 1 );
    fail_if_err (err);

    err = gpgme_op_import (ctx, in );
    fail_if_err (err);
    print_op_info (ctx);

    gpgme_data_release (in);
    gpgme_release (ctx);
  } while ( argc > 1 && !strcmp( argv[1], "--loop" ) );
   
    return 0;
}


