/* t-encrypt.c  - regression test
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

struct passphrase_cb_info_s {
    GpgmeCtx c;
    int did_it;
};


#define fail_if_err(a) do { if(a) { int my_errno = errno; \
            fprintf (stderr, "%s:%d: GpgmeError %s\n", \
                 __FILE__, __LINE__, gpgme_strerror(a));   \
            if ((a) == GPGME_File_Error)                       \
                   fprintf (stderr, "\terrno=`%s'\n", strerror (my_errno)); \
                   exit (1); }                               \
                             } while(0)

static void
print_op_info (GpgmeCtx ctx)
{
  char *str = gpgme_get_op_info (ctx, 0);

  if (!str)
    puts ("<!-- no operation info available -->");
  else
    {
      puts (str);
      free (str);
    }
}


static void
print_data (GpgmeData dh)
{
  char buf[100];
  int ret;
  
  ret = gpgme_data_seek (dh, 0, SEEK_SET);
  if (ret)
    fail_if_err (GPGME_File_Error);
  while ((ret = gpgme_data_read (dh, buf, 100)) > 0)
    fwrite (buf, ret, 1, stdout);
  if (ret < 0)
    fail_if_err (GPGME_File_Error);
}


static const char *
passphrase_cb ( void *opaque, const char *desc, void **r_hd )
{
    const char *pass;

    if ( !desc ) {
        /* cleanup by looking at *r_hd */

        
        return NULL;
    }

    pass = "abc";
    fprintf (stderr, "%% requesting passphrase for `%s': ", desc );
    fprintf (stderr, "sending `%s'\n", pass );

    return pass;
}


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

int 
main (int argc, char **argv )
{
    GpgmeCtx ctx;
    GpgmeError err;
    GpgmeData in, out, pwdata = NULL;
    struct passphrase_cb_info_s info;
    const char *cipher_1_asc = mk_fname ("cipher-1.asc");
    char *p;

  do {
    err = gpgme_new (&ctx);
    fail_if_err (err);

    p = getenv("GPG_AGENT_INFO");
    if (!(p && strchr (p, ':')))
      {
        memset ( &info, 0, sizeof info );
        info.c = ctx;
        gpgme_set_passphrase_cb ( ctx, passphrase_cb, &info );
      } 

    err = gpgme_data_new_from_file ( &in, cipher_1_asc, 1 );
    fail_if_err (err);

    err = gpgme_data_new ( &out );
    fail_if_err (err);

    err = gpgme_op_decrypt (ctx, in, out );
    fail_if_err (err);

    fflush (NULL);
    fputs ("Begin Result:\n", stdout );
    print_data (out);
    fputs ("End Result.\n", stdout );
   
    gpgme_data_release (in);
    gpgme_data_release (out);
    gpgme_data_release (pwdata);
    gpgme_release (ctx);
  } while ( argc > 1 && !strcmp( argv[1], "--loop" ) );
   
    return 0;
}


