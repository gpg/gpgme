/* t-import.c  - regression test
 *      Copyright (C) 2000 Werner Koch
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
make_filename (const char *fname)
{
  const char *srcdir = getenv ("srcdir");
  char *buf;

  if (!srcdir)
    srcdir = ".";
  buf = malloc (strlen(srcdir) + strlen(fname) + 2 );
  if (!buf)
    {
      fprintf (stderr, "%s:%d: could not allocate string: %s\n",
	       __FILE__, __LINE__, strerror (errno));
      exit (1);
    }
  strcpy (buf, srcdir);
  strcat (buf, "/");
  strcat (buf, fname);
  return buf;
}

int 
main (int argc, char **argv)
{
  GpgmeCtx ctx;
  GpgmeError err;
  GpgmeData in;
  const char *cert_1 = make_filename ("cert_dfn_pca01.der");
  const char *cert_2 = make_filename ("cert_dfn_pca15.der");

  do
    {
      err = gpgme_new (&ctx);
      fail_if_err (err);
      gpgme_set_protocol (ctx, GPGME_PROTOCOL_CMS);

      err = gpgme_data_new_from_file (&in, cert_1, 1);
      fail_if_err (err);

      err = gpgme_op_import (ctx, in);
      fail_if_err (err);

      gpgme_data_release (in);

      err = gpgme_data_new_from_file (&in, cert_2, 1);
      fail_if_err (err);
    
      err = gpgme_op_import (ctx, in);
      fail_if_err (err);

      gpgme_data_release (in);
      gpgme_release (ctx);
    }
  while (argc > 1 && !strcmp (argv[1], "--loop"));
   
  return 0;
}
