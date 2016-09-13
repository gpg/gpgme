/* t-export.c - Regression test.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2003, 2004 g10 Code GmbH

   This file is part of GPGME.

   GPGME is free software; you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   GPGME is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

/* We need to include config.h so that we know whether we are building
   with large file system (LFS) support. */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <gpgme.h>
#include "t-support.h"


int
main (void)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_data_t out;
  const char *pattern1[] = { "DFN Top Level Certification Authority", NULL };
  const char *pattern2[] = { "3CF405464F66ED4A7DF45BBDD1E4282E33BDB76E",
                             "DFN Server Certification Authority",
                             NULL };

  init_gpgme (GPGME_PROTOCOL_CMS);

  err = gpgme_new (&ctx);
  fail_if_err (err);
  gpgme_set_protocol (ctx, GPGME_PROTOCOL_CMS);

  gpgme_set_armor (ctx, 1);

  /* Check exporting of one certificate. */
  err = gpgme_data_new (&out);
  fail_if_err (err);
  err = gpgme_op_export_ext (ctx, pattern1, 0, out);
  fail_if_err (err);

  fflush (NULL);
  fputs ("Begin Result:\n", stdout);
  print_data (out);
  fputs ("End Result.\n", stdout);

  gpgme_data_release (out);

  /* Check exporting of 2 certificates. */
  err = gpgme_data_new (&out);
  fail_if_err (err);
  err = gpgme_op_export_ext (ctx, pattern2, 0, out);
  fail_if_err (err);

  fflush (NULL);
  fputs ("Begin Result:\n", stdout);
  print_data (out);
  fputs ("End Result.\n", stdout);

  gpgme_data_release (out);


  gpgme_release (ctx);

  return 0;
}
