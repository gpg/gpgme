/* t-import.c - Regression test.
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <gpgme.h>

#include "t-support.h"


void
check_result (gpgme_import_result_t result, const char *fpr, int total,
	      int total_stat)
{
  (void)fpr;

  if (result->considered != total)
    {
      fprintf (stderr, "Unexpected number of considered keys %i\n",
	       result->considered);
      exit (1);
    }
  if (result->no_user_id != 0)
    {
      fprintf (stderr, "Unexpected number of user ids %i\n",
	       result->no_user_id);
      exit (1);
    }
  if (result->imported != 0 && result->imported != 1)
    {
      fprintf (stderr, "Unexpected number of imported keys %i\n",
	       result->imported);
      exit (1);
    }
  if (result->imported_rsa != 0)
    {
      fprintf (stderr, "Unexpected number of imported RSA keys %i\n",
	       result->imported_rsa);
      exit (1);
    }
  if ((result->imported == 0 && result->unchanged != total)
      || (result->imported == 1 && result->unchanged != total - 1))
    {
      fprintf (stderr, "Unexpected number of unchanged keys %i\n",
	       result->unchanged);
      exit (1);
    }
  if (result->new_user_ids != 0)
    {
      fprintf (stderr, "Unexpected number of new user IDs %i\n",
	       result->new_user_ids);
      exit (1);
    }
  if (result->new_sub_keys != 0)
    {
      fprintf (stderr, "Unexpected number of new sub keys %i\n",
	       result->new_sub_keys);
      exit (1);
    }
  if (result->new_signatures != 0)
    {
      fprintf (stderr, "Unexpected number of new signatures %i\n",
	       result->new_signatures);
      exit (1);
    }
  if (result->new_revocations != 0)
    {
      fprintf (stderr, "Unexpected number of new revocations %i\n",
	       result->new_revocations);
      exit (1);
    }
  if (result->secret_read != 0)
    {
      fprintf (stderr, "Unexpected number of secret keys read %i\n",
	       result->secret_read);
      exit (1);
    }
  if (result->secret_imported != 0)
    {
      fprintf (stderr, "Unexpected number of secret keys imported %i\n",
	       result->secret_imported);
      exit (1);
    }
  if (result->secret_unchanged != 0)
    {
      fprintf (stderr, "Unexpected number of secret keys unchanged %i\n",
	       result->secret_unchanged);
      exit (1);
    }
  if (result->not_imported != 0)
    {
      fprintf (stderr, "Unexpected number of secret keys not imported %i\n",
	       result->not_imported);
      exit (1);
    }

  {
    int n;
    gpgme_import_status_t r;

    for (n=0, r=result->imports; r; r=r->next)
      n++;

    if (n != total_stat)
    {
      fprintf (stderr, "Unexpected number of status reports\n");
      exit (1);
    }
  }
}


int
main (void)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_data_t in;
  gpgme_import_result_t result;
  char *cert_1 = make_filename ("cert_dfn_pca01.der");
  char *cert_2 = make_filename ("cert_dfn_pca15.der");

  init_gpgme (GPGME_PROTOCOL_CMS);

  err = gpgme_new (&ctx);
  fail_if_err (err);

  gpgme_set_protocol (ctx, GPGME_PROTOCOL_CMS);

  err = gpgme_data_new_from_file (&in, cert_1, 1);
  free (cert_1);
  fail_if_err (err);

  err = gpgme_op_import (ctx, in);
  fail_if_err (err);
  result = gpgme_op_import_result (ctx);
  check_result (result, "DFA56FB5FC41E3A8921F77AD1622EEFD9152A5AD", 1, 1);
  gpgme_data_release (in);

  err = gpgme_data_new_from_file (&in, cert_2, 1);
  free (cert_2);
  fail_if_err (err);

  err = gpgme_op_import (ctx, in);
  fail_if_err (err);
  result = gpgme_op_import_result (ctx);
  check_result (result, "2C8F3C356AB761CB3674835B792CDA52937F9285", 1, 2);
  gpgme_data_release (in);

  gpgme_release (ctx);
  return 0;
}
