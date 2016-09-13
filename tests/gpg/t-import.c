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
check_result (gpgme_import_result_t result, const char *fpr, int secret)
{
  if (result->considered != 1 && (secret && result->considered != 3))
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
  if ((secret && result->imported != 0)
      || (!secret && (result->imported != 0 && result->imported != 1)))
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
  if ((secret && (result->unchanged != 0 && result->unchanged != 1))
      || (!secret && ((result->imported == 0 && result->unchanged != 1)
		      || (result->imported == 1 && result->unchanged != 0))))
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
  if ((secret
       && ((result->secret_imported == 0 && result->new_signatures != 0)
	   || (result->secret_imported == 1 && result->new_signatures > 1)))
      || (!secret && result->new_signatures != 0))
    {
      fprintf (stderr, "Unexpected number of new signatures %i\n",
	       result->new_signatures);
      if (result->new_signatures == 2)
        fprintf (stderr, "### ignored due to gpg 1.3.4 problems\n");
      else
        exit (1);
    }
  if (result->new_revocations != 0)
    {
      fprintf (stderr, "Unexpected number of new revocations %i\n",
	       result->new_revocations);
      exit (1);
    }
  if ((secret && result->secret_read != 1 && result->secret_read != 3)
      || (!secret && result->secret_read != 0))
    {
      fprintf (stderr, "Unexpected number of secret keys read %i\n",
	       result->secret_read);
      exit (1);
    }
  if ((secret && result->secret_imported != 0 && result->secret_imported != 1
       && result->secret_imported != 2)
      || (!secret && result->secret_imported != 0))
    {
      fprintf (stderr, "Unexpected number of secret keys imported %i\n",
	       result->secret_imported);
      exit (1);
    }
  if ((secret
       && ((result->secret_imported == 0 && result->secret_unchanged != 1
	    && result->secret_unchanged != 2)
	   || (result->secret_imported == 1 && result->secret_unchanged != 0)))
      || (!secret && result->secret_unchanged != 0))
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
  if (secret)
    {
      if (!result->imports
	  || (result->imports->next && result->imports->next->next))
	{
	  fprintf (stderr, "Unexpected number of status reports\n");
	  exit (1);
	}
    }
  else
    {
      if (!result->imports || result->imports->next)
	{
	  fprintf (stderr, "Unexpected number of status reports\n");
	  exit (1);
	}
    }
  if (strcmp (fpr, result->imports->fpr))
    {
      fprintf (stderr, "Unexpected fingerprint %s\n",
	       result->imports->fpr);
      exit (1);
    }
  if (result->imports->next && strcmp (fpr, result->imports->next->fpr))
    {
      fprintf (stderr, "Unexpected fingerprint on second status %s\n",
	       result->imports->next->fpr);
      exit (1);
    }
  if (result->imports->result != 0)
    {
      fprintf (stderr, "Unexpected status result %s\n",
	       gpgme_strerror (result->imports->result));
      exit (1);
    }
#if 0
  if (secret)
    {
      if (result->secret_imported == 0)
	{
	  if (result->imports->status != GPGME_IMPORT_SECRET)
	    {
	      fprintf (stderr, "Unexpected status %i\n",
		       result->imports->status);
	      exit (1);
	    }
	}
      else
	{
	  if (result->imports->status
	      != (GPGME_IMPORT_SECRET | GPGME_IMPORT_NEW)
	      || (result->imports->next
		  && result->imports->next->status != GPGME_IMPORT_SIG))
	    {
	      fprintf (stderr, "Unexpected status %i\n",
		       result->imports->status);
	      exit (1);
	    }
	}
    }
  else
    {
      if ((result->imported == 0 && result->imports->status != 0)
	  || (result->imported == 1
	      && result->imports->status != GPGME_IMPORT_NEW))
	{
	  fprintf (stderr, "Unexpected status %i\n",
		   result->imports->status);
	  exit (1);
	}
    }
#endif
}


int
main (int argc, char *argv[])
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_data_t in;
  gpgme_import_result_t result;
  char *pubkey_1_asc = make_filename ("pubkey-1.asc");
  char *seckey_1_asc = make_filename ("seckey-1.asc");

  (void)argc;
  (void)argv;

  init_gpgme (GPGME_PROTOCOL_OpenPGP);

  err = gpgme_new (&ctx);
  fail_if_err (err);

  err = gpgme_data_new_from_file (&in, pubkey_1_asc, 1);
  free (pubkey_1_asc);
  fail_if_err (err);

  err = gpgme_op_import (ctx, in);
  fail_if_err (err);
  result = gpgme_op_import_result (ctx);
  check_result (result, "ADAB7FCC1F4DE2616ECFA402AF82244F9CD9FD55", 0);
  gpgme_data_release (in);

  err = gpgme_data_new_from_file (&in, seckey_1_asc, 1);
  free (seckey_1_asc);
  fail_if_err (err);

  err = gpgme_op_import (ctx, in);
  fail_if_err (err);
  result = gpgme_op_import_result (ctx);
  check_result (result, "ADAB7FCC1F4DE2616ECFA402AF82244F9CD9FD55", 1);
  gpgme_data_release (in);

  gpgme_release (ctx);
  return 0;
}
