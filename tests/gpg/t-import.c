/* t-import.c  - regression test
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2003 g10 Code GmbH

   This file is part of GPGME.
 
   GPGME is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
 
   GPGME is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with GPGME; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <gpgme.h>


#define fail_if_err(err)					\
  do								\
    {								\
      if (err)							\
        {							\
          fprintf (stderr, "%s:%d: GpgmeError %s\n",		\
                   __FILE__, __LINE__, gpgme_strerror (err));   \
          exit (1);						\
        }							\
    }								\
  while (0)


static char *
mk_fname (const char *fname)
{
  const char *srcdir = getenv ("srcdir");
  char *buf;

  if (!srcdir)
    srcdir = ".";
  buf = malloc (strlen(srcdir) + strlen(fname) + 2);
  if (!buf) 
    exit (8);
  strcpy (buf, srcdir);
  strcat (buf, "/");
  strcat (buf, fname);
  return buf;
}


void
check_result (GpgmeImportResult result, char *fpr, int secret)
{
  if (result->considered != 1)
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
  if ((secret && result->unchanged != 0)
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
  if ((secret && result->secret_read != 1)
      || (!secret && result->secret_read != 0))
    {
      fprintf (stderr, "Unexpected number of secret keys read %i\n",
	       result->secret_read);
      exit (1);
    }
  if ((secret && result->secret_imported != 0 && result->secret_imported != 1)
      || (!secret && result->secret_imported != 0))
    {
      fprintf (stderr, "Unexpected number of secret keys imported %i\n",
	       result->secret_imported);
      exit (1);
    }
  if ((secret
       && ((result->secret_imported == 0 && result->secret_unchanged != 1)
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
  if (!result->imports || result->imports->next)
    {
      fprintf (stderr, "Unexpected number of status reports\n");
      exit (1);
    }
  if (strcmp (fpr, result->imports->fpr))
    {
      fprintf (stderr, "Unexpected fingerprint %s\n",
	       result->imports->fpr);
      exit (1);
    }
  if (result->imports->result != 0)
    {
      fprintf (stderr, "Unexpected status result %s\n",
	       gpgme_strerror (result->imports->result));
      exit (1);
    }
  if ((secret
       && ((result->secret_imported == 0
	    && result->imports->status != GPGME_IMPORT_SECRET)
	   || (result->secret_imported == 1
	       && result->imports->status != (GPGME_IMPORT_SECRET | GPGME_IMPORT_NEW))))
      || (!secret
	  && ((result->imported == 0 && result->imports->status != 0)
	      || (result->imported == 1
		  && result->imports->status != GPGME_IMPORT_NEW))))
    {
      fprintf (stderr, "Unexpected status %i\n",
	       result->imports->status);
      exit (1);
    }
}


int 
main (int argc, char **argv)
{
  GpgmeCtx ctx;
  GpgmeError err;
  GpgmeData in;
  GpgmeImportResult result;
  const char *pubkey_1_asc = mk_fname ("pubkey-1.asc");
  const char *seckey_1_asc = mk_fname ("seckey-1.asc");

  err = gpgme_new (&ctx);
  fail_if_err (err);

  err = gpgme_data_new_from_file (&in, pubkey_1_asc, 1);
  fail_if_err (err);

  err = gpgme_op_import (ctx, in);
  fail_if_err (err);
  result = gpgme_op_import_result (ctx);
  check_result (result, "ADAB7FCC1F4DE2616ECFA402AF82244F9CD9FD55", 0);
  gpgme_data_release (in);

  err = gpgme_data_new_from_file (&in, seckey_1_asc, 1);
  fail_if_err (err);

  err = gpgme_op_import (ctx, in);
  fail_if_err (err);
  result = gpgme_op_import_result (ctx);
  check_result (result, "ADAB7FCC1F4DE2616ECFA402AF82244F9CD9FD55", 1);
  gpgme_data_release (in);

  gpgme_release (ctx);
  return 0;
}
