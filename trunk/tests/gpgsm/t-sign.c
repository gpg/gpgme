/* t-sign.c - Regression test.
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


static void
print_data (GpgmeData dh)
{
#define BUF_SIZE 512
  char buf[BUF_SIZE + 1];
  int ret;
  
  ret = gpgme_data_seek (dh, 0, SEEK_SET);
  if (ret)
    fail_if_err (GPGME_File_Error);
  while ((ret = gpgme_data_read (dh, buf, BUF_SIZE)) > 0)
    fwrite (buf, ret, 1, stdout);
  if (ret < 0)
    fail_if_err (GPGME_File_Error);
}


static void
check_result (GpgmeSignResult result, GpgmeSigMode type)
{
  if (result->invalid_signers)
    {
      fprintf (stderr, "Invalid signer found: %s\n",
	       result->invalid_signers->id);
      exit (1);
    }
  if (!result->signatures || result->signatures->next)
    {
      fprintf (stderr, "Unexpected number of signatures created\n");
      exit (1);
    }
  if (result->signatures->type != type)
    {
      fprintf (stderr, "Wrong type of signature created\n");
      exit (1);
    }
  if (result->signatures->pubkey_algo != GPGME_PK_RSA)
    {
      fprintf (stderr, "Wrong pubkey algorithm reported: %i\n",
	       result->signatures->pubkey_algo);
      exit (1);
    }
  if (result->signatures->hash_algo != GPGME_MD_SHA1)
    {
      fprintf (stderr, "Wrong hash algorithm reported: %i\n",
	       result->signatures->hash_algo);
      exit (1);
    }
  if (result->signatures->class != 0)
    {
      fprintf (stderr, "Wrong signature class reported: %lu\n",
	       result->signatures->class);
      exit (1);
    }
  if (strcmp ("3CF405464F66ED4A7DF45BBDD1E4282E33BDB76E",
	      result->signatures->fpr))
    {
      fprintf (stderr, "Wrong fingerprint reported: %s\n",
	       result->signatures->fpr);
      exit (1);
    }
}


int 
main (int argc, char **argv)
{
  GpgmeCtx ctx;
  GpgmeError err;
  GpgmeData in, out;
  GpgmeSignResult result;

  err = gpgme_engine_check_version (GPGME_PROTOCOL_CMS);
  fail_if_err (err);

  err = gpgme_new (&ctx);
  fail_if_err (err);

  gpgme_set_protocol (ctx, GPGME_PROTOCOL_CMS);
  gpgme_set_textmode (ctx, 1);
  gpgme_set_armor (ctx, 1);

  err = gpgme_data_new_from_mem (&in, "Hallo Leute!\n", 13, 0);
  fail_if_err (err);

  /* First a normal signature.  */
  err = gpgme_data_new (&out);
  fail_if_err (err);
  err = gpgme_op_sign (ctx, in, out, GPGME_SIG_MODE_NORMAL);
  fail_if_err (err);
  result = gpgme_op_sign_result (ctx);
  check_result (result, GPGME_SIG_MODE_NORMAL);
  print_data (out);
  gpgme_data_release (out);
    
  /* Now a detached signature.  */ 
  gpgme_data_rewind (in);
  err = gpgme_data_new (&out);
  fail_if_err (err);
  err = gpgme_op_sign (ctx, in, out, GPGME_SIG_MODE_DETACH);
  fail_if_err (err);
  result = gpgme_op_sign_result (ctx);
  check_result (result, GPGME_SIG_MODE_DETACH);
  print_data (out);
  gpgme_data_release (out);

  gpgme_data_release (in);
  gpgme_release (ctx);
  return 0;
}




