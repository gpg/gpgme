/* t-decrypt-verify.c - Regression test.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003 g10 Code GmbH

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
          fprintf (stderr, "%s:%d: gpgme_error_t %s\n",		\
                   __FILE__, __LINE__, gpgme_strerror (err));   \
          exit (1);						\
        }							\
    }								\
  while (0)


static void
print_data (gpgme_data_t dh)
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


static gpgme_error_t
passphrase_cb (void *opaque, const char *desc, void **hd, const char **result)
{
  /* Cleanup by looking at *hd.  */
  if (!desc)
    return 0;

  *result = "abc";
  return 0;
}


static char *
make_filename (const char *fname)
{
  const char *srcdir = getenv ("srcdir");
  char *buf;

  if (!srcdir)
    srcdir = ".";
  buf = malloc (strlen(srcdir) + strlen(fname) + 2);
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


static void
check_verify_result (gpgme_verify_result_t result, int summary, char *fpr,
		     gpgme_error_t status)
{
  gpgme_signature_t sig;

  sig = result->signatures;
  if (!sig || sig->next)
    {
      fprintf (stderr, "%s:%i: Unexpected number of signatures\n",
	       __FILE__, __LINE__);
      exit (1);
    }
  if (sig->summary != summary)
    {
      fprintf (stderr, "%s:%i: Unexpected signature summary: 0x%x\n",
	       __FILE__, __LINE__, sig->summary);
      exit (1);
    }
  if (strcmp (sig->fpr, fpr))
    {
      fprintf (stderr, "%s:%i: Unexpected fingerprint: %s\n",
	       __FILE__, __LINE__, sig->fpr);
      exit (1);
    }
  if (sig->status != status)
    {
      fprintf (stderr, "%s:%i: Unexpected signature status: %s\n",
	       __FILE__, __LINE__, gpgme_strerror (sig->status));
      exit (1);
    }
  if (sig->notations)
    {
      fprintf (stderr, "%s:%i: Unexpected notation data\n",
	       __FILE__, __LINE__);
      exit (1);
    }
  if (sig->wrong_key_usage)
    {
      fprintf (stderr, "%s:%i: Unexpectedly wrong key usage\n",
	       __FILE__, __LINE__);
      exit (1);
    }
  if (sig->validity != GPGME_VALIDITY_UNKNOWN)
    {
      fprintf (stderr, "%s:%i: Unexpected validity: %i\n",
	       __FILE__, __LINE__, sig->validity);
      exit (1);
    }
  if (sig->validity_reason != GPGME_No_Error)
    {
      fprintf (stderr, "%s:%i: Unexpected validity reason: %s\n",
	       __FILE__, __LINE__, gpgme_strerror (sig->validity_reason));
      exit (1);
    }
}


int 
main (int argc, char *argv[])
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_data_t in, out;
  gpgme_decrypt_result_t decrypt_result;
  gpgme_verify_result_t verify_result;
  const char *cipher_2_asc = make_filename ("cipher-2.asc");
  char *agent_info;

  err = gpgme_new (&ctx);
  fail_if_err (err);

  agent_info = getenv("GPG_AGENT_INFO");
  if (!(agent_info && strchr (agent_info, ':')))
    gpgme_set_passphrase_cb (ctx, passphrase_cb, NULL);

  err = gpgme_data_new_from_file (&in, cipher_2_asc, 1);
  fail_if_err (err);
  err = gpgme_data_new (&out);
  fail_if_err (err);

  err = gpgme_op_decrypt_verify (ctx, in, out);
  fail_if_err (err);
  decrypt_result = gpgme_op_decrypt_result (ctx);
  if (decrypt_result->unsupported_algorithm)
    {
      fprintf (stderr, "%s:%i: unsupported algorithm: %s\n",
	       __FILE__, __LINE__, decrypt_result->unsupported_algorithm);
      exit (1);
    }    
  print_data (out);
  verify_result = gpgme_op_verify_result (ctx);
  check_verify_result (verify_result, 0,
		       "A0FF4590BB6122EDEF6E3C542D727CC768697734",
		       GPGME_No_Error);

  gpgme_data_release (in);
  gpgme_data_release (out);
  gpgme_release (ctx);
  return 0;
}


