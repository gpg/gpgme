/* t-genkey.c  - regression test
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


void
dump_data (GpgmeData dh)
{
#define BUF_SIZE 512
  char buffer[BUF_SIZE + 1];
  int bufread;

  gpgme_data_rewind (dh);

  do
    {
      bufread = gpgme_data_read (dh, buffer, BUF_SIZE);
      if (bufread > 0)
	{
	  buffer[bufread] = '\0';
	  printf ("%s", buffer);
	}
    }
  while (bufread > 0);

  if (bufread < 0)
    {
      fprintf (stderr, "%s:%d: gpgme_data_read failed: %s\n",
	       __FILE__, __LINE__, strerror (errno));
      exit (1);
    }
  printf ("\n");
}


/* True if progress function printed something on the screen.  */
int progress_called;

static void
progress (void *self, const char *what, int type, int current, int total)
{
  if (!strcmp (what, "primegen") && !current && !total
      && (type == '.' || type == '+' || type == '!'
	  || type == '^' || type == '<' || type == '>'))
    {
      printf ("%c", type);
      fflush (stdout);
      progress_called = 1;
    }
  else
    {
      fprintf (stderr, "unknown progress `%s' %d %d %d\n", what, type,
	       current, total);
      exit (1);
    }
}


int 
main (int argc, char **argv)
{
  GpgmeCtx ctx;
  GpgmeError err;
  const char *parms = "<GnupgKeyParms format=\"internal\">\n"
    "Key-Type: RSA\n"
    "Key-Length: 1024\n"
    "Name-DN: C=de,O=g10 code,OU=Testlab,CN=Joe 2 Tester\n"
    "Name-Email: joe@foo.bar\n"
    "</GnupgKeyParms>\n";
  GpgmeGenKeyResult result;
  GpgmeData certreq;

  err = gpgme_engine_check_version (GPGME_PROTOCOL_CMS);
  fail_if_err (err);

  err = gpgme_data_new (&certreq);
  fail_if_err (err);

  err = gpgme_new (&ctx);
  fail_if_err (err);

  gpgme_set_protocol (ctx, GPGME_PROTOCOL_CMS);
  gpgme_set_armor (ctx, 1);

  gpgme_set_progress_cb (ctx, progress, NULL);
  
  err = gpgme_op_genkey (ctx, parms, certreq, NULL);
  fail_if_err (err);

  result = gpgme_op_genkey_result (ctx);
  if (!result)
    {
      fprintf (stderr, "%s:%d: gpgme_op_genkey_result returns NULL\n",
	       __FILE__, __LINE__);
      exit (1);
    }
  if (progress_called)
    printf ("\n");

  printf ("Generated key: %s (%s)\n", result->fpr ? result->fpr : "none",
	  result->primary ? (result->sub ? "primary, sub" : "primary")
	  : (result->sub ? "sub" : "none"));

  if (result->fpr)
    {
      fprintf (stderr, "%s:%d: generated key has (unexpectdly) a fingerprint\n",
	       __FILE__, __LINE__);
      exit (1);
    }
  if (!result->primary)
    {
      fprintf (stderr, "%s:%d: primary key was not generated\n",
	       __FILE__, __LINE__);
      exit (1);
    }
  if (result->sub)
    {
      fprintf (stderr, "%s:%d: sub key was (unexpectedly) generated\n",
	       __FILE__, __LINE__);
      exit (1);
    }
  gpgme_release (ctx);

  dump_data (certreq);
  gpgme_data_release (certreq);

  return 0;
}
