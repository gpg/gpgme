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

#include <gpgme.h>

#define fail_if_err(a) do { if(a) {                                       \
                               fprintf (stderr, "%s:%d: GpgmeError %s\n", \
                                __FILE__, __LINE__, gpgme_strerror(a));   \
                                exit (1); }                               \
                             } while(0)

static void
print_data (GpgmeData dh)
{
  char buf[100];
  size_t nread;
  GpgmeError err;

  err = gpgme_data_rewind (dh);
  fail_if_err (err);
  while (!(err = gpgme_data_read (dh, buf, 100, &nread)))
    fwrite ( buf, nread, 1, stdout );
  if (err != GPGME_EOF) 
    fail_if_err (err);
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


int 
main (int argc, char **argv)
{
  GpgmeCtx ctx;
  GpgmeError err;
  GpgmeData plain, cipher;
  const char *text = "Hallo Leute\n";
  char *text2;
  int i;

  err = gpgme_check_engine ();
  fail_if_err (err);

  do
    {
      err = gpgme_new (&ctx);
      fail_if_err (err);
      gpgme_set_armor (ctx, 1);
      if (!getenv("GPG_AGENT_INFO"))
	gpgme_set_passphrase_cb (ctx, passphrase_cb, NULL);

      err = gpgme_data_new_from_mem (&plain, text, strlen (text), 0);
      fail_if_err (err);

      err = gpgme_data_new (&cipher);
      fail_if_err (err);

      err = gpgme_op_encrypt (ctx, 0, plain, cipher);
      fail_if_err (err);

      fflush (NULL);
      fputs ("Begin Result Encryption:\n", stdout);
      print_data (cipher);
      fputs ("End Result.\n", stdout);

      err = gpgme_data_rewind (cipher);
      fail_if_err (err);

      gpgme_data_release (plain);
      err = gpgme_data_new (&plain);
      fail_if_err (err);

      err = gpgme_op_decrypt (ctx, cipher, plain);
      fail_if_err (err);

      fputs ("Begin Result Decryption:\n", stdout);
      print_data (plain);
      fputs ("End Result.\n", stdout);

      text2 = gpgme_data_release_and_get_mem (plain, &i);
      if (strncmp (text, text2, i))
	{
	  fprintf (stderr, "%s:%d: Wrong plaintext\n", __FILE__, __LINE__);
	  exit (1);
	}

      gpgme_data_release (cipher);
      gpgme_release (ctx);
    }
  while (argc > 1 && !strcmp (argv[1], "--loop"));

  return 0;
}


