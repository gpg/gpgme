/* t-encrypt-sym.c  - regression test
 *	Copyright (C) 2000 Werner Koch (dd9jn)
 *      Copyright (C) 2001, 2003 g10 Code GmbH
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
  int ret;
  
  ret = gpgme_data_seek (dh, 0, SEEK_SET);
  if (ret)
    fail_if_err (GPGME_File_Error);
  while ((ret = gpgme_data_read (dh, buf, 100)) > 0)
    fwrite (buf, ret, 1, stdout);
  if (ret < 0)
    fail_if_err (GPGME_File_Error);
}

static GpgmeError
passphrase_cb (void *opaque, const char *desc,
	       void **r_hd, const char **result)
{
  if (!desc)
    /* Cleanup by looking at *r_hd.  */
    return 0;

  *result = "abc";
  fprintf (stderr, "%% requesting passphrase for `%s': ", desc);
  fprintf (stderr, "sending `%s'\n", *result);
  
  return 0;
}


int 
main (int argc, char **argv)
{
  GpgmeCtx ctx;
  GpgmeError err;
  GpgmeData plain, cipher;
  const char *text = "Hallo Leute\n";
  char *text2;
  char *p;
  size_t len;

  err = gpgme_engine_check_version (GPGME_PROTOCOL_OpenPGP);
  fail_if_err (err);

  do
    {
      err = gpgme_new (&ctx);
      fail_if_err (err);
      gpgme_set_armor (ctx, 1);

      p = getenv("GPG_AGENT_INFO");
      if (!(p && strchr (p, ':')))
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

      text2 = gpgme_data_release_and_get_mem (plain, &len);
      if (strncmp (text, text2, len))
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


