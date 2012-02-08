/* cms-decrypt.c  - Helper to debug the decrupt operation.
   Copyright (C) 2008 g10 Code GmbH

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
   License along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

/* We need to include config.h so that we know whether we are building
   with large file system (LFS) support. */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <gpgme.h>

#define PGM "cms-decrypt"

#include "t-support.h"

static const char *
nonnull (const char *s)
{
  return s? s :"[none]";
}


int 
main (int argc, char **argv)
{
  gpgme_error_t err;
  gpgme_ctx_t ctx;
  gpgme_data_t in, out;
  gpgme_decrypt_result_t result;
  gpgme_recipient_t recp;

  if (argc)
    { argc--; argv++; }

  if (argc != 1)
    {
      fputs ("usage: " PGM " FILE\n", stderr);
      exit (1);
    }

  init_gpgme (GPGME_PROTOCOL_CMS);

  err = gpgme_new (&ctx);
  fail_if_err (err);
  gpgme_set_protocol (ctx, GPGME_PROTOCOL_CMS);


  err = gpgme_data_new_from_file (&in, *argv, 1);
  fail_if_err (err);

  err = gpgme_data_new (&out);
  fail_if_err (err);

  err = gpgme_op_decrypt (ctx, in, out);
  printf ("gpgme_op_decrypt: %s <%s> (%u)\n",
          gpgme_strerror (err), gpgme_strsource (err), err);
  result = gpgme_op_decrypt_result (ctx);
  if (!result)
    {
      fputs (PGM ": error: decryption result missing\n", stderr);
      exit (1);
    }
  
  printf ("unsupported_algorithm: %s\n", 
          nonnull (result->unsupported_algorithm));
  printf ("wrong_key_usage: %u\n",  result->wrong_key_usage);
  printf ("file_name: %s\n", nonnull (result->file_name));
  for (recp = result->recipients; recp; recp = recp->next)
    {
      printf ("recipient.status: %s <%s> (%u)\n",
              gpgme_strerror (recp->status), gpgme_strsource (recp->status),
              recp->status);
      printf ("recipient.pkalgo: %d\n", recp->pubkey_algo);
      printf ("recipient.keyid : %s\n", nonnull (recp->keyid));
    }

  if (!err)
    {
      puts ("plaintext:");
      print_data (out);
      gpgme_data_release (out);
    }

  gpgme_data_release (in);

  gpgme_release (ctx);
  return 0;
}
