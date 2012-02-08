/* cms-keylist.c  - Helper to show a key listing.
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

#define PGM "cms-keylist"

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
  gpgme_key_t key;
  gpgme_keylist_result_t result;

  if (argc)
    { argc--; argv++; }

  if (argc > 1)
    {
      fputs ("usage: " PGM " [USERID]\n", stderr);
      exit (1);
    }

  init_gpgme (GPGME_PROTOCOL_CMS);

  err = gpgme_new (&ctx);
  fail_if_err (err);
  gpgme_set_protocol (ctx, GPGME_PROTOCOL_CMS);

  gpgme_set_keylist_mode (ctx, (gpgme_get_keylist_mode (ctx)
                                | GPGME_KEYLIST_MODE_VALIDATE));

  err = gpgme_op_keylist_start (ctx, argc? argv[0]:NULL, 0);
  fail_if_err (err);
    
  while (!(err = gpgme_op_keylist_next (ctx, &key)))
    {
      gpgme_user_id_t uid;
      int nuids;
      
      for (nuids=0, uid=key->uids; uid; uid = uid->next)
        nuids++;

      printf ("serial  : %s\n", nonnull (key->issuer_serial));
      printf ("issuer  : %s\n", nonnull (key->issuer_name));
      printf ("chain-id: %s\n", nonnull (key->chain_id));
      printf ("caps    : %s%s%s%s\n",
              key->can_encrypt? "e":"",
              key->can_sign? "s":"",
              key->can_certify? "c":"",
              key->can_authenticate? "a":"");
      printf ("flags   :%s%s%s%s%s%s\n",
              key->secret? " secret":"",
              key->revoked? " revoked":"",
              key->expired? " expired":"",
              key->disabled? " disabled":"",
              key->invalid? " invalid":"",
              key->is_qualified? " qualifid":"");
      for (nuids=0, uid=key->uids; uid; uid = uid->next, nuids++)
        {
          printf ("userid %d: %s\n", nuids, nonnull(uid->uid));
          printf ("valid  %d: %s\n", nuids, 
                  uid->validity == GPGME_VALIDITY_UNKNOWN? "unknown":
                  uid->validity == GPGME_VALIDITY_UNDEFINED? "undefined":
                  uid->validity == GPGME_VALIDITY_NEVER? "never":
                  uid->validity == GPGME_VALIDITY_MARGINAL? "marginal":
                  uid->validity == GPGME_VALIDITY_FULL? "full":
                  uid->validity == GPGME_VALIDITY_ULTIMATE? "ultimate": "[?]");
        }

      putchar ('\n');

      gpgme_key_unref (key);
    }
  if (gpgme_err_code (err) != GPG_ERR_EOF)
    fail_if_err (err);
  err = gpgme_op_keylist_end (ctx);
  fail_if_err (err);

  result = gpgme_op_keylist_result (ctx);
  if (result->truncated)
    {
      fprintf (stderr, PGM ": key listing unexpectedly truncated\n");
      exit (1);
    }

  gpgme_release (ctx);
  return 0;
}
