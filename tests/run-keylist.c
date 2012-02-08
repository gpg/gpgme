/* run-keylist.c  - Helper to show a key listing.
   Copyright (C) 2008, 2009 g10 Code GmbH

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

#define PGM "run-keylist"

#include "run-support.h"


static int verbose;


static int
show_usage (int ex)
{
  fputs ("usage: " PGM " [options] [USERID]\n\n"
         "Options:\n"
         "  --verbose        run in verbose mode\n"
         "  --openpgp        use the OpenPGP protocol (default)\n"
         "  --cms            use the CMS protocol\n"
         "  --local          use GPGME_KEYLIST_MODE_LOCAL\n"
         "  --extern         use GPGME_KEYLIST_MODE_EXTERN\n"
         "  --sigs           use GPGME_KEYLIST_MODE_SIGS\n"
         "  --sig-notations  use GPGME_KEYLIST_MODE_SIG_NOTATIONS\n"
         "  --ephemeral      use GPGME_KEYLIST_MODE_EPHEMERAL\n"
         "  --validate       use GPGME_KEYLIST_MODE_VALIDATE\n"
         "  --import         import all keys\n"
         , stderr);
  exit (ex);
}


int 
main (int argc, char **argv)
{
  int last_argc = -1;
  gpgme_error_t err;
  gpgme_ctx_t ctx;
  gpgme_keylist_mode_t mode = 0;
  gpgme_key_t key;
  gpgme_keylist_result_t result;
  int import = 0;
  gpgme_key_t keyarray[100];
  int keyidx = 0;
  gpgme_protocol_t protocol = GPGME_PROTOCOL_OpenPGP;

  if (argc)
    { argc--; argv++; }

  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--"))
        {
          argc--; argv++;
          break;
        }
      else if (!strcmp (*argv, "--help"))
        show_usage (0);
      else if (!strcmp (*argv, "--verbose"))
        {
          verbose = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--openpgp"))
        {
          protocol = GPGME_PROTOCOL_OpenPGP;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--cms"))
        {
          protocol = GPGME_PROTOCOL_CMS;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--local"))
        {
          mode |= GPGME_KEYLIST_MODE_LOCAL;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--extern"))
        {
          mode |= GPGME_KEYLIST_MODE_EXTERN;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--sigs"))
        {
          mode |= GPGME_KEYLIST_MODE_SIGS;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--sig-notations"))
        {
          mode |= GPGME_KEYLIST_MODE_SIG_NOTATIONS;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--ephemeral"))
        {
          mode |= GPGME_KEYLIST_MODE_EPHEMERAL;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--validate"))
        {
          mode |= GPGME_KEYLIST_MODE_VALIDATE;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--import"))
        {
          import = 1;
          argc--; argv++;
        }
      else if (!strncmp (*argv, "--", 2))
        show_usage (1);
      
    }          
 
  if (argc > 1)
    show_usage (1);

  init_gpgme (protocol);

  err = gpgme_new (&ctx);
  fail_if_err (err);
  gpgme_set_protocol (ctx, protocol);

  gpgme_set_keylist_mode (ctx, mode);

  err = gpgme_op_keylist_start (ctx, argc? argv[0]:NULL, 0);
  fail_if_err (err);
    
  while (!(err = gpgme_op_keylist_next (ctx, &key)))
    {
      gpgme_user_id_t uid;
      int nuids;
      

      printf ("keyid   : %s\n", key->subkeys?nonnull (key->subkeys->keyid):"?");
      printf ("fpr     : %s\n", key->subkeys?nonnull (key->subkeys->fpr):"?");
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

      if (import)
        {
          if (keyidx < DIM (keyarray)-1)
            keyarray[keyidx++] = key;
          else
            {
              fprintf (stderr, PGM": too many keys in import mode"
                       "- skipping this key\n");
              gpgme_key_unref (key);
            }
        }
      else
        gpgme_key_unref (key);
    }
  if (gpgme_err_code (err) != GPG_ERR_EOF)
    fail_if_err (err);
  err = gpgme_op_keylist_end (ctx);
  fail_if_err (err);
  keyarray[keyidx] = NULL;

  result = gpgme_op_keylist_result (ctx);
  if (result->truncated)
    {
      fprintf (stderr, PGM ": key listing unexpectedly truncated\n");
      exit (1);
    }

  if (import)
    {
      gpgme_import_result_t impres;

      err = gpgme_op_import_keys (ctx, keyarray);
      fail_if_err (err);
      impres = gpgme_op_import_result (ctx);
      if (!impres)
        {
          fprintf (stderr, PGM ": no import result returned\n");
          exit (1);
        }
      print_import_result (impres);
    }

  for (keyidx=0; keyarray[keyidx]; keyidx++)
    gpgme_key_unref (keyarray[keyidx]);

  gpgme_release (ctx);
  return 0;
}
