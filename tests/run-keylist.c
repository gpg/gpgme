/* run-keylist.c  - Helper to show a key listing.
 * Copyright (C) 2008, 2009 g10 Code GmbH
 *
 * This file is part of GPGME.
 *
 * GPGME is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * GPGME is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <https://gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

/* We need to include config.h so that we know whether we are building
   with large file system (LFS) support. */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <gpgme.h>

#define PGM "run-keylist"

#include "run-support.h"


static int verbose;


static int
show_usage (int ex)
{
  fputs ("usage: " PGM " [options] [USERID_or_FILE]\n\n"
         "Options:\n"
         "  --verbose        run in verbose mode\n"
         "  --openpgp        use the OpenPGP protocol (default)\n"
         "  --cms            use the CMS protocol\n"
         "  --secret         list only secret keys\n"
         "  --with-secret    list pubkeys with secret info filled\n"
         "  --local          use GPGME_KEYLIST_MODE_LOCAL\n"
         "  --extern         use GPGME_KEYLIST_MODE_EXTERN\n"
         "  --sigs           use GPGME_KEYLIST_MODE_SIGS\n"
         "  --tofu           use GPGME_KEYLIST_MODE_TOFU\n"
         "  --sig-notations  use GPGME_KEYLIST_MODE_SIG_NOTATIONS\n"
         "  --ephemeral      use GPGME_KEYLIST_MODE_EPHEMERAL\n"
         "  --validate       use GPGME_KEYLIST_MODE_VALIDATE\n"
         "  --import         import all keys\n"
         "  --offline        use offline mode\n"
         "  --no-trust-check disable automatic trust database check\n"
         "  --from-file      list all keys in the given file\n"
         "  --from-wkd       list key from a web key directory\n"
         "  --require-gnupg  required at least the given GnuPG version\n"
         "  --trust-model    use the specified trust-model\n"
         , stderr);
  exit (ex);
}


static const char *
isotimestr (unsigned long value)
{
  time_t t;
  static char buffer[25+5];
  struct tm *tp;

  if (!value)
    return "none";
  t = value;

  tp = gmtime (&t);
  snprintf (buffer, sizeof buffer, "%04d-%02d-%02d %02d:%02d:%02d",
            1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday,
            tp->tm_hour, tp->tm_min, tp->tm_sec);
  return buffer;
}



int
main (int argc, char **argv)
{
  int last_argc = -1;
  gpgme_error_t err;
  gpgme_ctx_t ctx;
  gpgme_keylist_mode_t mode = 0;
  gpgme_key_t key;
  gpgme_subkey_t subkey;
  gpgme_keylist_result_t result;
  int import = 0;
  gpgme_key_t keyarray[100];
  int keyidx = 0;
  gpgme_protocol_t protocol = GPGME_PROTOCOL_OpenPGP;
  int only_secret = 0;
  int offline = 0;
  int no_trust_check = 0;
  int from_file = 0;
  int from_wkd = 0;
  gpgme_data_t data = NULL;
  char *trust_model = NULL;


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
      else if (!strcmp (*argv, "--secret"))
        {
          only_secret = 1;
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
      else if (!strcmp (*argv, "--tofu"))
        {
          mode |= GPGME_KEYLIST_MODE_WITH_TOFU;
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
      else if (!strcmp (*argv, "--with-secret"))
        {
          mode |= GPGME_KEYLIST_MODE_WITH_SECRET;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--import"))
        {
          import = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--offline"))
        {
          offline = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--no-trust-check"))
        {
          no_trust_check = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--from-file"))
        {
          from_file = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--require-gnupg"))
        {
          argc--; argv++;
          if (!argc)
            show_usage (1);
          gpgme_set_global_flag ("require-gnupg", *argv);
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--from-wkd"))
        {
          argc--; argv++;
          mode |= GPGME_KEYLIST_MODE_LOCATE;
          from_wkd = 1;
        }
      else if (!strcmp (*argv, "--trust-model"))
        {
          argc--; argv++;
          if (!argc)
            show_usage (1);
          trust_model = strdup (*argv);
          argc--; argv++;
        }
      else if (!strncmp (*argv, "--", 2))
        show_usage (1);
    }

  if (argc > 1)
    show_usage (1);
  else if (from_file && !argc)
    show_usage (1);

  init_gpgme (protocol);

  err = gpgme_new (&ctx);
  fail_if_err (err);
  gpgme_set_protocol (ctx, protocol);

  gpgme_set_keylist_mode (ctx, mode);

  gpgme_set_offline (ctx, offline);

  if (no_trust_check)
    {
      err = gpgme_set_ctx_flag (ctx, "no-auto-check-trustdb", "1");
      fail_if_err (err);
    }

  if (trust_model)
    {
      err = gpgme_set_ctx_flag (ctx, "trust-model", trust_model);
      fail_if_err (err);
    }

  if (from_wkd)
    {
      err = gpgme_set_ctx_flag (ctx, "auto-key-locate",
                                "clear,nodefault,wkd");
      fail_if_err (err);
    }

  if (from_file)
    {
      err = gpgme_data_new_from_file (&data, *argv, 1);
      fail_if_err (err);

      err = gpgme_op_keylist_from_data_start (ctx, data, 0);
    }
  else
    err = gpgme_op_keylist_start (ctx, argc? argv[0]:NULL, only_secret);
  fail_if_err (err);

  while (!(err = gpgme_op_keylist_next (ctx, &key)))
    {
      gpgme_user_id_t uid;
      gpgme_tofu_info_t ti;
      gpgme_key_sig_t ks;
      int nuids;
      int nsub;
      int nsigs;

      printf ("keyid   : %s\n", key->subkeys?nonnull (key->subkeys->keyid):"?");
      printf ("caps    : %s%s%s%s\n",
              key->can_encrypt? "e":"",
              key->can_sign? "s":"",
              key->can_certify? "c":"",
              key->can_authenticate? "a":"");
      printf ("flags   :%s%s%s%s%s%s%s%s\n",
              key->secret? " secret":"",
              key->revoked? " revoked":"",
              key->expired? " expired":"",
              key->disabled? " disabled":"",
              key->invalid? " invalid":"",
              key->is_qualified? " qualified":"",
              key->subkeys && key->subkeys->is_de_vs? " de-vs":"",
              key->subkeys && key->subkeys->is_cardkey? " cardkey":"");
      printf ("upd     : %lu (%u)\n", key->last_update, key->origin);

      subkey = key->subkeys;
      for (nsub=0; subkey; subkey = subkey->next, nsub++)
        {
          printf ("fpr   %2d: %s\n", nsub, nonnull (subkey->fpr));
          if (subkey->keygrip)
            printf ("grip  %2d: %s\n", nsub, subkey->keygrip);
          if (subkey->curve)
            printf ("curve %2d: %s\n", nsub, subkey->curve);
          printf ("caps  %2d: %s%s%s%s%s%s\n",
                  nsub,
                  subkey->can_encrypt? "e":"",
                  subkey->can_sign? "s":"",
                  subkey->can_certify? "c":"",
                  subkey->can_authenticate? "a":"",
                  subkey->can_renc? "r":"",
                  subkey->can_timestamp? "t":"");
          printf ("flags %2d:%s%s%s%s%s%s%s%s%s\n",
                  nsub,
                  subkey->secret? " secret":"",
                  subkey->revoked? " revoked":"",
                  subkey->expired? " expired":"",
                  subkey->disabled? " disabled":"",
                  subkey->invalid? " invalid":"",
                  subkey->is_group_owned? " group":"",
                  subkey->is_qualified? " qualified":"",
                  subkey->is_de_vs? " de-vs":"",
                  subkey->is_cardkey? " cardkey":"");
        }
      for (nuids=0, uid=key->uids; uid; uid = uid->next, nuids++)
        {
          printf ("userid %d: %s\n", nuids, nonnull(uid->uid));
          printf ("    mbox: %s\n", nonnull(uid->address));
          if (uid->email && uid->email != uid->address)
            printf ("   email: %s\n", uid->email);
          if (uid->name)
            printf ("    name: %s\n", uid->name);
          if (uid->comment)
            printf ("   cmmnt: %s\n", uid->comment);
          if (uid->uidhash)
            printf (" uidhash: %s\n", uid->uidhash);
          printf ("     upd: %lu (%u)\n", uid->last_update, uid->origin);
          printf ("   valid: %s\n",
                  uid->validity == GPGME_VALIDITY_UNKNOWN? "unknown":
                  uid->validity == GPGME_VALIDITY_UNDEFINED? "undefined":
                  uid->validity == GPGME_VALIDITY_NEVER? "never":
                  uid->validity == GPGME_VALIDITY_MARGINAL? "marginal":
                  uid->validity == GPGME_VALIDITY_FULL? "full":
                  uid->validity == GPGME_VALIDITY_ULTIMATE? "ultimate": "[?]");
          if ((ti = uid->tofu))
            {
              printf ("    tofu: %u (%s)\n", ti->validity,
                      ti->validity == 0? "conflict" :
                      ti->validity == 1? "no history" :
                      ti->validity == 2? "little history" :
                      ti->validity == 3? "enough history" :
                      ti->validity == 4? "lot of history" : "?");
              printf ("  policy: %u (%s)\n", ti->policy,
                      ti->policy == GPGME_TOFU_POLICY_NONE? "none" :
                      ti->policy == GPGME_TOFU_POLICY_AUTO? "auto" :
                      ti->policy == GPGME_TOFU_POLICY_GOOD? "good" :
                      ti->policy == GPGME_TOFU_POLICY_UNKNOWN? "unknown" :
                      ti->policy == GPGME_TOFU_POLICY_BAD? "bad" :
                      ti->policy == GPGME_TOFU_POLICY_ASK? "ask" : "?");
              printf ("   nsigs: %hu\n", ti->signcount);
              printf ("   first: %s\n", isotimestr (ti->signfirst));
              printf ("    last: %s\n", isotimestr (ti->signlast));
              printf ("   nencr: %hu\n", ti->encrcount);
              printf ("   first: %s\n", isotimestr (ti->encrfirst));
              printf ("    last: %s\n", isotimestr (ti->encrlast));
            }
          for (nsigs=0, ks=uid->signatures; ks; ks = ks->next, nsigs++)
            {
              printf ("signature %d: %s\n", nsigs, nonnull (ks->uid));
              printf ("       keyid: %s\n", nonnull (ks->keyid));
              printf ("     created: %s\n", isotimestr(ks->timestamp));
              printf ("     expires: %s\n", isotimestr(ks->expires));
              printf ("       class: %x\n", ks->sig_class);
              printf (" trust depth: %u\n", ks->trust_depth);
              printf (" trust value: %u\n", ks->trust_value);
              printf (" trust scope: %s\n", nonnull (ks->trust_scope));
            }
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
  gpgme_data_release (data);

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

  free (trust_model);

  gpgme_release (ctx);
  return 0;
}
