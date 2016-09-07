/* run-verify.c  - Helper to perform a verify operation
   Copyright (C) 2009 g10 Code GmbH

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
#include <time.h>

#include <gpgme.h>

#define PGM "run-verify"

#include "run-support.h"


static int verbose;


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


static gpg_error_t
status_cb (void *opaque, const char *keyword, const char *value)
{
  (void)opaque;
  fprintf (stderr, "status_cb: %s %s\n", keyword, value);
  return 0;
}


static void
print_summary (gpgme_sigsum_t summary)
{
  if ( (summary & GPGME_SIGSUM_VALID      ))
    fputs (" valid", stdout);
  if ( (summary & GPGME_SIGSUM_GREEN      ))
    fputs (" green", stdout);
  if ( (summary & GPGME_SIGSUM_RED        ))
    fputs (" red", stdout);
  if ( (summary & GPGME_SIGSUM_KEY_REVOKED))
    fputs (" revoked", stdout);
  if ( (summary & GPGME_SIGSUM_KEY_EXPIRED))
    fputs (" key-expired", stdout);
  if ( (summary & GPGME_SIGSUM_SIG_EXPIRED))
    fputs (" sig-expired", stdout);
  if ( (summary & GPGME_SIGSUM_KEY_MISSING))
    fputs (" key-missing", stdout);
  if ( (summary & GPGME_SIGSUM_CRL_MISSING))
    fputs (" crl-missing", stdout);
  if ( (summary & GPGME_SIGSUM_CRL_TOO_OLD))
    fputs (" crl-too-old", stdout);
  if ( (summary & GPGME_SIGSUM_BAD_POLICY ))
    fputs (" bad-policy", stdout);
  if ( (summary & GPGME_SIGSUM_SYS_ERROR  ))
    fputs (" sys-error", stdout);
}

static void
print_validity (gpgme_validity_t val)
{
  const char *s = NULL;

  switch (val)
    {
    case GPGME_VALIDITY_UNKNOWN:  s = "unknown"; break;
    case GPGME_VALIDITY_UNDEFINED:s = "undefined"; break;
    case GPGME_VALIDITY_NEVER:    s = "never"; break;
    case GPGME_VALIDITY_MARGINAL: s = "marginal"; break;
    case GPGME_VALIDITY_FULL:     s = "full"; break;
    case GPGME_VALIDITY_ULTIMATE: s = "ultimate"; break;
    }
  if (s)
    fputs (s, stdout);
  else
    printf ("[bad validity value %u]", (unsigned int)val);
}


static void
print_description (const char *text, int indent)
{
  for (; *text; text++)
    {
      putchar (*text);
      if (*text == '\n')
        printf ("%*s", indent, "");
    }
  putchar ('\n');
}


static void
print_result (gpgme_verify_result_t result)
{
  gpgme_signature_t sig;
  gpgme_sig_notation_t nt;
  gpgme_user_id_t uid;
  gpgme_tofu_info_t ti;
  int count = 0;

  printf ("Original file name: %s\n", nonnull(result->file_name));
  for (sig = result->signatures; sig; sig = sig->next)
    {
      printf ("Signature %d\n", count++);
      printf ("  status ....: %s\n", gpgme_strerror (sig->status));
      printf ("  summary ...:"); print_summary (sig->summary); putchar ('\n');
      printf ("  fingerprint: %s\n", nonnull (sig->fpr));
      printf ("  created ...: %lu\n", sig->timestamp);
      printf ("  expires ...: %lu\n", sig->exp_timestamp);
      printf ("  validity ..: ");
      print_validity (sig->validity); putchar ('\n');
      printf ("  val.reason : %s\n", gpgme_strerror (sig->status));
      printf ("  pubkey algo: %d (%s)\n", sig->pubkey_algo,
              nonnull(gpgme_pubkey_algo_name (sig->pubkey_algo)));
      printf ("  digest algo: %d (%s)\n", sig->hash_algo,
              nonnull(gpgme_hash_algo_name (sig->hash_algo)));
      printf ("  pka address: %s\n", nonnull (sig->pka_address));
      printf ("  pka trust .: %s\n",
              sig->pka_trust == 0? "n/a" :
              sig->pka_trust == 1? "bad" :
              sig->pka_trust == 2? "okay": "RFU");
      printf ("  other flags:%s%s\n",
              sig->wrong_key_usage? " wrong-key-usage":"",
              sig->chain_model? " chain-model":""
              );
      for (nt = sig->notations; nt; nt = nt->next)
        {
          printf ("  notation ..: '%s'\n", nt->name);
          if (strlen (nt->name) != nt->name_len)
            printf ("    warning : name larger (%d)\n", nt->name_len);
          printf ("    flags ...:%s%s (0x%02x)\n",
                  nt->critical? " critical":"",
                  nt->human_readable? " human":"",
                  nt->flags);
          if (nt->value)
            printf ("    value ...: '%s'\n", nt->value);
          if ((nt->value?strlen (nt->value):0) != nt->value_len)
            printf ("    warning : value larger (%d)\n", nt->value_len);
        }
      if (sig->key)
        {
          printf ("  primary fpr: %s\n", nonnull (sig->key->fpr));
          for (uid = sig->key->uids; uid; uid = uid->next)
            {
              printf ("  tofu addr .: %s\n", nonnull (uid->address));
              ti = uid->tofu;
              if (!ti)
                continue;
              printf ("    validity : %u (%s)\n", ti->validity,
                      ti->validity == 0? "conflict" :
                      ti->validity == 1? "no history" :
                      ti->validity == 2? "little history" :
                      ti->validity == 3? "enough history" :
                      ti->validity == 4? "lot of history" : "?");
              printf ("    policy ..: %u (%s)\n", ti->policy,
                      ti->policy == GPGME_TOFU_POLICY_NONE? "none" :
                      ti->policy == GPGME_TOFU_POLICY_AUTO? "auto" :
                      ti->policy == GPGME_TOFU_POLICY_GOOD? "good" :
                      ti->policy == GPGME_TOFU_POLICY_UNKNOWN? "unknown" :
                      ti->policy == GPGME_TOFU_POLICY_BAD? "bad" :
                      ti->policy == GPGME_TOFU_POLICY_ASK? "ask" : "?");
              printf ("    signcount: %hu\n", ti->signcount);
              printf ("      first..: %s\n", isotimestr (ti->signfirst));
              printf ("      last ..: %s\n", isotimestr (ti->signlast));
              printf ("    encrcount: %hu\n", ti->encrcount);
              printf ("      first..: %s\n", isotimestr (ti->encrfirst));
              printf ("      last ..: %s\n", isotimestr (ti->encrlast));
              printf ("    desc ....: ");
              print_description (nonnull (ti->description), 15);
            }
        }
    }
}



static int
show_usage (int ex)
{
  fputs ("usage: " PGM " [options] [DETACHEDSIGFILE] FILE\n\n"
         "Options:\n"
         "  --verbose        run in verbose mode\n"
         "  --status         print status lines from the backend\n"
         "  --openpgp        use the OpenPGP protocol (default)\n"
         "  --cms            use the CMS protocol\n"
         , stderr);
  exit (ex);
}


int
main (int argc, char **argv)
{
  int last_argc = -1;
  gpgme_error_t err;
  gpgme_ctx_t ctx;
  gpgme_protocol_t protocol = GPGME_PROTOCOL_OpenPGP;
  FILE *fp_sig = NULL;
  gpgme_data_t sig = NULL;
  FILE *fp_msg = NULL;
  gpgme_data_t msg = NULL;
  gpgme_verify_result_t result;
  int print_status = 0;

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
      else if (!strcmp (*argv, "--status"))
        {
          print_status = 1;
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
      else if (!strncmp (*argv, "--", 2))
        show_usage (1);

    }

  if (argc < 1 || argc > 2)
    show_usage (1);

  fp_sig = fopen (argv[0], "rb");
  if (!fp_sig)
    {
      err = gpgme_error_from_syserror ();
      fprintf (stderr, PGM ": can't open `%s': %s\n",
               argv[0], gpgme_strerror (err));
      exit (1);
    }
  if (argc > 1)
    {
      fp_msg = fopen (argv[1], "rb");
      if (!fp_msg)
        {
          err = gpgme_error_from_syserror ();
          fprintf (stderr, PGM ": can't open `%s': %s\n",
                   argv[1], gpgme_strerror (err));
          exit (1);
        }
    }

  init_gpgme (protocol);

  err = gpgme_new (&ctx);
  fail_if_err (err);
  gpgme_set_protocol (ctx, protocol);
  if (print_status)
    {
      gpgme_set_status_cb (ctx, status_cb, NULL);
      gpgme_set_ctx_flag (ctx, "full-status", "1");
    }
  /* gpgme_set_ctx_flag (ctx, "raw-description", "1"); */

  err = gpgme_data_new_from_stream (&sig, fp_sig);
  if (err)
    {
      fprintf (stderr, PGM ": error allocating data object: %s\n",
               gpgme_strerror (err));
      exit (1);
    }
  if (fp_msg)
    {
      err = gpgme_data_new_from_stream (&msg, fp_msg);
      if (err)
        {
          fprintf (stderr, PGM ": error allocating data object: %s\n",
                   gpgme_strerror (err));
          exit (1);
        }
    }

  err = gpgme_op_verify (ctx, sig, msg, NULL);
  result = gpgme_op_verify_result (ctx);
  if (result)
    print_result (result);
  if (err)
    {
      fprintf (stderr, PGM ": verify failed: %s\n", gpgme_strerror (err));
      exit (1);
    }

  gpgme_data_release (msg);
  gpgme_data_release (sig);

  gpgme_release (ctx);
  return 0;
}
