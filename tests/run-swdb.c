/* run-swdb.c  - Test tool for SWDB function
 * Copyright (C) 2016 g10 Code GmbH
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
#include <assert.h>

#include <gpgme.h>

#define PGM "run-swdb"

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


static int
show_usage (int ex)
{
  fputs ("usage: " PGM " [options] NAME [VERSION]\n\n"
         "Options:\n"
         "  --verbose        run in verbose mode\n"
         , stderr);
  exit (ex);
}


int
main (int argc, char **argv)
{
  int last_argc = -1;
  gpgme_error_t err;
  gpgme_ctx_t ctx;
  gpgme_protocol_t protocol = GPGME_PROTOCOL_GPGCONF;
  const char *name;
  const char *iversion;
  gpgme_query_swdb_result_t result;

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
      else if (!strncmp (*argv, "--", 2))
        show_usage (1);
    }

  if (argc < 1 || argc > 2)
    show_usage (1);
  name = argv[0];
  iversion = argc > 1? argv[1] : NULL;

  init_gpgme (protocol);

  err = gpgme_new (&ctx);
  fail_if_err (err);
  gpgme_set_protocol (ctx, protocol);

  err = gpgme_op_query_swdb (ctx, name, iversion, 0);
  if (err)
    {
      fprintf (stderr, PGM ": error querying swdb: %s\n", gpg_strerror (err));
      exit (1);
    }

  result = gpgme_op_query_swdb_result (ctx);
  if (!result)
    {
      fprintf (stderr, PGM ": error querying swdb: %s\n", "no result");
      exit (1);
    }

  printf ("package ...: %s\n"
          "iversion ..: %s\n"
          "version ...: %s\n",
          nonnull (result->name),
          nonnull (result->iversion),
          nonnull (result->version));
  printf ("reldate ...: %s\n", isotimestr (result->reldate));
  printf ("created ...: %s\n", isotimestr (result->created));
  printf ("retrieved .: %s\n", isotimestr (result->retrieved));
  printf ("flags .....:%s%s%s%s%s%s%s\n",
          result->warning? " warning" : "",
          result->update?  " update"  : "",
          result->urgent?  " urgent"  : "",
          result->unknown? " unknown" : "",
          result->tooold?  " tooold"  : "",
          result->noinfo?  " noinfo"  : "",
          result->error?   " error"   : "" );


  gpgme_release (ctx);
  return 0;
}
