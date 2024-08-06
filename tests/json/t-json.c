/* t-json.c - Regression test.
 * Copyright (C) 2018 Bundesamt für Sicherheit in der Informationstechnik
 *                    Software engineering by Intevation GmbH
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#include <gpgme.h>
#include <gpg-error.h>

#include "../gpg/t-support.h"
#include "../../src/cJSON.h"

/* Register tests here */
static const char*tests[] = { "t-config", "t-version",
    "t-keylist", "t-keylist-secret", "t-decrypt", "t-config-opt",
    "t-encrypt", "t-encrypt-sign", "t-sign", "t-verify",
    "t-decrypt-verify", "t-export", "t-createkey",
    "t-export-secret-info", "t-chunking", "t-sig-notations",
    "t-keylist-revokers",
    /* For these two the order is important
     * as t-import imports the deleted key from t-delete */
    "t-delete", "t-import",
    NULL };

static int verbose = 0;


static char *
get_file (const char *fname)
{
  gpg_error_t err;
  gpgrt_stream_t fp;
  struct stat st;
  char *buf;
  size_t buflen;

  fp = gpgrt_fopen (fname, "r");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      fprintf (stderr, "Error: can't open '%s': %s\n", fname,
               gpg_strerror (err));
      return NULL;
    }

  if (fstat (gpgrt_fileno(fp), &st))
    {
      err = gpg_error_from_syserror ();
      fprintf (stderr, "Error: can't stat '%s': %s\n", fname,
               gpg_strerror (err));
      gpgrt_fclose (fp);
      return NULL;
    }

  buflen = st.st_size;
  buf = malloc (buflen+1);
  if (!buf)
    {
      fprintf (stderr, "Error: no mem\n");
      gpgrt_fclose (fp);
      return NULL;
    }

  if (gpgrt_fread (buf, buflen, 1, fp) != 1)
    {
      err = gpg_error_from_syserror ();
      fprintf (stderr, "error reading '%s': %s\n", fname, gpg_strerror (err));
      gpgrt_fclose (fp);
      free (buf);
      return NULL;
    }
  buf[buflen] = 0;
  gpgrt_fclose (fp);

  return buf;
}

/* Check that the element needle exists in hay. Returns 0 if
   the needle was found. */
int
test_contains (cjson_t needle, cjson_t hay)
{
  cjson_t it;

  if (verbose == 2)
    fprintf (stderr, "%s: -------checking-------- "
                     "\n%s\n -------against-------- \n%s\n",
             nonnull (needle->string), cJSON_Print (needle),
             cJSON_Print (hay));

  /* Type check. This automatically checks bool vals and NULL */
  if (needle->type != hay->type)
    {
      if (verbose)
        fprintf (stderr, "%s: type mismatch expected %i got %i\n",
                 nonnull (needle->string), needle->type,
                 hay->type);
      return 1;
    }

  /* First the simple types */
  if (cjson_is_number (needle))
    {
      if (needle->valueint != hay->valueint)
        {
          if (verbose)
            fprintf (stderr, "%s: value mismatch. Expected %i got %i\n",
                     nonnull (needle->string), needle->valueint,
                     hay->valueint);
          return 1;
        }
    }
  if (cjson_is_string (needle))
    {
      if (strcmp (needle->valuestring, hay->valuestring) &&
          /* Use * as a general don't care placeholder */
          strcmp (needle->valuestring, "*"))
        {
          if (verbose)
            fprintf (stderr, "%s: string mismatch Expected '%s' got '%s'\n",
                     needle->string, needle->valuestring, hay->valuestring);
          return 1;
        }
    }

  /* Now the complex types */
  if (needle->child)
    {
      if (!hay->child)
        {
          fprintf (stderr, "Depth mismatch. Expected child for %s\n",
                   nonnull (needle->string));
        }
      else if (test_contains (needle->child, hay->child))
        {
          int found = 0;
          cjson_t hit;

          for (hit = hay->child; hit; hit = hit->next)
            {
              found |= !test_contains (needle->child, hit);
              if (found)
                {
                  break;
                }
            }
          if (!found)
            {
              return 1;
            }
        }
    }

  if (needle->prev)
    {
      return 0;
    }

  /* Walk elements of an array */
  for (it = needle->next; it; it = it->next)
    {
      int found = 0;
      cjson_t hit;

      if (!it->string && it->child)
        {
          /* Try out all other anonymous children on the same level */
          hit = hay;

          /* Return to the beginning */
          while (hit->prev)
            {
              hit = hit->prev;
            }
          for (; hit && hit->child; hit = hit->next)
            {
              found |= !test_contains (it->child, hit->child);
              if (found)
                {
                  break;
                }
            }
          if (!found)
            {
              return 1;
            }
          continue;
        }

      /* Try the children in the haystack */
      for (hit = hay; hit; hit = hit->next)
        {
          if (hit->string && it->string &&
              !strcmp (hit->string, it->string))
            {
              found = 1;
              if (test_contains (it, hit))
                {
                  return 1;
                }
            }
        }
      if (!found)
        {
          if (verbose)
            fprintf (stderr, "Failed to find '%s' in list\n",
                     nonnull (it->string));
          return 1;
        }
    }
  return 0;
}


int
check_response (const char *response, const char *expected)
{
  cjson_t hay;
  cjson_t needle;
  int rc;
  size_t erroff;

  hay = cJSON_Parse (response, &erroff);

  if (!hay)
    {
      fprintf (stderr, "Failed to parse json at %i:\n%s\n", (int) erroff,
               response);
      return 1;
    }
  needle = cJSON_Parse (expected, &erroff);
  if (!needle)
    {
      fprintf (stderr, "Failed to parse json at %i:\n%s\n", (int) erroff,
               expected);
      cJSON_Delete (hay);
      return 1;
    }

  rc = test_contains (needle, hay);

  cJSON_Delete (needle);
  cJSON_Delete (hay);
  return rc;
}


int
run_test (const char *test, const char *gpgme_json)
{
  gpgme_ctx_t ctx;
  gpgme_data_t json_stdin = NULL;
  gpgme_data_t json_stdout = NULL;
  gpgme_data_t json_stderr = NULL;
  char *test_in;
  char *test_out;
  const char *argv[3];
  char *response;
  char *expected = NULL;
  size_t response_size;
  int rc = 0;
  const char *top_srcdir = getenv ("top_srcdir");

  if (!top_srcdir)
    {
      fprintf (stderr, "Error top_srcdir environment variable not set\n");
      exit(1);
    }

  gpgrt_asprintf (&test_in, "%s/tests/json/%s.in.json",
                  top_srcdir, test);
  gpgrt_asprintf (&test_out, "%s/tests/json/%s.out.json",
                  top_srcdir, test);

  printf ("Running %s...\n", test);

  fail_if_err (gpgme_new (&ctx));

  gpgme_set_protocol (ctx, GPGME_PROTOCOL_SPAWN);

  fail_if_err (gpgme_data_new_from_file (&json_stdin, test_in, 1));
  fail_if_err (gpgme_data_new (&json_stdout));
  fail_if_err (gpgme_data_new (&json_stderr));

  argv[0] = gpgme_json;
  argv[1] = "-s";
  argv[2] = NULL;

  fail_if_err (gpgme_op_spawn (ctx, gpgme_json, argv,
                               json_stdin,
                               json_stdout,
                               json_stderr,
                               0));
  response = gpgme_data_release_and_get_mem (json_stdout,
                                             &response_size);
  if (response_size)
    {
      expected = get_file (test_out);

      test (expected);

      rc = check_response (response, expected);
    }
  else
    {
      rc = 1;
    }

  if (!rc)
    {
      printf (" success\n");
      gpgme_data_release (json_stderr);
    }
  else
    {
      char *buf;
      size_t size;

      buf = gpgme_data_release_and_get_mem (json_stderr, &size);
      printf (" failed%s\n", response_size ? "" :
                             ", no response from gpgme-json");
      if (size)
        {
          printf ("gpgme-json stderr:\n%.*s\n", (int)size, buf);
        }
      free (buf);
    }

  free (test_out);
  free (test_in);
  free (response);
  free (expected);
  gpgme_data_release (json_stdin);
  gpgme_release (ctx);

  return rc;
}

int
main (int argc, char *argv[])
{
  const char *gpgme_json = getenv ("gpgme_json");
  int last_argc = -1;
  const char **test;

  if (argc)
    { argc--; argv++; }


  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--verbose"))
        {
          verbose++;
          argc--; argv++;
        }
    }

  if (!have_gpg_version ("2.1.18"))
    {
      /* Let us not break too much or have to test all combinations */
      printf ("Testsuite skipped. Minimum GnuPG version (2.1.18) "
              "not found.\n");
      exit(0);
    }

  init_gpgme (GPGME_PROTOCOL_SPAWN);

  for (test = tests; *test; test++)
    {
      if (run_test (*test, gpgme_json))
        {
          exit(1);
        }
    }
  return 0;
}
