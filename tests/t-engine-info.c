/* t-engine-info.c - Regression test for gpgme_get_engine_info.
 * Copyright (C) 2003, 2004, 2007 g10 Code GmbH
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
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <gpgme.h>

#define PGM "t-engine-info"

static int verbose;




#define fail_if_err(err)					\
  do								\
    {								\
      if (err)							\
        {							\
          fprintf (stderr, "%s:%d: gpgme_error_t %s\n",		\
                   __FILE__, __LINE__, gpgme_strerror (err));   \
          exit (1);						\
        }							\
    }								\
  while (0)


int
main (int argc, char **argv )
{
  int last_argc = -1;
  gpgme_engine_info_t info;
  gpgme_error_t err;

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
        {
          fputs ("usage: " PGM " [options]\n"
                 "Options:\n"
                 "  --set-global-flag KEY VALUE\n",
                 stdout);
          exit (0);
        }
      else if (!strcmp (*argv, "--verbose"))
        {
          verbose++;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--set-global-flag"))
        {
          argc--; argv++;
          if (argc < 2)
            {
              fprintf (stderr, PGM ": not enough arguments for option\n");
              exit (1);
            }
          if (gpgme_set_global_flag (argv[0], argv[1]))
            {
              fprintf (stderr, PGM ": gpgme_set_global_flag failed\n");
              exit (1);
            }
          argc--; argv++;
          argc--; argv++;
        }
      else if (!strncmp (*argv, "--", 2))
        {
          fprintf (stderr, PGM ": unknown option '%s'\n", *argv);
          exit (1);
        }
    }

  if (argc)
    {
      fprintf (stderr, PGM ": unexpected arguments\n");
      exit (1);
    }

  gpgme_check_version (NULL);

  {
    const char *keys[] = {"homedir",
                          "sysconfdir",
                          "bindir",
                          "libexecdir",
                          "libdir",
                          "datadir",
                          "localedir",
                          "socketdir",
                          "agent-socket",
                          "agent-ssh-socket",
                          "dirmngr-socket",
                          "uiserver-socket",
                          "gpgconf-name",
                          "gpg-name",
                          "gpgsm-name",
                          "g13-name",
                          "keyboxd-name",
                          "agent-name",
                          "scdaemon-name",
                          "dirmngr-name",
                          "pinentry-name",
                          "gpg-wks-client-name",
                          "gpgtar-name",
                          NULL };
    const char *s;
    int i;

    for (i=0; keys[i]; i++)
      if ((s = gpgme_get_dirinfo (keys[i])))
        fprintf (stderr, "dirinfo: %s='%s'\n", keys[i], s);
  }

  err = gpgme_get_engine_info (&info);
  fail_if_err (err);

  for (; info; info = info->next)
    fprintf (stdout, "protocol=%d engine='%s' v='%s' (min='%s') home='%s'\n",
             info->protocol, info->file_name, info->version, info->req_version,
             info->home_dir? info->home_dir : "[default]");

  return 0;
}
