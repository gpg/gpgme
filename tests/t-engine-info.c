/* t-engine-info.c - Regression test for gpgme_get_engine_info.
   Copyright (C) 2003 g10 Code GmbH

   This file is part of GPGME.
 
   GPGME is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
 
   GPGME is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with GPGME; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <gpgme.h>


#define fail_if_err(err)					\
  do								\
    {								\
      if (err)							\
        {							\
          fprintf (stderr, "%s:%d: GpgmeError %s\n",		\
                   __FILE__, __LINE__, gpgme_strerror (err));   \
          exit (1);						\
        }							\
    }								\
  while (0)


void
check_engine_info (GpgmeEngineInfo info, GpgmeProtocol protocol,
		   const char *path, const char *req_version)
{
  if (info->protocol != protocol)
    {
      fprintf (stderr, "Unexpected protocol %i (expected %i instead)\n",
	       info->protocol, protocol);
      exit (1);
    }
  if (strcmp (info->path, path))
    {
      fprintf (stderr, "Unexpected path to executable %s (expected %s instead)",
	       info->path, path);
      exit (1);
    }
  if (strcmp (info->req_version, req_version))
    {
      fprintf (stderr, "Unexpected required version %s (expected %s instead)",
	       info->req_version, req_version);
      exit (1);
    }
}


int 
main (int argc, char **argv )
{
  GpgmeEngineInfo info;
  GpgmeError err;

  err = gpgme_get_engine_info (&info);
  fail_if_err (err);

  check_engine_info (info, GPGME_PROTOCOL_OpenPGP, GPG_PATH, NEED_GPG_VERSION);

  info = info->next;
#ifdef GPGSM_PATH
  check_engine_info (info, GPGME_PROTOCOL_CMS, GPGSM_PATH, NEED_GPGSM_VERSION);
#else
  if (info)
    {
      fprintf (stderr, "Unexpected engine info.\n");
      exit (1);
    }
#endif

  return 0;
}
