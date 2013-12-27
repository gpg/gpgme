/* t-engine-info.c - Regression test for gpgme_get_engine_info.
   Copyright (C) 2003, 2004, 2007 g10 Code GmbH

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
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

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
          fprintf (stderr, "%s:%d: gpgme_error_t %s\n",		\
                   __FILE__, __LINE__, gpgme_strerror (err));   \
          exit (1);						\
        }							\
    }								\
  while (0)



int
main (int argc, char **argv )
{
  gpgme_engine_info_t info;
  gpgme_error_t err;

  gpgme_check_version (NULL);
  err = gpgme_get_engine_info (&info);
  fail_if_err (err);

  for (; info; info = info->next)
    fprintf (stdout, "protocol=%d engine='%s' v='%s' (min='%s')\n",
             info->protocol, info->file_name, info->version, info->req_version);

  return 0;
}
