/* progress.c -  status handler for progress status
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003 g10 Code GmbH
 
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
#include <string.h>
#include <errno.h>

#include "util.h"
#include "context.h"


gpgme_error_t
_gpgme_progress_status_handler (void *priv, gpgme_status_code_t code,
				char *args)
{
  gpgme_ctx_t ctx = (gpgme_ctx_t) priv;
  char *p;
  char *args_cpy;
  int type = 0;
  int current = 0;
  int total = 0;

  if (code != GPGME_STATUS_PROGRESS || !*args || !ctx->progress_cb)
    return 0;

  args_cpy = strdup (args);
  if (!args_cpy)
    return gpg_error_from_errno (errno);

  p = strchr (args_cpy, ' ');
  if (p)
    {
      *p++ = 0;
      if (*p)
	{
	  type = *(unsigned char *)p;
	  p = strchr (p+1, ' ');
	  if (p)
	    {
	      *p++ = 0;
	      if (*p)
		{
		  current = atoi (p);
		  p = strchr (p+1, ' ');
		  if (p)
		    {
		      *p++ = 0;
		      total = atoi (p);
		    }
		}
	    }
	}
    }           

  if (type != 'X')
    ctx->progress_cb (ctx->progress_cb_value, args_cpy, type, current, total);

  free (args_cpy);
  return 0;
}
