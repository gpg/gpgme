/* progress.c -  status handler for progress status
 *	Copyright (C) 2000 Werner Koch (dd9jn)
 *      Copyright (C) 2001, 2002 g10 Code GmbH
 *
 * This file is part of GPGME.
 *
 * GPGME is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GPGME is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "context.h"


void
_gpgme_progress_status_handler (GpgmeCtx ctx, GpgmeStatusCode code, char *args)
{
  char *p;
  char *args_cpy;
  int type = 0;
  int current = 0;
  int total = 0;

  if (code != GPGME_STATUS_PROGRESS || !*args || !ctx->progress_cb)
    return;

  args_cpy = strdup (args);
  if (!args_cpy)
    {
      ctx->error = mk_error (Out_Of_Core);
      return;
    }

  p = strchr (args_cpy, ' ');
  if (p)
    {
      *p++ = 0;
      if (*p)
	{
	  type = *(byte *)p;
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
}
