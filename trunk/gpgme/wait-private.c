/* wait-private.c 
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

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <assert.h>
#include <errno.h>

#include "gpgme.h"
#include "context.h"
#include "wait.h"
#include "ops.h"
#include "io.h"
#include "util.h"


/* The private event loops are used for all blocking operations, and
   for the key and trust item listing operations.  They are completely
   separated from each other.  */


/* Internal I/O callback functions.  */

/* The add_io_cb and remove_io_cb handlers are shared with the global
   event loops.  */

void
_gpgme_wait_private_event_cb (void *data, gpgme_event_io_t type,
			      void *type_data)
{
  switch (type)
    {
    case GPGME_EVENT_START:
      /* Nothing to do here, as the wait routine is called after the
	 initialization is finished.  */
      break;

    case GPGME_EVENT_DONE:
      break;

    case GPGME_EVENT_NEXT_KEY:
      _gpgme_op_keylist_event_cb (data, type, type_data);
      break;

    case GPGME_EVENT_NEXT_TRUSTITEM:
      _gpgme_op_trustlist_event_cb (data, type, type_data);
      break;
    }
}


/* If COND is a null pointer, wait until the blocking operation in CTX
   finished and return its error value.  Otherwise, wait until COND is
   satisfied or the operation finished.  */
gpgme_error_t
_gpgme_wait_on_condition (gpgme_ctx_t ctx, volatile int *cond)
{
  gpgme_error_t err = 0;
  int hang = 1;

  do
    {
      int nr = _gpgme_io_select (ctx->fdt.fds, ctx->fdt.size, 0);
      unsigned int i;

      if (nr < 0)
	{
	  /* An error occured.  Close all fds in this context, and
	     signal it.  */
	  unsigned int idx;

	  err = gpg_error_from_errno (errno);
	  for (idx = 0; idx < ctx->fdt.size; idx++)
	    if (ctx->fdt.fds[idx].fd != -1)
	      _gpgme_io_close (ctx->fdt.fds[idx].fd);
	  _gpgme_engine_io_event (ctx->engine, GPGME_EVENT_DONE, &err);

	  return err;
	}
      
      for (i = 0; i < ctx->fdt.size && nr; i++)
	{
	  if (ctx->fdt.fds[i].fd != -1 && ctx->fdt.fds[i].signaled)
	    {
	      struct wait_item_s *item;
	      
	      ctx->fdt.fds[i].signaled = 0;
	      assert (nr);
	      nr--;
	      
	      item = (struct wait_item_s *) ctx->fdt.fds[i].opaque;

	      err = item->handler (item->handler_value, ctx->fdt.fds[i].fd);
	      if (err)
		{
		  /* An error occured.  Close all fds in this context,
		     and signal it.  */
		  unsigned int idx;
		  
		  for (idx = 0; idx < ctx->fdt.size; idx++)
		    if (ctx->fdt.fds[idx].fd != -1)
		      _gpgme_io_close (ctx->fdt.fds[idx].fd);
		  _gpgme_engine_io_event (ctx->engine, GPGME_EVENT_DONE, &err);
		  return err;
		}
	    }
	}

      for (i = 0; i < ctx->fdt.size; i++)
	if (ctx->fdt.fds[i].fd != -1)
	  break;
      if (i == ctx->fdt.size)
	{
	  _gpgme_engine_io_event (ctx->engine, GPGME_EVENT_DONE, &err);
	  hang = 0;
	}
      if (cond && *cond)
	hang = 0;
    }
  while (hang);

  return 0;
}


/* Wait until the blocking operation in context CTX has finished and
   return the error value.  */
gpgme_error_t
_gpgme_wait_one (gpgme_ctx_t ctx)
{
  return _gpgme_wait_on_condition (ctx, NULL);
}
