/* wait.c 
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>

#include "util.h"
#include "context.h"
#include "ops.h"
#include "wait.h"
#include "sema.h"
#include "io.h"
#include "engine.h"

struct fd_table fdt_global;

static GpgmeCtx *ctx_done_list;
static int ctx_done_list_size;
static int ctx_done_list_length;
DEFINE_STATIC_LOCK (ctx_done_list_lock);

static GpgmeIdleFunc idle_function;

struct wait_item_s
{
  struct wait_item_s *next;
  GpgmeIOCb handler;
  void *handler_value;
  int dir;
};

static void run_idle (void);


void
_gpgme_fd_table_init (fd_table_t fdt)
{
  INIT_LOCK (fdt->lock);
  fdt->fds = NULL;
  fdt->size = 0;
}

void
_gpgme_fd_table_deinit (fd_table_t fdt)
{
  DESTROY_LOCK (fdt->lock);
  if (fdt->fds)
    xfree (fdt->fds);
}

/* XXX We should keep a marker and roll over for speed.  */
GpgmeError
_gpgme_fd_table_put (fd_table_t fdt, int fd, int dir, void *opaque, int *idx)
{
  int i, j;
  struct io_select_fd_s *new_fds;

  LOCK (fdt->lock);
  for (i = 0; i < fdt->size; i++)
    {
      if (fdt->fds[i].fd == -1)
	break;
    }
  if (i == fdt->size)
    {
#define FDT_ALLOCSIZE 10
      new_fds = xtryrealloc (fdt->fds, (fdt->size + FDT_ALLOCSIZE)
			     * sizeof (*new_fds));
      if (!new_fds)
	{
	  UNLOCK (fdt->lock);
	  return mk_error (Out_Of_Core);
	}
      
      fdt->fds = new_fds;
      fdt->size += FDT_ALLOCSIZE;
      for (j = 0; j < FDT_ALLOCSIZE; j++)
	fdt->fds[i + j].fd = -1;
    }

  fdt->fds[i].fd = fd;
  fdt->fds[i].for_read = (dir == 1);
  fdt->fds[i].for_write = (dir == 0);
  fdt->fds[i].frozen = 0;
  fdt->fds[i].signaled = 0;
  fdt->fds[i].opaque = opaque;
  UNLOCK (fdt->lock);
  *idx = i;
  return 0;
}


/**
 * gpgme_register_idle:
 * @fnc: Callers idle function
 * 
 * Register a function with GPGME called by GPGME whenever it feels
 * that is is idle.  NULL may be used to remove this function.
 *
 * Return value: The idle function pointer that was passed to the
 * function at the last time it was invoked, or NULL if the function
 * is invoked the first time.
 **/
GpgmeIdleFunc
gpgme_register_idle (GpgmeIdleFunc idle)
{
  GpgmeIdleFunc old_idle = idle_function;

  idle_function = idle;
  return old_idle;
}

static void
run_idle ()
{
  _gpgme_engine_housecleaning ();
  if (idle_function)
    idle_function ();
}


/* Wait on all file descriptors listed in FDT and process them using
   the registered callbacks.  Returns -1 on error (with errno set), 0
   if nothing to run and 1 if it did run something.  */
static int
do_select (fd_table_t fdt)
{
  int i, n;
  int any = 0;

  LOCK (fdt->lock);
  n = _gpgme_io_select (fdt->fds, fdt->size);

  if (n <= 0) 
    {
      UNLOCK (fdt->lock);
      return n;	/* Error or timeout.  */
    }

  for (i = 0; i < fdt->size && n; i++)
    {
      if (fdt->fds[i].fd != -1 && fdt->fds[i].signaled)
	{
	  struct wait_item_s *item;

	  assert (n);
	  n--;
            
	  item = (struct wait_item_s *) fdt->fds[i].opaque;
	  assert (item);
	  any = 1;

	  fdt->fds[i].signaled = 0;
	  UNLOCK (fdt->lock);
	  item->handler (item->handler_value, fdt->fds[i].fd);
	  LOCK (fdt->lock);
        }
    }
  UNLOCK (fdt->lock);
    
  return any;
}



void
_gpgme_wait_event_cb (void *data, GpgmeEventIO type, void *type_data)
{
  if (type != GPGME_EVENT_DONE)
    return;

  if (ctx_done_list_size == ctx_done_list_length)
    {
#define CTX_DONE_LIST_SIZE_INITIAL 8
      int new_size = ctx_done_list_size ? 2 * ctx_done_list_size
	: CTX_DONE_LIST_SIZE_INITIAL;
      GpgmeCtx *new_list = xtryrealloc (ctx_done_list,
					new_size * sizeof (GpgmeCtx *));
      assert (new_list);
#if 0
      if (!new_list)
	return mk_error (Out_Of_Core);
#endif
      ctx_done_list = new_list;
      ctx_done_list_size = new_size;
    }
  ctx_done_list[ctx_done_list_length++] = (GpgmeCtx) data;
}


/**
 * gpgme_wait:
 * @c: 
 * @hang: 
 * 
 * Wait for a finished request, if @c is given the function does only
 * wait on a finished request for that context, otherwise it will return
 * on any request.  When @hang is true the function will wait, otherwise
 * it will return immediately when there is no pending finished request.
 * 
 * Return value: Context of the finished request or NULL if @hang is false
 *  and no (or not the given) request has finished.
 **/
GpgmeCtx 
gpgme_wait (GpgmeCtx ctx, GpgmeError *status, int hang)
{
  ctx = _gpgme_wait_on_condition (ctx, hang, NULL);
  if (ctx && status)
    *status = ctx->error;
  return ctx;
}

GpgmeError
_gpgme_wait_one (GpgmeCtx ctx)
{
  GpgmeError err = 0;
  int hang = 1;
  DEBUG1 ("waiting... ctx=%p", ctx);
  do
    {
      if (do_select (&ctx->fdt) < 0)
	{
	  err = mk_error (File_Error);
	  hang = 0;
	}
      else
	{
	  int any = 0;
	  int i;

	  LOCK (ctx->fdt.lock);
	  for (i = 0; i < ctx->fdt.size; i++)
	    {
	      if (ctx->fdt.fds[i].fd != -1)
		{
		  any = 1;
		  break;
		}
	    }
	  if (!any)
	    hang = 0;
	  UNLOCK (ctx->fdt.lock);
	}
    }
  while (hang && !ctx->cancel);
  if (!err && ctx->cancel)
    {
      /* FIXME: Paranoia?  */
      ctx->cancel = 0;
      ctx->pending = 0;
      ctx->error = mk_error (Canceled);
    }
  return err ? err : ctx->error;
}


GpgmeCtx 
_gpgme_wait_on_condition (GpgmeCtx ctx, int hang, volatile int *cond)
{
  DEBUG3 ("waiting... ctx=%p hang=%d cond=%p", ctx, hang, cond);
  do
    {
      /* XXX We are ignoring all errors from select here.  */
      do_select (&fdt_global);
      
      if (cond && *cond)
	hang = 0;
      else
	{
	  int i;

	  LOCK (ctx_done_list_lock);
	  /* A process that is done is eligible for election if it is
	     the requested context or if it was not yet reported.  */
	  for (i = 0; i < ctx_done_list_length; i++)
	    if (!ctx || ctx == ctx_done_list[i])
	      break;
	  if (i < ctx_done_list_length)
	    {
	      if (!ctx)
		ctx = ctx_done_list[i];
	      hang = 0;
	      ctx->pending = 0;
	      if (--ctx_done_list_length)
		memcpy (&ctx_done_list[i],
			&ctx_done_list[i + 1],
			(ctx_done_list_length - i) * sizeof (GpgmeCtx *));
	    }
	  UNLOCK (ctx_done_list_lock);
        }
      if (hang)
	run_idle ();
    }
  while (hang && (!ctx || !ctx->cancel));
  if (ctx && ctx->cancel)
    {
      /* FIXME: Paranoia?  */
      ctx->cancel = 0;
      ctx->pending = 0;
      ctx->error = mk_error (Canceled);
    }
  return ctx;
}


struct tag
{
  fd_table_t fdt;
  int idx;
};

void *
_gpgme_add_io_cb (void *data, int fd, int dir,
		  GpgmeIOCb fnc, void *fnc_data)
{
  GpgmeError err;
  fd_table_t fdt = (fd_table_t) (data ? data : &fdt_global);
  struct wait_item_s *item;
  struct tag *tag;

  assert (fdt);
  assert (fnc);

  tag = xtrymalloc (sizeof *tag);
  if (!tag)
    return NULL;
  tag->fdt = fdt;

  /* Allocate a structure to hold info about the handler.  */
  item = xtrycalloc (1, sizeof *item);
  if (!item)
    {
      xfree (tag);
      return NULL;
    }
  item->dir = dir;
  item->handler = fnc;
  item->handler_value = fnc_data;

  err = _gpgme_fd_table_put (fdt, fd, dir, item, &tag->idx);
  if (err)
    {
      xfree (tag);
      xfree (item);
      errno = ENOMEM;
      return 0;
    }
  
  return tag;
}

void
_gpgme_remove_io_cb (void *data)
{
  struct tag *tag = data;
  fd_table_t fdt = tag->fdt;
  int idx = tag->idx;

  LOCK (fdt->lock);
  DEBUG2 ("setting fd %d (item=%p) done", fdt->fds[idx].fd,
	  fdt->fds[idx].opaque);
  xfree (fdt->fds[idx].opaque);
  xfree (tag);

  /* Free the table entry.  */
  fdt->fds[idx].fd = -1;
  fdt->fds[idx].for_read = 0;
  fdt->fds[idx].for_write = 0;
  fdt->fds[idx].opaque = NULL;
}

