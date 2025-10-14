/* wait.c
 * Copyright (C) 2000 Werner Koch (dd9jn)
 * Copyright (C) 2001, 2002, 2003, 2004, 2005, 2007 g10 Code GmbH
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

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include "util.h"
#include "context.h"
#include "ops.h"
#include "wait.h"
#include "sema.h"
#include "priv-io.h"
#include "engine.h"
#include "debug.h"


void
_gpgme_fd_table_init (fd_table_t fdt)
{
  fdt->fds = NULL;
  fdt->size = 0;
}

void
_gpgme_fd_table_deinit (fd_table_t fdt)
{
  if (fdt->fds)
    free (fdt->fds);
}


/* XXX We should keep a marker and roll over for speed.  */
static gpgme_error_t
fd_table_put (fd_table_t fdt, int fd, int dir, void *opaque, int *idx)
{
  unsigned int i, j;
  struct io_select_fd_s *new_fds;

  for (i = 0; i < fdt->size; i++)
    {
      if (fdt->fds[i].fd == -1)
	break;
    }
  if (i == fdt->size)
    {
#define FDT_ALLOCSIZE 10
      new_fds = realloc (fdt->fds, (fdt->size + FDT_ALLOCSIZE)
			 * sizeof (*new_fds));
      if (!new_fds)
	return gpg_error_from_syserror ();

      fdt->fds = new_fds;
      fdt->size += FDT_ALLOCSIZE;
      for (j = 0; j < FDT_ALLOCSIZE; j++)
	fdt->fds[i + j].fd = -1;
    }

  fdt->fds[i].fd = fd;
  fdt->fds[i].for_read = (dir == 1);
  fdt->fds[i].for_write = (dir == 0);
  fdt->fds[i].signaled = 0;
  fdt->fds[i].opaque = opaque;
  *idx = i;
  return 0;
}


/* Register the file descriptor FD with the handler FNC (which gets
   FNC_DATA as its first argument) for the direction DIR.  DATA should
   be the context for which the fd is added.  R_TAG will hold the tag
   that can be used to remove the fd.  */
gpgme_error_t
_gpgme_add_io_cb (void *data, int fd, int dir, gpgme_io_cb_t fnc,
		  void *fnc_data, void **r_tag)
{
  gpgme_error_t err;
  gpgme_ctx_t ctx = (gpgme_ctx_t) data;
  fd_table_t fdt;
  struct wait_item_s *item;
  struct tag *tag;

  assert (fnc);
  assert (ctx);

  fdt = &ctx->fdt;
  assert (fdt);

  tag = malloc (sizeof *tag);
  if (!tag)
    return gpg_error_from_syserror ();
  tag->ctx = ctx;

  /* Allocate a structure to hold information about the handler.  */
  item = calloc (1, sizeof *item);
  if (!item)
    {
      free (tag);
      return gpg_error_from_syserror ();
    }
  item->ctx = ctx;
  item->dir = dir;
  item->handler = fnc;
  item->handler_value = fnc_data;

  err = fd_table_put (fdt, fd, dir, item, &tag->idx);
  if (err)
    {
      free (tag);
      free (item);
      return err;
    }

  TRACE (DEBUG_CTX, "_gpgme_add_io_cb", ctx,
	  "fd=%d, dir=%d -> tag=%p", fd, dir, tag);

  *r_tag = tag;
  return 0;
}


void
_gpgme_remove_io_cb (void *data)
{
  struct tag *tag = data;
  gpgme_ctx_t ctx;
  fd_table_t fdt;
  int idx;

  assert (tag);
  ctx = tag->ctx;
  assert (ctx);
  fdt = &ctx->fdt;
  assert (fdt);
  idx = tag->idx;

  TRACE (DEBUG_CTX, "_gpgme_remove_io_cb", data,
	  "setting fd 0x%x (item=%p) done", fdt->fds[idx].fd,
	  fdt->fds[idx].opaque);

  free (fdt->fds[idx].opaque);
  free (tag);

  /* Free the table entry.  */
  fdt->fds[idx].fd = -1;
  fdt->fds[idx].for_read = 0;
  fdt->fds[idx].for_write = 0;
  fdt->fds[idx].opaque = NULL;
}


/* This is slightly embarrassing.  The problem is that running an I/O
   callback _may_ influence the status of other file descriptors.  Our
   own event loops could compensate for that, but the external event
   loops cannot.  FIXME: We may still want to optimize this a bit when
   we are called from our own event loops.  So if CHECKED is 1, the
   check is skipped.  FIXME: Give an example on how the status of other
   fds can be influenced.  */
gpgme_error_t
_gpgme_run_io_cb (struct io_select_fd_s *an_fds, int checked,
		  gpgme_error_t *op_err)
{
  struct wait_item_s *item;
  struct io_cb_data iocb_data;
  gpgme_error_t err;

  item = (struct wait_item_s *) an_fds->opaque;
  assert (item);

  if (!checked)
    {
      int nr;
      struct io_select_fd_s fds;

      TRACE (DEBUG_CTX, "_gpgme_run_io_cb", item, "need to check");
      fds = *an_fds;
      fds.signaled = 0;  /* Clear the signal because we already know
                          * about it and are running the callback.  */
      /* Just give it a quick poll.  */
      nr = _gpgme_io_select (&fds, 1, 1);
      assert (nr <= 1);
      if (nr < 0)
	return gpg_error_from_syserror ();
      else if (nr == 0)
        {
          /* The status changed in the meantime, there is nothing left
           * to do.  */
          return 0;
        }
    }

  TRACE (DEBUG_CTX, "_gpgme_run_io_cb", item, "handler (%p, %d)",
          item->handler_value, an_fds->fd);

  iocb_data.handler_value = item->handler_value;
  iocb_data.op_err = 0;
  err = item->handler (&iocb_data, an_fds->fd);

  *op_err = iocb_data.op_err;
  return err;
}
