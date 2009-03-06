/* assuan-util.c - Utility functions for Assuan 
 * Copyright (C) 2001, 2002, 2003, 2004, 2005 Free Software Foundation, Inc.
 *
 * This file is part of Assuan.
 *
 * Assuan is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Assuan is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "assuan-defs.h"

static void *(*alloc_func)(size_t n) = malloc;
static void *(*realloc_func)(void *p, size_t n) = realloc;
static void (*free_func)(void*) = free;

struct assuan_io_hooks _assuan_io_hooks;



void
assuan_set_malloc_hooks ( void *(*new_alloc_func)(size_t n),
                          void *(*new_realloc_func)(void *p, size_t n),
                          void (*new_free_func)(void*) )
{
  alloc_func	    = new_alloc_func;
  realloc_func      = new_realloc_func;
  free_func	    = new_free_func;
}


void
assuan_set_io_hooks (assuan_io_hooks_t io_hooks)
{
  _assuan_io_hooks.read_hook = NULL;
  _assuan_io_hooks.write_hook = NULL;
  if (io_hooks)
    {
      _assuan_io_hooks.read_hook = io_hooks->read_hook;
      _assuan_io_hooks.write_hook = io_hooks->write_hook;
    }
}


void *
_assuan_malloc (size_t n)
{
  return alloc_func (n);
}

void *
_assuan_realloc (void *a, size_t n)
{
  return realloc_func (a, n);
}

void *
_assuan_calloc (size_t n, size_t m)
{
  void *p;
  size_t nbytes;
    
  nbytes = n * m;
  if (m && nbytes / m != n) 
    {
      errno = ENOMEM;
      return NULL;
    }

  p = _assuan_malloc (nbytes);
  if (p)
    memset (p, 0, nbytes);
  return p;
}

void
_assuan_free (void *p)
{
  if (p)
    free_func (p);
}


/* Store the error in the context so that the error sending function
  can take out a descriptive text.  Inside the assuan code, use the
  macro set_error instead of this function. */
int
assuan_set_error (assuan_context_t ctx, int err, const char *text)
{
  ctx->err_no = err;
  ctx->err_str = text;
  return err;
}

void
assuan_set_pointer (assuan_context_t ctx, void *pointer)
{
  if (ctx)
    ctx->user_pointer = pointer;
}

void *
assuan_get_pointer (assuan_context_t ctx)
{
  return ctx? ctx->user_pointer : NULL;
}


void
assuan_begin_confidential (assuan_context_t ctx)
{
  if (ctx)
    {
      ctx->confidential = 1;
    }
}

void
assuan_end_confidential (assuan_context_t ctx)
{
  if (ctx)
    {
      ctx->confidential = 0;
    }
}


void 
assuan_set_io_monitor (assuan_context_t ctx,
                       unsigned int (*monitor)(assuan_context_t ctx,
                                               int direction,
                                               const char *line,
                                               size_t linelen))
{
  if (ctx)
    {
      ctx->io_monitor = monitor;
    }
}




/* For context CTX, set the flag FLAG to VALUE.  Values for flags
   are usually 1 or 0 but certain flags might allow for other values;
   see the description of the type assuan_flag_t for details. */
void
assuan_set_flag (assuan_context_t ctx, assuan_flag_t flag, int value)
{
  if (!ctx)
    return;
  switch (flag)
    {
    case ASSUAN_NO_WAITPID: ctx->flags.no_waitpid = value; break;
    case ASSUAN_CONFIDENTIAL: ctx->confidential = value; break;
    }
}

/* Return the VALUE of FLAG in context CTX. */ 
int
assuan_get_flag (assuan_context_t ctx, assuan_flag_t flag)
{
  if (!ctx)
    return 0;
  switch (flag)
    {
    case ASSUAN_NO_WAITPID: return ctx->flags.no_waitpid;
    case ASSUAN_CONFIDENTIAL: return ctx->confidential;
    }
  return 0;
}

