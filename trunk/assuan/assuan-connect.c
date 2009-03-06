/* assuan-connect.c - Establish a connection (client) 
 *	Copyright (C) 2001, 2002 Free Software Foundation, Inc.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#ifndef HAVE_W32_SYSTEM
#include <sys/wait.h>
#endif

#include "assuan-defs.h"

/* Disconnect and release the context CTX. */
void
assuan_disconnect (assuan_context_t ctx)
{
  if (ctx)
    {
      assuan_write_line (ctx, "BYE");
      ctx->finish_handler (ctx);
      ctx->deinit_handler (ctx);
      ctx->deinit_handler = NULL;
      _assuan_release_context (ctx);
    }
}

/* Return the PID of the peer or -1 if not known. This function works
   in some situations where assuan_get_ucred fails. */
pid_t
assuan_get_pid (assuan_context_t ctx)
{
  return (ctx && ctx->pid)? ctx->pid : -1;
}


#ifndef HAVE_W32_SYSTEM
/* Return user credentials. PID, UID and GID may be given as NULL if
   you are not interested in a value.  For getting the pid of the
   peer the assuan_get_pid is usually better suited. */
assuan_error_t
assuan_get_peercred (assuan_context_t ctx, pid_t *pid, uid_t *uid, gid_t *gid)
{
  if (!ctx)
    return _assuan_error (ASSUAN_Invalid_Value);
  if (!ctx->peercred.valid)
    return _assuan_error (ASSUAN_General_Error);

#ifdef HAVE_SO_PEERCRED
  if (pid)
    *pid = ctx->peercred.pid;
  if (uid)
    *uid = ctx->peercred.uid;
  if (gid)
    *gid = ctx->peercred.gid;
#endif

  return 0;
}
#endif /* HAVE_W32_SYSTEM */
