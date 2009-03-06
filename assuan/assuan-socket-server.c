/* assuan-socket-server.c - Assuan socket based server
 *	Copyright (C) 2002, 2007 Free Software Foundation, Inc.
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
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#ifdef HAVE_W32_SYSTEM
# include <windows.h>
# if HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
# elif HAVE_WS2TCPIP_H
#  include <ws2tcpip.h>
# endif
#else
# include <sys/socket.h>
# include <sys/un.h>
#endif


#include "assuan-defs.h"

static struct assuan_io io = { _assuan_simple_read, _assuan_simple_write,
			       NULL, NULL };

static int
accept_connection_bottom (assuan_context_t ctx)
{
  assuan_fd_t fd = ctx->connected_fd;

  ctx->peercred.valid = 0;
#ifdef HAVE_SO_PEERCRED
  {
    struct ucred cr; 
    socklen_t cl = sizeof cr;

    if ( !getsockopt (fd, SOL_SOCKET, SO_PEERCRED, &cr, &cl))
      {
         ctx->peercred.pid = cr.pid;
         ctx->peercred.uid = cr.uid;
         ctx->peercred.gid = cr.gid;
         ctx->peercred.valid = 1;

         /* This overrides any already set PID if the function returns
            a valid one. */
         if (cr.pid != (pid_t)-1 && cr.pid) 
           ctx->pid = cr.pid;
      }
  }
#endif

  ctx->inbound.fd = fd;
  ctx->inbound.eof = 0;
  ctx->inbound.linelen = 0;
  ctx->inbound.attic.linelen = 0;
  ctx->inbound.attic.pending = 0;

  ctx->outbound.fd = fd;
  ctx->outbound.data.linelen = 0;
  ctx->outbound.data.error = 0;
  
  ctx->confidential = 0;

  return 0;
}


static int
accept_connection (assuan_context_t ctx)
{
  assuan_fd_t fd;
  struct sockaddr_un clnt_addr;
  socklen_t len = sizeof clnt_addr;

  fd = SOCKET2HANDLE(accept (HANDLE2SOCKET(ctx->listen_fd), 
                             (struct sockaddr*)&clnt_addr, &len ));
  if (fd == ASSUAN_INVALID_FD)
    {
      ctx->os_errno = errno;
      return _assuan_error (ASSUAN_Accept_Failed);
    }
  if (_assuan_sock_check_nonce (fd, &ctx->listen_nonce))
    {
      _assuan_close (fd);
      ctx->os_errno = EACCES;
      return _assuan_error (ASSUAN_Accept_Failed);
    }

  ctx->connected_fd = fd;
  return accept_connection_bottom (ctx);
}

static int
finish_connection (assuan_context_t ctx)
{
  if (ctx->inbound.fd != ASSUAN_INVALID_FD)
    {
      _assuan_close (ctx->inbound.fd);
    }
  ctx->inbound.fd = ASSUAN_INVALID_FD;
  ctx->outbound.fd = ASSUAN_INVALID_FD;
  return 0;
}


static void
deinit_socket_server (assuan_context_t ctx)
{
  finish_connection (ctx);
}

/* Initialize a server for the socket LISTEN_FD which has already be
   put into listen mode */
int
assuan_init_socket_server (assuan_context_t *r_ctx, assuan_fd_t listen_fd)
{
  return assuan_init_socket_server_ext (r_ctx, listen_fd, 0);
}

/* Initialize a server using the already accepted socket FD.  This
   function is deprecated. */
int
assuan_init_connected_socket_server (assuan_context_t *r_ctx, assuan_fd_t fd)
{
  return assuan_init_socket_server_ext (r_ctx, fd, 2);
}


/* 
   Flag bits: 0 - use sendmsg/recvmsg to allow descriptor passing
              1 - FD has already been accepted.
*/
int
assuan_init_socket_server_ext (assuan_context_t *r_ctx, assuan_fd_t fd,
                               unsigned int flags)
{
  assuan_context_t ctx;
  int rc;

  *r_ctx = NULL;
  ctx = xtrycalloc (1, sizeof *ctx);
  if (!ctx)
    return _assuan_error (ASSUAN_Out_Of_Core);
  ctx->is_server = 1;
  if ((flags & 2))
    ctx->pipe_mode = 1; /* We want a second accept to indicate EOF. */
  ctx->input_fd = ASSUAN_INVALID_FD;
  ctx->output_fd = ASSUAN_INVALID_FD;

  ctx->inbound.fd = ASSUAN_INVALID_FD;
  ctx->outbound.fd = ASSUAN_INVALID_FD;

  if ((flags & 2))
    {
      ctx->listen_fd = ASSUAN_INVALID_FD;
      ctx->connected_fd = fd;
    }
  else
    {
      ctx->listen_fd = fd;
      ctx->connected_fd = ASSUAN_INVALID_FD;
    }
  ctx->deinit_handler = (flags & 1)? _assuan_uds_deinit:deinit_socket_server;
  ctx->accept_handler = ((flags & 2)
                         ? accept_connection_bottom 
                         : accept_connection);
  ctx->finish_handler = finish_connection;

  ctx->io = &io;
  if ((flags & 1))
    _assuan_init_uds_io (ctx);

  rc = _assuan_register_std_commands (ctx);
  if (rc)
    xfree (ctx);
  else
    *r_ctx = ctx;
  return rc;
}


/* Save a copy of NONCE in context CTX.  This should be used to
   register the server's nonce with an context established by
   assuan_init_socket_server.  */
void
assuan_set_sock_nonce (assuan_context_t ctx, assuan_sock_nonce_t *nonce)
{
  if (ctx && nonce)
    ctx->listen_nonce = *nonce;
}
