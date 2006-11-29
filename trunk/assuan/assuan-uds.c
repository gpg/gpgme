/* assuan-uds.c - Assuan unix domain socket utilities
 * Copyright (C) 2006 Free Software Foundation, Inc.
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
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA. 
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#ifndef HAVE_W32_SYSTEM
#include <sys/socket.h>
#include <sys/un.h>
#else
#include <windows.h>
#endif
#if HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>

#include "assuan-defs.h"

#ifdef USE_DESCRIPTOR_PASSING
/* Provide replacement for missing CMSG maccros.  We assume that
   size_t matches the alignment requirement. */
#define MY_ALIGN(n) ((((n))+ sizeof(size_t)-1) & (size_t)~(sizeof(size_t)-1))
#ifndef CMSG_SPACE
#define CMSG_SPACE(n) (MY_ALIGN(sizeof(struct cmsghdr)) + MY_ALIGN((n)))
#endif 
#ifndef CMSG_LEN
#define CMSG_LEN(n) (MY_ALIGN(sizeof(struct cmsghdr)) + (n))
#endif 
#ifndef CMSG_FIRSTHDR
#define CMSG_FIRSTHDR(mhdr) \
  ((size_t)(mhdr)->msg_controllen >= sizeof (struct cmsghdr)		      \
   ? (struct cmsghdr*) (mhdr)->msg_control : (struct cmsghdr*)NULL)
#endif
#ifndef CMSG_DATA
#define CMSG_DATA(cmsg) ((unsigned char*)((struct cmsghdr*)(cmsg)+1))
#endif
#endif /*USE_DESCRIPTOR_PASSING*/


/* Read from a unix domain socket using sendmsg. 

   FIXME: We don't need the buffering. It is a leftover from the time
   when we used datagrams. */
static ssize_t
uds_reader (assuan_context_t ctx, void *buf, size_t buflen)
{
  int len = ctx->uds.buffersize;

#ifndef HAVE_W32_SYSTEM
  if (!ctx->uds.bufferallocated)
    {
      ctx->uds.buffer = xtrymalloc (2048);
      if (!ctx->uds.buffer)
        return _assuan_error (ASSUAN_Out_Of_Core);
      ctx->uds.bufferallocated = 2048;
    }

  while (!len)  /* No data is buffered.  */
    {
      struct msghdr msg;
      struct iovec iovec;
#ifdef USE_DESCRIPTOR_PASSING
      union {
        struct cmsghdr cm;
        char control[CMSG_SPACE(sizeof (int))];
      } control_u;
      struct cmsghdr *cmptr;
#endif /*USE_DESCRIPTOR_PASSING*/

      memset (&msg, 0, sizeof (msg));

      msg.msg_name = NULL;
      msg.msg_namelen = 0;
      msg.msg_iov = &iovec;
      msg.msg_iovlen = 1;
      iovec.iov_base = ctx->uds.buffer;
      iovec.iov_len = ctx->uds.bufferallocated;
#ifdef USE_DESCRIPTOR_PASSING
      msg.msg_control = control_u.control;
      msg.msg_controllen = sizeof (control_u.control);
#endif

      len = _assuan_simple_recvmsg (ctx, &msg);
      if (len < 0)
        return -1;

      ctx->uds.buffersize = len;
      ctx->uds.bufferoffset = 0;

#ifdef USE_DESCRIPTOR_PASSING
      cmptr = CMSG_FIRSTHDR (&msg);
      if (cmptr && cmptr->cmsg_len == CMSG_LEN (sizeof(int)))
        {
          if (cmptr->cmsg_level != SOL_SOCKET
              || cmptr->cmsg_type != SCM_RIGHTS)
            _assuan_log_printf ("unexpected ancillary data received\n");
          else
            {
              int fd = *((int*)CMSG_DATA (cmptr));

              if (ctx->uds.pendingfdscount >= DIM (ctx->uds.pendingfds))
                {
                  _assuan_log_printf ("too many descriptors pending - "
                                      "closing received descriptor %d\n", fd);
                  _assuan_close (fd);
                }
              else
                ctx->uds.pendingfds[ctx->uds.pendingfdscount++] = fd;
            }
	}
#endif /*USE_DESCRIPTOR_PASSING*/
    }

#else /*HAVE_W32_SYSTEM*/

  len = recvfrom (ctx->inbound.fd, buf, buflen, 0, NULL, NULL);

#endif /*HAVE_W32_SYSTEM*/

  /* Return some data to the user.  */

  if (len > buflen) /* We have more than the user requested.  */
    len = buflen;

  memcpy (buf, ctx->uds.buffer + ctx->uds.bufferoffset, len);
  ctx->uds.buffersize -= len;
  assert (ctx->uds.buffersize >= 0);
  ctx->uds.bufferoffset += len;
  assert (ctx->uds.bufferoffset <= ctx->uds.bufferallocated);

  return len;
}


/* Write to the domain server.  */
static ssize_t
uds_writer (assuan_context_t ctx, const void *buf, size_t buflen)
{
#ifndef HAVE_W32_SYSTEM
  struct msghdr msg;
  struct iovec iovec;
  ssize_t len;

  memset (&msg, 0, sizeof (msg));

  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  msg.msg_iovlen = 1;
  msg.msg_iov = &iovec;
  iovec.iov_base = (void*)buf;
  iovec.iov_len = buflen;

  len = _assuan_simple_sendmsg (ctx, &msg);
#else /*HAVE_W32_SYSTEM*/
  int len;
  
  len = sendto (ctx->outbound.fd, buf, buflen, 0,
                (struct sockaddr *)&ctx->serveraddr,
                sizeof (struct sockaddr_in));
#endif /*HAVE_W32_SYSTEM*/
  return len;
}


static assuan_error_t
uds_sendfd (assuan_context_t ctx, int fd)
{
#ifdef USE_DESCRIPTOR_PASSING
  struct msghdr msg;
  struct iovec iovec;
  union {
    struct cmsghdr cm;
    char control[CMSG_SPACE(sizeof (int))];
  } control_u;
  struct cmsghdr *cmptr;
  int len;
  char buffer[80];

  /* We need to send some real data so that a read won't return 0
     which will be taken as an EOF.  It also helps with debugging. */ 
  snprintf (buffer, sizeof(buffer)-1, "# descriptor %d is in flight\n", fd);
  buffer[sizeof(buffer)-1] = 0;

  memset (&msg, 0, sizeof (msg));

  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  msg.msg_iovlen = 1;
  msg.msg_iov = &iovec;
  iovec.iov_base = buffer;
  iovec.iov_len = strlen (buffer);

  msg.msg_control = control_u.control;
  msg.msg_controllen = sizeof (control_u.control);
  cmptr = CMSG_FIRSTHDR (&msg);
  cmptr->cmsg_len = CMSG_LEN(sizeof(int));
  cmptr->cmsg_level = SOL_SOCKET;
  cmptr->cmsg_type = SCM_RIGHTS;
  *((int*)CMSG_DATA (cmptr)) = fd;

  len = _assuan_simple_sendmsg (ctx, &msg);
  if (len < 0)
    {
      _assuan_log_printf ("uds_sendfd: %s\n", strerror (errno));
      return _assuan_error (ASSUAN_Write_Error);
    }
  else
    return 0;
#else
  return _assuan_error (ASSUAN_Not_Implemented);
#endif
}


static assuan_error_t
uds_receivefd (assuan_context_t ctx, int *fd)
{
#ifdef USE_DESCRIPTOR_PASSING
  int i;

  if (!ctx->uds.pendingfdscount)
    {
      _assuan_log_printf ("no pending file descriptors!\n");
      return _assuan_error (ASSUAN_General_Error);
    }
  assert (ctx->uds.pendingfdscount <= DIM(ctx->uds.pendingfds));

  *fd = ctx->uds.pendingfds[0];
  for (i=1; i < ctx->uds.pendingfdscount; i++)
    ctx->uds.pendingfds[i-1] = ctx->uds.pendingfds[i];
  ctx->uds.pendingfdscount--;

  return 0;
#else
  return _assuan_error (ASSUAN_Not_Implemented);
#endif
}


/* Close all pending fds. */
void
_assuan_uds_close_fds (assuan_context_t ctx)
{
  int i;

  for (i = 0; i < ctx->uds.pendingfdscount; i++)
    _assuan_close (ctx->uds.pendingfds[i]);
  ctx->uds.pendingfdscount = 0;
}

/* Deinitialize the unix domain socket I/O functions.  */
void
_assuan_uds_deinit (assuan_context_t ctx)
{
  /* First call the finish_handler which should close descriptors etc. */
  ctx->finish_handler (ctx);

  if (ctx->uds.buffer)
    {
      assert (ctx->uds.bufferallocated);
      ctx->uds.bufferallocated = 0;
      xfree (ctx->uds.buffer);
    }

  _assuan_uds_close_fds (ctx);
}


/* Helper function to initialize a context for domain I/O. */
void
_assuan_init_uds_io (assuan_context_t ctx)
{
  static struct assuan_io io = { uds_reader, uds_writer,
				 uds_sendfd, uds_receivefd };

  ctx->io = &io;
  ctx->uds.buffer = 0;
  ctx->uds.bufferoffset = 0;
  ctx->uds.buffersize = 0;
  ctx->uds.bufferallocated = 0;
  ctx->uds.pendingfdscount = 0;
}

