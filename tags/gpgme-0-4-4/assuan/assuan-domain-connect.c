/* assuan-domain-connect.c - Assuan unix domain socket based client
 *	Copyright (C) 2002, 2003 Free Software Foundation, Inc.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA 
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <alloca.h>
#include <string.h>
#include <assert.h>

#include "assuan-defs.h"

#define LOG(format, args...) \
	fprintf (assuan_get_assuan_log_stream (), \
	         assuan_get_assuan_log_prefix (), \
	         "%s" format , ## args)


static void
do_deinit (ASSUAN_CONTEXT ctx)
{
  if (ctx->inbound.fd != -1)
    close (ctx->inbound.fd);
  ctx->inbound.fd = -1;
  ctx->outbound.fd = -1;

  if (ctx->domainbuffer)
    {
      assert (ctx->domainbufferallocated);
      free (ctx->domainbuffer);
    }

  if (ctx->pendingfds)
    {
      int i;

      assert (ctx->pendingfdscount > 0);
      for (i = 0; i < ctx->pendingfdscount; i ++)
	close (ctx->pendingfds[i]);

      free (ctx->pendingfds);
    }

  unlink (ctx->myaddr.sun_path);
}


/* Read from the socket server.  */
static ssize_t
domain_reader (ASSUAN_CONTEXT ctx, void *buf, size_t buflen)
{
  int len = ctx->domainbuffersize;

 start:
  if (len == 0)
    /* No data is buffered.  */
    {
      struct msghdr msg;
      struct iovec iovec;
      struct sockaddr_un sender;
      struct
      {
	struct cmsghdr hdr;
	int fd;
      }
      cmsg;

      memset (&msg, 0, sizeof (msg));

      for (;;)
	{
	  msg.msg_name = &sender;
	  msg.msg_namelen = sizeof (struct sockaddr_un);
	  msg.msg_iov = &iovec;
	  msg.msg_iovlen = 1;
	  iovec.iov_base = ctx->domainbuffer;
	  iovec.iov_len = ctx->domainbufferallocated;
	  msg.msg_control = &cmsg;
	  msg.msg_controllen = sizeof cmsg;

	  /* Peek first: if the buffer we have is too small then it
	     will be truncated.  */
	  len = recvmsg (ctx->inbound.fd, &msg, MSG_PEEK);
	  if (len < 0)
	    {
	      printf ("domain_reader: %m\n");
	      return -1;
	    }

	  if (strcmp (ctx->serveraddr.sun_path,
		      ((struct sockaddr_un *) msg.msg_name)->sun_path) != 0)
	    {
	      /* XXX: Arg.  Not from whom we expected!  What do we
		 want to do?  Should we just ignore it?  Either way,
		 we still need to consume the message.  */
	      break;
	    }

	  if (msg.msg_flags & MSG_TRUNC)
	    /* Enlarge the buffer and try again.  */
	    {
	      int size = ctx->domainbufferallocated;
	      void *tmp;

	      if (size == 0)
		size = 4 * 1024;
	      else
		size *= 2;

	      tmp = malloc (size);
	      if (! tmp)
		return -1;

	      free (ctx->domainbuffer);
	      ctx->domainbuffer = tmp;
	      ctx->domainbufferallocated = size;
	    }
	  else
	    /* We have enough space!  */
	    break;
	}

      /* Now we have to actually consume it (remember, we only
	 peeked).  */
      msg.msg_name = &sender;
      msg.msg_namelen = sizeof (struct sockaddr_un);
      msg.msg_iov = &iovec;
      msg.msg_iovlen = 1;
      iovec.iov_base = ctx->domainbuffer;
      iovec.iov_len = ctx->domainbufferallocated;
      msg.msg_control = &cmsg;
      msg.msg_controllen = sizeof cmsg;

      if (strcmp (ctx->serveraddr.sun_path,
		  ((struct sockaddr_un *) msg.msg_name)->sun_path) != 0)
	{
	  /* XXX: Arg.  Not from whom we expected!  What do we want to
	     do?  Should we just ignore it?  We shall do the latter
	     for the moment.  */
	  LOG ("Not setup to receive messages from: `%s'.",
	       ((struct sockaddr_un *) msg.msg_name)->sun_path);
	  goto start;
	}

      len = recvmsg (ctx->inbound.fd, &msg, 0);
      if (len < 0)
	{
	  LOG ("domain_reader: %s\n", strerror (errno));
	  return -1;
	}

      ctx->domainbuffersize = len;
      ctx->domainbufferoffset = 0;

      if (sizeof (cmsg) == msg.msg_controllen)
	/* We received a file descriptor.  */
	{
	  void *tmp;

	  tmp = realloc (ctx->pendingfds,
			 sizeof (int) * (ctx->pendingfdscount + 1));
	  if (! tmp)
	    {
	      LOG ("domain_reader: %s\n", strerror (errno));
	      return -1;
	    }

	  ctx->pendingfds = tmp;
	  ctx->pendingfds[ctx->pendingfdscount++]
	    = *(int *) CMSG_DATA (&cmsg.hdr);

	  LOG ("Received file descriptor %d from peer.\n",
	       ctx->pendingfds[ctx->pendingfdscount - 1]);
	}

      if (len == 0)
	goto start;
    }

  /* Return some data to the user.  */

  if (len > buflen)
    /* We have more than the user requested.  */
    len = buflen;

  memcpy (buf, ctx->domainbuffer + ctx->domainbufferoffset, len);
  ctx->domainbuffersize -= len;
  assert (ctx->domainbuffersize >= 0);
  ctx->domainbufferoffset += len;
  assert (ctx->domainbufferoffset <= ctx->domainbufferallocated);

  return len;
}

/* Write to the domain server.  */
static ssize_t
domain_writer (ASSUAN_CONTEXT ctx, const void *buf, size_t buflen)
{
  struct msghdr msg;
  struct iovec iovec;
  ssize_t len;

  memset (&msg, 0, sizeof (msg));

  msg.msg_name = &ctx->serveraddr;
  msg.msg_namelen = offsetof (struct sockaddr_un, sun_path)
    + strlen (ctx->serveraddr.sun_path) + 1;

  msg.msg_iovlen = 1;
  msg.msg_iov = &iovec;
  iovec.iov_base = (void *) buf;
  iovec.iov_len = buflen;
  msg.msg_control = 0;
  msg.msg_controllen = 0;

  len = sendmsg (ctx->outbound.fd, &msg, 0);
  if (len < 0)
    LOG ("domain_writer: %s\n", strerror (errno));

  return len;
}

static AssuanError
domain_sendfd (ASSUAN_CONTEXT ctx, int fd)
{
  struct msghdr msg;
  struct
  {
    struct cmsghdr hdr;
    int fd;
  }
  cmsg;
  int len;

  memset (&msg, 0, sizeof (msg));

  msg.msg_name = &ctx->serveraddr;
  msg.msg_namelen = offsetof (struct sockaddr_un, sun_path)
    + strlen (ctx->serveraddr.sun_path) + 1;

  msg.msg_iovlen = 0;
  msg.msg_iov = 0;

  cmsg.hdr.cmsg_level = SOL_SOCKET;
  cmsg.hdr.cmsg_type = SCM_RIGHTS;
  cmsg.hdr.cmsg_len = sizeof (cmsg);

  msg.msg_control = &cmsg;
  msg.msg_controllen = sizeof (cmsg);

  *(int *) CMSG_DATA (&cmsg.hdr) = fd;

  len = sendmsg (ctx->outbound.fd, &msg, 0);
  if (len < 0)
    {
      LOG ("domain_sendfd: %s\n", strerror (errno));
      return ASSUAN_General_Error;
    }
  else
    return 0;
}

static AssuanError
domain_receivefd (ASSUAN_CONTEXT ctx, int *fd)
{
  if (ctx->pendingfds == 0)
    {
      LOG ("No pending file descriptors!\n");
      return ASSUAN_General_Error;
    }

  *fd = ctx->pendingfds[0];
  if (-- ctx->pendingfdscount == 0)
    {
      free (ctx->pendingfds);
      ctx->pendingfds = 0;
    }
  else
    /* Fix the array.  */
    {
      memmove (ctx->pendingfds, ctx->pendingfds + 1,
	       ctx->pendingfdscount * sizeof (int));
      ctx->pendingfds = realloc (ctx->pendingfds,
				 ctx->pendingfdscount * sizeof (int));
    }

  return 0;
}



/* Make a connection to the Unix domain socket NAME and return a new
   Assuan context in CTX.  SERVER_PID is currently not used but may
   become handy in the future.  */
AssuanError
_assuan_domain_init (ASSUAN_CONTEXT *r_ctx, int rendezvousfd, pid_t peer)
{
  static struct assuan_io io = { domain_reader, domain_writer,
				 domain_sendfd, domain_receivefd };

  AssuanError err;
  ASSUAN_CONTEXT ctx;
  int fd;
  size_t len;
  int tries;

  if (!r_ctx)
    return ASSUAN_Invalid_Value;
  *r_ctx = NULL;

  err = _assuan_new_context (&ctx); 
  if (err)
    return err;

  /* Save it in case we need it later.  */
  ctx->pid = peer;

  /* Override the default (NOP) handlers.  */
  ctx->deinit_handler = do_deinit;

  /* Setup the socket.  */

  fd = socket (PF_LOCAL, SOCK_DGRAM, 0);
  if (fd == -1)
    {
      LOG ("can't create socket: %s\n", strerror (errno));
      _assuan_release_context (ctx);
      return ASSUAN_General_Error;
    }

  ctx->inbound.fd = fd;
  ctx->outbound.fd = fd;

  /* And the io buffers.  */

  ctx->io = &io;
  ctx->domainbuffer = 0;
  ctx->domainbufferoffset = 0;
  ctx->domainbuffersize = 0;
  ctx->domainbufferallocated = 0;
  ctx->pendingfds = 0;
  ctx->pendingfdscount = 0;

  /* Get usable name and bind to it.  */

  for (tries = 0; tries < TMP_MAX; tries ++)
    {
      char *p;
      char buf[L_tmpnam];

      /* XXX: L_tmpnam must be shorter than sizeof (sun_path)!  */
      assert (L_tmpnam < sizeof (ctx->myaddr.sun_path));

      p = tmpnam (buf);
      if (! p)
	{
	  LOG ("cannot determine an appropriate temporary file "
	       "name.  DOS in progress?\n");
	  _assuan_release_context (ctx);
	  close (fd);
	  return ASSUAN_General_Error;
	}

      memset (&ctx->myaddr, 0, sizeof ctx->myaddr);
      ctx->myaddr.sun_family = AF_LOCAL;
      len = strlen (buf) + 1;
      memcpy (ctx->myaddr.sun_path, buf, len);
      len += offsetof (struct sockaddr_un, sun_path);

      err = bind (fd, (struct sockaddr *) &ctx->myaddr, len);
      if (! err)
	break;
    }

  if (err)
    {
      LOG ("can't bind to `%s': %s\n", ctx->myaddr.sun_path,
	   strerror (errno));
      _assuan_release_context (ctx);
      close (fd);
      return ASSUAN_Connect_Failed;
    }

  /* Rendezvous with our peer.  */
  {
    FILE *fp;
    char *p;

    fp = fdopen (rendezvousfd, "w+");
    if (! fp)
      {
	LOG ("can't open rendezvous port: %s\n", strerror (errno));
	return ASSUAN_Connect_Failed;
      }

    /* Send our address.  */
    fprintf (fp, "%s\n", ctx->myaddr.sun_path);
    fflush (fp);

    /* And receive our peer's.  */
    memset (&ctx->serveraddr, 0, sizeof ctx->serveraddr);
    for (p = ctx->serveraddr.sun_path;
	 p < (ctx->serveraddr.sun_path
	      + sizeof ctx->serveraddr.sun_path - 1);
	 p ++)
      {
	*p = fgetc (fp);
	if (*p == '\n')
	  break;
      }
    *p = '\0';
    fclose (fp);

    ctx->serveraddr.sun_family = AF_LOCAL;
  }

  *r_ctx = ctx;
  return 0;
}

AssuanError
assuan_domain_connect (ASSUAN_CONTEXT * r_ctx, int rendezvousfd, pid_t peer)
{
  AssuanError aerr;
  int okay, off;

  aerr = _assuan_domain_init (r_ctx, rendezvousfd, peer);
  if (aerr)
    return aerr;

  /* Initial handshake.  */
  aerr = _assuan_read_from_server (*r_ctx, &okay, &off);
  if (aerr)
    LOG ("can't connect to server: %s\n", assuan_strerror (aerr));
  else if (okay != 1)
    {
      LOG ("can't connect to server: `");
      _assuan_log_sanitized_string ((*r_ctx)->inbound.line);
      fprintf (assuan_get_assuan_log_stream (), "'\n");
      aerr = ASSUAN_Connect_Failed;
    }

  if (aerr)
    assuan_disconnect (*r_ctx);

  return aerr;
}
