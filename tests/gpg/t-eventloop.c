/* t-eventloop.c - Regression test.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003, 2004 g10 Code GmbH

   This file is part of GPGME.

   GPGME is free software; you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   GPGME is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

/* We need to include config.h so that we know whether we are building
   with large file system (LFS) support. */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/select.h>

#include <gpgme.h>

#include "t-support.h"


/* Stripped down version of gpgme/wait.c.  */

struct op_result
{
  int done;
  gpgme_error_t err;
};

struct op_result op_result;

struct one_fd
{
  int fd;
  int dir;
  gpgme_io_cb_t fnc;
  void *fnc_data;
};

#define FDLIST_MAX 32
struct one_fd fdlist[FDLIST_MAX];

gpgme_error_t
add_io_cb (void *data, int fd, int dir, gpgme_io_cb_t fnc, void *fnc_data,
	   void **r_tag)
{
  struct one_fd *fds = data;
  int i;

  for (i = 0; i < FDLIST_MAX; i++)
    {
      if (fds[i].fd == -1)
	{
	  fds[i].fd = fd;
	  fds[i].dir = dir;
	  fds[i].fnc = fnc;
	  fds[i].fnc_data = fnc_data;
	  break;
	}
    }
  if (i == FDLIST_MAX)
    return gpgme_err_make (GPG_ERR_SOURCE_USER_1, GPG_ERR_GENERAL);
  *r_tag = &fds[i];
  return 0;
}

void
remove_io_cb (void *tag)
{
  struct one_fd *fd = tag;

  fd->fd = -1;
}

void
io_event (void *data, gpgme_event_io_t type, void *type_data)
{
  struct op_result *result = data;

  if (type == GPGME_EVENT_DONE)
    {
      result->done = 1;
      result->err = * (gpgme_error_t *) type_data;
    }
}


int
do_select (void)
{
  fd_set rfds;
  fd_set wfds;
  int i, n;
  int any = 0;

  FD_ZERO (&rfds);
  FD_ZERO (&wfds);
  for (i = 0; i < FDLIST_MAX; i++)
    if (fdlist[i].fd != -1)
      FD_SET (fdlist[i].fd, fdlist[i].dir ? &rfds : &wfds);

  do
    {
      n = select (FD_SETSIZE, &rfds, &wfds, NULL, 0);
    }
  while (n < 0 && errno == EINTR);

  if (n < 0)
    return n;	/* Error or timeout.  */

  for (i = 0; i < FDLIST_MAX && n; i++)
    {
      if (fdlist[i].fd != -1)
	{
	  if (FD_ISSET (fdlist[i].fd, fdlist[i].dir ? &rfds : &wfds))
	    {
	      assert (n);
	      n--;
	      any = 1;
	      (*fdlist[i].fnc) (fdlist[i].fnc_data, fdlist[i].fd);
	    }
	}
    }
  return any;
}

int
my_wait (void)
{
  int n;

  do
    {
      n = do_select ();
    }
  while (n >= 0 && !op_result.done);
  return 0;
}


struct gpgme_io_cbs io_cbs =
  {
    add_io_cb,
    fdlist,
    remove_io_cb,
    io_event,
    &op_result
  };


int
main (void)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_data_t in, out;
  gpgme_key_t key[3] = { NULL, NULL, NULL };
  int i;

  init_gpgme (GPGME_PROTOCOL_OpenPGP);

  for (i = 0; i < FDLIST_MAX; i++)
    fdlist[i].fd = -1;

  err = gpgme_engine_check_version (GPGME_PROTOCOL_OpenPGP);
  fail_if_err (err);

  err = gpgme_new (&ctx);
  fail_if_err (err);
  gpgme_set_armor (ctx, 1);
  gpgme_set_io_cbs (ctx, &io_cbs);
  op_result.done = 0;

  err = gpgme_data_new_from_mem (&in, "Hallo Leute\n", 12, 0);
  fail_if_err (err);

  err = gpgme_data_new (&out);
  fail_if_err (err);

  err = gpgme_get_key (ctx, "A0FF4590BB6122EDEF6E3C542D727CC768697734",
		       &key[0], 0);
  fail_if_err (err);
  err = gpgme_get_key (ctx, "D695676BDCEDCC2CDD6152BCFE180B1DA9E3B0B2",
		       &key[1], 0);
  fail_if_err (err);

  err = gpgme_op_encrypt_start (ctx, key, GPGME_ENCRYPT_ALWAYS_TRUST, in, out);
  fail_if_err (err);

  my_wait ();
  fail_if_err (op_result.err);
  fail_if_err (err);

  fflush (NULL);
  fputs ("Begin Result:\n", stdout);
  print_data (out);
  fputs ("End Result.\n", stdout);

  gpgme_key_unref (key[0]);
  gpgme_key_unref (key[1]);
  gpgme_data_release (in);
  gpgme_data_release (out);
  gpgme_release (ctx);

  return 0;
}
