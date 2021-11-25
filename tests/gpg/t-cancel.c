/* t-thread-cancel.c - Regression test.
 * Copyright (C) 2000 Werner Koch (dd9jn)
 * Copyright (C) 2001, 2003, 2004 g10 Code GmbH
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

/* We need to include config.h so that we know whether we are building
   with large file system (LFS) support. */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#ifdef HAVE_POLL_H
# include <poll.h>
#else
# ifdef HAVE_SYS_SELECT_H
#  include <sys/select.h>
# else
#  ifdef HAVE_SYS_TIME_H
#   include <sys/time.h>
#  endif
# endif
#endif

#include <gpgme.h>

#include "t-support.h"

struct op_result
{
  int done;
  gpgme_error_t err;
};

static struct op_result op_result;

struct one_fd
{
  int fd;
  int dir;
  gpgme_io_cb_t fnc;
  void *fnc_data;
};

#define FDLIST_MAX 32
static struct one_fd fdlist[FDLIST_MAX];

static pthread_mutex_t lock;

static gpgme_error_t
add_io_cb (void *data, int fd, int dir, gpgme_io_cb_t fnc, void *fnc_data,
           void **r_tag)
{
  struct one_fd *fds = data;
  int i;

  pthread_mutex_lock (&lock);
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
  pthread_mutex_unlock (&lock);
  if (i == FDLIST_MAX)
    return gpgme_err_make (GPG_ERR_SOURCE_USER_1, GPG_ERR_GENERAL);
  *r_tag = &fds[i];
  return 0;
}

static void
remove_io_cb (void *tag)
{
  struct one_fd *fd = tag;

  pthread_mutex_lock (&lock);
  fd->fd = -1;
  pthread_mutex_unlock (&lock);
}

static void
io_event (void *data, gpgme_event_io_t type, void *type_data)
{
  struct op_result *result = data;

  if (type == GPGME_EVENT_DONE)
    {
      result->done = 1;
      result->err = * (gpgme_error_t *) type_data;
    }
}


#ifdef HAVE_POLL_H
static int
do_select (void)
{
  struct pollfd poll_fds[FDLIST_MAX];
  nfds_t poll_nfds;
  int i, n;
  int any = 0;

  pthread_mutex_lock (&lock);
  poll_nfds = 0;
  for (i = 0; i < FDLIST_MAX; i++)
    if (fdlist[i].fd != -1)
      {
        poll_fds[poll_nfds].fd = fdlist[i].fd;
        poll_fds[poll_nfds].events = 0;
        poll_fds[poll_nfds].revents = 0;
        if (fdlist[i].dir)
          poll_fds[poll_nfds].events |= POLLIN;
        else
          poll_fds[poll_nfds].events |= POLLOUT;
        poll_nfds++;
      }
  pthread_mutex_unlock (&lock);

  do
    {
      n = poll (poll_fds, poll_nfds, 1000);
    }
  while (n < 0 && (errno == EINTR || errno == EAGAIN));

  if (n < 0)
    return n;	/* Error or timeout.  */

  pthread_mutex_lock (&lock);
  poll_nfds = 0;
  for (i = 0; i < FDLIST_MAX && n; i++)
    {
      if (fdlist[i].fd != -1)
	{
	  if ((poll_fds[poll_nfds++].revents
               & (fdlist[i].dir ? (POLLIN|POLLHUP) : POLLOUT)))
	    {
	      assert (n);
	      n--;
	      any = 1;
	      (*fdlist[i].fnc) (fdlist[i].fnc_data, fdlist[i].fd);
	    }
	}
    }
  pthread_mutex_unlock (&lock);
  return any;
}
#else
static int
do_select (void)
{
  fd_set rfds;
  fd_set wfds;
  int i, n;
  int any = 0;
  struct timeval tv;

  pthread_mutex_lock (&lock);
  FD_ZERO (&rfds);
  FD_ZERO (&wfds);
  for (i = 0; i < FDLIST_MAX; i++)
    if (fdlist[i].fd != -1)
      FD_SET (fdlist[i].fd, fdlist[i].dir ? &rfds : &wfds);
  pthread_mutex_unlock (&lock);

  tv.tv_sec = 0;
  tv.tv_usec = 1000;

  do
    {
      n = select (FD_SETSIZE, &rfds, &wfds, NULL, &tv);
    }
  while (n < 0 && errno == EINTR);

  if (n < 0)
    return n;   /* Error or timeout.  */

  pthread_mutex_lock (&lock);
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
  pthread_mutex_unlock (&lock);
  return any;
}
#endif

static int
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


static struct gpgme_io_cbs io_cbs =
  {
    add_io_cb,
    fdlist,
    remove_io_cb,
    io_event,
    &op_result
  };


static void *
thread_cancel (void *data)
{
  gpgme_ctx_t ctx = data;
  gpgme_error_t err;

  usleep (100000);
  err = gpgme_cancel (ctx);
  fail_if_err (err);

  return NULL;
}

int
main (void)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_engine_info_t info;
  int i;
  pthread_mutexattr_t attr;
  pthread_t tcancel;
  const char *parms = "<GnupgKeyParms format=\"internal\">\n"
    "Key-Type: RSA\n"
    "Key-Length: 2048\n"
    "Subkey-Type: RSA\n"
    "Subkey-Length: 2048\n"
    "Name-Real: Joe Tester\n"
    "Name-Comment: (pp=abc)\n"
    "Name-Email: joe@foo.bar\n"
    "Expire-Date: 0\n"
    "Passphrase: abc\n"
    "</GnupgKeyParms>\n";

  init_gpgme (GPGME_PROTOCOL_OpenPGP);

  err = gpgme_get_engine_info (&info);
  fail_if_err (err);

  /* The mutex must be recursive, since remove_io_cb (which acquires a
     lock) can be called while holding a lock acquired in do_select.  */
  pthread_mutexattr_init (&attr);
  pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init (&lock, &attr);
  pthread_mutexattr_destroy (&attr);

  for (i = 0; i < FDLIST_MAX; i++)
    fdlist[i].fd = -1;

  err = gpgme_new (&ctx);
  fail_if_err (err);
  gpgme_set_armor (ctx, 1);
  gpgme_set_io_cbs (ctx, &io_cbs);
  op_result.done = 0;

  pthread_create (&tcancel, NULL, thread_cancel, ctx);

  err = gpgme_op_genkey_start (ctx, parms, NULL, NULL);
  fail_if_err (err);

  my_wait ();

  pthread_join (tcancel, NULL);

  if (op_result.err)
    {
      if (gpgme_err_code (op_result.err) == GPG_ERR_CANCELED)
	fputs ("Successfully cancelled\n", stdout);
      else
	{
	  fprintf (stderr,
		   "%s:%i: Operation finished with unexpected error: %s\n",
		   __FILE__, __LINE__, gpgme_strerror (op_result.err));
	  exit (1);
	}
    }
  else
    fputs ("Successfully finished before cancellation\n", stdout);

  gpgme_release (ctx);

  return 0;
}
