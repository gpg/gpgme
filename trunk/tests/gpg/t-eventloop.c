/* t-eventloop.c  - regression test
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/select.h>

#include <gpgme.h>

#define fail_if_err(a) do { if(a) {                                       \
                               fprintf (stderr, "%s:%d: GpgmeError %s\n", \
                                __FILE__, __LINE__, gpgme_strerror(a));   \
                                exit (1); }                               \
                             } while(0)

static void
print_op_info (GpgmeCtx ctx)
{
  char *str = gpgme_get_op_info (ctx, 0);

  if (!str)
    puts ("<!-- no operation info available -->");
  else
    {
      puts (str);
      free (str);
    }
}


static void
print_data (GpgmeData dh)
{
  char buf[100];
  int ret;
  
  ret = gpgme_data_seek (dh, 0, SEEK_SET);
  if (ret)
    fail_if_err (GPGME_File_Error);
  while ((ret = gpgme_data_read (dh, buf, 100)) > 0)
    fwrite (buf, ret, 1, stdout);
  if (ret < 0)
    fail_if_err (GPGME_File_Error);
}


/* Stripped down version of gpgme/wait.c.  */

struct op_result
{
  int done;
  GpgmeError err;
};

struct op_result op_result;

struct one_fd
{
  int fd;
  int dir;
  GpgmeIOCb fnc;
  void *fnc_data;
};

#define FDLIST_MAX 32
struct one_fd fdlist[FDLIST_MAX];

GpgmeError
add_io_cb (void *data, int fd, int dir, GpgmeIOCb fnc, void *fnc_data,
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
    return GPGME_General_Error;
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
io_event (void *data, GpgmeEventIO type, void *type_data)
{
  struct op_result *result = data;

  if (type == GPGME_EVENT_DONE)
    {
      result->done = 1;
      result->err = * (GpgmeError *) type_data;
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

struct GpgmeIOCbs io_cbs =
  {
    add_io_cb,
    fdlist,
    remove_io_cb,
    io_event,
    &op_result
  };

int 
main (int argc, char *argv[])
{
  GpgmeCtx ctx;
  GpgmeError err;
  GpgmeData in, out;
  GpgmeRecipients rset;
  int i;

  for (i = 0; i < FDLIST_MAX; i++)
    fdlist[i].fd = -1;

  err = gpgme_engine_check_version (GPGME_PROTOCOL_OpenPGP);
  fail_if_err (err);
  puts (gpgme_get_engine_info ());

  do
    {
      err = gpgme_new (&ctx);
      fail_if_err (err);
      gpgme_set_armor (ctx, 1);
      gpgme_set_io_cbs (ctx, &io_cbs);
      op_result.done = 0;

      err = gpgme_data_new_from_mem (&in, "Hallo Leute\n", 12, 0);
      fail_if_err (err);

      err = gpgme_data_new (&out);
      fail_if_err (err);

      err = gpgme_recipients_new (&rset);
      fail_if_err (err);
      err = gpgme_recipients_add_name_with_validity (rset, "Bob",
						     GPGME_VALIDITY_FULL);
      fail_if_err (err);
      err = gpgme_recipients_add_name_with_validity (rset, "Alpha",
						     GPGME_VALIDITY_FULL);
      fail_if_err (err);

      err = gpgme_op_encrypt_start (ctx, rset, in, out);
      fail_if_err (err);

      my_wait ();
      fail_if_err (op_result.err);
      print_op_info (ctx);
      fail_if_err (err);

      fflush (NULL);
      fputs ("Begin Result:\n", stdout);
      print_data (out);
      fputs ("End Result.\n", stdout);
   
      gpgme_recipients_release (rset);
      gpgme_data_release (in);
      gpgme_data_release (out);
      gpgme_release (ctx);
    }
  while (argc > 1 && !strcmp (argv[1], "--loop"));

  return 0;
}


