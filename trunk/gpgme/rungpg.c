/* rungpg.c 
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
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <signal.h>
#include <fcntl.h>
#include "unistd.h"

#include "gpgme.h"
#include "util.h"
#include "ops.h"
#include "wait.h"
#include "rungpg.h"
#include "context.h"  /*temp hack until we have GpmeData methods to do I/O */
#include "io.h"
#include "sema.h"

#include "status-table.h"


/* This type is used to build a list of gpg arguments and data
   sources/sinks.  */
struct arg_and_data_s
{
  struct arg_and_data_s *next;
  GpgmeData data;  /* If this is not NULL, use arg below.  */
  int inbound;     /* True if this is used for reading from gpg.  */
  int dup_to;
  int print_fd;    /* Print the fd number and not the special form of it.  */
  char arg[1];     /* Used if data above is not used.  */
};

struct fd_data_map_s
{
  GpgmeData data;
  int inbound;  /* true if this is used for reading from gpg */
  int dup_to;
  int fd;       /* the fd to use */
  int peer_fd;  /* the outher side of the pipe */
  void *tag;
};


struct gpg_object_s
{
  struct arg_and_data_s *arglist;
  struct arg_and_data_s **argtail;
  int arg_error;  

  struct
  {
    int fd[2];  
    size_t bufsize;
    char *buffer;
    size_t readpos;
    int eof;
    GpgStatusHandler fnc;
    void *fnc_value;
    void *tag;
  } status;

  /* This is a kludge - see the comment at gpg_colon_line_handler */
  struct
  {
    int fd[2];  
    size_t bufsize;
    char *buffer;
    size_t readpos;
    int eof;
    GpgColonLineHandler fnc;  /* this indicate use of this structrue */
    void *fnc_value;
    void *tag;
    int simple;
  } colon;

  char **argv;  
  struct fd_data_map_s *fd_data_map;

  /* stuff needed for pipemode */
  struct
  {
    int used;
    int active;
    GpgmeData sig;
    GpgmeData text;
    int stream_started;
  } pm;

  /* stuff needed for interactive (command) mode */
  struct
  {
    int used;
    int fd;
    int idx;		/* Index in fd_data_map */
    GpgmeData cb_data;   /* hack to get init the above idx later */
    GpgmeStatusCode code;  /* last code */
    char *keyword;       /* what has been requested (malloced) */
    GpgCommandHandler fnc; 
    void *fnc_value;
    /* The kludges never end.  This is used to couple command handlers
       with output data in edit key mode.  */
    GpgmeData linked_data;
    int linked_idx;
  } cmd;

  struct GpgmeIOCbs io_cbs;
};

static void free_argv (char **argv);
static void free_fd_data_map (struct fd_data_map_s *fd_data_map);

static void gpg_status_handler (void *opaque, int fd);
static GpgmeError read_status (GpgObject gpg);

static void gpg_colon_line_handler (void *opaque, int fd);
static GpgmeError read_colon_line (GpgObject gpg);

static int pipemode_cb (void *opaque, char *buffer, size_t length,
			size_t *nread);
static int command_cb (void *opaque, char *buffer, size_t length,
		       size_t *nread);

static void
close_notify_handler (int fd, void *opaque)
{
  GpgObject gpg = opaque;
  int possibly_done = 0;
  int not_done = 0;
  assert (fd != -1);

  if (gpg->status.fd[0] == fd)
    {
      if (gpg->status.tag)
	{
	  (*gpg->io_cbs.remove) (gpg->status.tag);
	  possibly_done = 1;
	}
      gpg->status.fd[0] = -1;
    }
  else if (gpg->status.fd[1] == fd)
    gpg->status.fd[1] = -1;
  else if (gpg->colon.fd[0] == fd)
    {
      if (gpg->colon.tag)
	{
	  (*gpg->io_cbs.remove) (gpg->colon.tag);
	  possibly_done = 1;
	}
      gpg->colon.fd[0] = -1;
    }
  else if (gpg->colon.fd[1] == fd)
    gpg->colon.fd[1] = -1;
  else if (gpg->fd_data_map)
    {
      int i;

      for (i = 0; gpg->fd_data_map[i].data; i++)
	{
	  if (gpg->fd_data_map[i].fd == fd)
	    {
	      if (gpg->fd_data_map[i].tag)
		{
		  (*gpg->io_cbs.remove) (gpg->fd_data_map[i].tag);
		  possibly_done = 1;
		}
	      gpg->fd_data_map[i].fd = -1;
	      break;
            }
	  if (gpg->fd_data_map[i].peer_fd == fd)
	    {
	      gpg->fd_data_map[i].peer_fd = -1;
	      break;
            }
        }
    }
  if (!possibly_done)
    not_done = 1;
  else if (gpg->status.fd[0] != -1)
    not_done = 1;
  else if (gpg->colon.fd[0] != -1)
    not_done = 1;
  else if (gpg->fd_data_map)
    {
      int i;

      for (i = 0; gpg->fd_data_map[i].data; i++)
	if (gpg->fd_data_map[i].fd != -1)
	  {
	    not_done = 1;
	    break;
	  }
    }
  if (!not_done)
    _gpgme_gpg_io_event (gpg, GPGME_EVENT_DONE, NULL);
}

const char *
_gpgme_gpg_get_version (void)
{
  static const char *gpg_version;
  DEFINE_STATIC_LOCK (gpg_version_lock);

  LOCK (gpg_version_lock);
  if (!gpg_version)
    gpg_version = _gpgme_get_program_version (_gpgme_get_gpg_path ());
  UNLOCK (gpg_version_lock);
  return gpg_version;
}

GpgmeError
_gpgme_gpg_check_version (void)
{
  return _gpgme_compare_versions (_gpgme_gpg_get_version (),
                                  NEED_GPG_VERSION)
    ? 0 : mk_error (Invalid_Engine);
}

GpgmeError
_gpgme_gpg_new (GpgObject *r_gpg)
{
  GpgObject gpg;
  int rc = 0;

  gpg = calloc (1, sizeof *gpg);
  if (!gpg)
    {
      rc = mk_error (Out_Of_Core);
      goto leave;
    }
  gpg->argtail = &gpg->arglist;

  gpg->status.fd[0] = -1;
  gpg->status.fd[1] = -1;
  gpg->colon.fd[0] = -1;
  gpg->colon.fd[1] = -1;
  gpg->cmd.fd = -1;
  gpg->cmd.idx = -1;
  gpg->cmd.linked_data = NULL;
  gpg->cmd.linked_idx = -1;

  /* Allocate the read buffer for the status pipe.  */
  gpg->status.bufsize = 1024;
  gpg->status.readpos = 0;
  gpg->status.buffer = malloc (gpg->status.bufsize);
  if (!gpg->status.buffer)
    {
      rc = mk_error (Out_Of_Core);
      goto leave;
    }
  /* In any case we need a status pipe - create it right here and
     don't handle it with our generic GpgmeData mechanism.  */
  if (_gpgme_io_pipe (gpg->status.fd, 1) == -1)
    {
      rc = mk_error (Pipe_Error);
      goto leave;
    }
  if (_gpgme_io_set_close_notify (gpg->status.fd[0],
				  close_notify_handler, gpg)
      || _gpgme_io_set_close_notify (gpg->status.fd[1],
				     close_notify_handler, gpg))
    {
      rc = mk_error (General_Error);
      goto leave;
    }
  gpg->status.eof = 0;
  _gpgme_gpg_add_arg (gpg, "--status-fd");
  {
    char buf[25];
    sprintf (buf, "%d", gpg->status.fd[1]);
    _gpgme_gpg_add_arg (gpg, buf);
  }
  _gpgme_gpg_add_arg (gpg, "--no-tty");
  _gpgme_gpg_add_arg (gpg, "--charset");
  _gpgme_gpg_add_arg (gpg, "utf8");

 leave:
  if (rc)
    {
      _gpgme_gpg_release (gpg);
      *r_gpg = NULL;
    }
  else
    *r_gpg = gpg;
  return rc;
}


void
_gpgme_gpg_release (GpgObject gpg)
{
  if (!gpg)
    return;

  while (gpg->arglist)
    {
      struct arg_and_data_s *next = gpg->arglist->next;

      free (gpg->arglist);
      gpg->arglist = next;
    }

  free (gpg->status.buffer);
  free (gpg->colon.buffer);
  if (gpg->argv)
    free_argv (gpg->argv);
  gpgme_data_release (gpg->cmd.cb_data);
  free (gpg->cmd.keyword);

  if (gpg->status.fd[0] != -1)
    _gpgme_io_close (gpg->status.fd[0]);
  if (gpg->status.fd[1] != -1)
    _gpgme_io_close (gpg->status.fd[1]);
  if (gpg->colon.fd[0] != -1)
    _gpgme_io_close (gpg->colon.fd[0]);
  if (gpg->colon.fd[1] != -1)
    _gpgme_io_close (gpg->colon.fd[1]);
  free_fd_data_map (gpg->fd_data_map);
  if (gpg->cmd.fd != -1)
    _gpgme_io_close (gpg->cmd.fd);
  free (gpg);
}

void
_gpgme_gpg_enable_pipemode ( GpgObject gpg )
{
    gpg->pm.used = 1;
    assert ( !gpg->pm.sig );
    assert ( !gpg->pm.text );
}
    
GpgmeError
_gpgme_gpg_add_arg ( GpgObject gpg, const char *arg )
{
    struct arg_and_data_s *a;

    assert (gpg);
    assert (arg);

    if (gpg->pm.active)
        return 0;

    a = malloc ( sizeof *a + strlen (arg) );
    if ( !a ) {
        gpg->arg_error = 1;
        return mk_error(Out_Of_Core);
    }
    a->next = NULL;
    a->data = NULL;
    a->dup_to = -1;
    strcpy ( a->arg, arg );
    *gpg->argtail = a;
    gpg->argtail = &a->next;
    return 0;
}

GpgmeError
_gpgme_gpg_add_data (GpgObject gpg, GpgmeData data, int dup_to, int inbound)
{
  struct arg_and_data_s *a;

  assert (gpg);
  assert (data);
  if (gpg->pm.active)
    return 0;

  a = malloc (sizeof *a - 1);
  if (!a)
    {
      gpg->arg_error = 1;
      return mk_error(Out_Of_Core);
    }
  a->next = NULL;
  a->data = data;
  a->inbound = inbound;
  if (dup_to == -2)
    {
      a->print_fd = 1;
      a->dup_to = -1;
    }
  else
    {
      a->print_fd = 0;
      a->dup_to = dup_to;
    }
  *gpg->argtail = a;
  gpg->argtail = &a->next;
  return 0;
}

GpgmeError
_gpgme_gpg_add_pm_data ( GpgObject gpg, GpgmeData data, int what )
{
    GpgmeError rc=0;

    assert ( gpg->pm.used );
    
    if ( !what ) {
        /* the signature */
        assert ( !gpg->pm.sig );
        gpg->pm.sig = data;
    }
    else if (what == 1) {
        /* the signed data */
        assert ( !gpg->pm.text );
        gpg->pm.text = data;
    }
    else {
        assert (0);
    }

    if ( gpg->pm.sig && gpg->pm.text ) {
        if ( !gpg->pm.active ) {
            /* create the callback handler and connect it to stdin */
            GpgmeData tmp;
            
            rc = gpgme_data_new_with_read_cb ( &tmp, pipemode_cb, gpg );
            if (!rc )
                rc = _gpgme_gpg_add_data (gpg, tmp, 0, 0);
        }
        if ( !rc ) {
            /* here we can reset the handler stuff */
            gpg->pm.stream_started = 0;
        }
    }

    return rc;
}

/*
 * Note, that the status_handler is allowed to modifiy the args value
 */
void
_gpgme_gpg_set_status_handler ( GpgObject gpg,
                                GpgStatusHandler fnc, void *fnc_value ) 
{
    assert (gpg);
    if (gpg->pm.active)
        return;

    gpg->status.fnc = fnc;
    gpg->status.fnc_value = fnc_value;
}

/* Kludge to process --with-colon output */
GpgmeError
_gpgme_gpg_set_colon_line_handler ( GpgObject gpg,
                                    GpgColonLineHandler fnc, void *fnc_value ) 
{
    assert (gpg);
    if (gpg->pm.active)
        return 0;

    gpg->colon.bufsize = 1024;
    gpg->colon.readpos = 0;
    gpg->colon.buffer = malloc (gpg->colon.bufsize);
    if (!gpg->colon.buffer) {
        return mk_error (Out_Of_Core);
    }
    if (_gpgme_io_pipe (gpg->colon.fd, 1) == -1) {
        free (gpg->colon.buffer); gpg->colon.buffer = NULL;
        return mk_error (Pipe_Error);
    }
    if ( _gpgme_io_set_close_notify (gpg->colon.fd[0],
                                     close_notify_handler, gpg)
         ||  _gpgme_io_set_close_notify (gpg->colon.fd[1],
                                         close_notify_handler, gpg) ) {
        return mk_error (General_Error);
    }
    gpg->colon.eof = 0;
    gpg->colon.fnc = fnc;
    gpg->colon.fnc_value = fnc_value;
    gpg->colon.simple = 0;
    return 0;
}


GpgmeError
_gpgme_gpg_set_simple_line_handler ( GpgObject gpg,
                                     GpgColonLineHandler fnc,
                                     void *fnc_value ) 
{
    GpgmeError err;

    err = _gpgme_gpg_set_colon_line_handler (gpg, fnc, fnc_value);
    if (!err)
        gpg->colon.simple = 1;
    return err;
}


/* 
 * The Fnc will be called to get a value for one of the commands with
 * a key KEY.  If the Code pssed to FNC is 0, the function may release
 * resources associated with the returned value from another call.  To
 * match such a second call to a first call, the returned value from
 * the first call is passed as keyword.
 */

GpgmeError
_gpgme_gpg_set_command_handler (GpgObject gpg,
				GpgCommandHandler fnc, void *fnc_value,
				GpgmeData linked_data)
{
  GpgmeData tmp;
  GpgmeError err;

  assert (gpg);
  if (gpg->pm.active)
    return 0;

  err = gpgme_data_new_with_read_cb (&tmp, command_cb, gpg);
  if (err)
    return err;
        
  _gpgme_gpg_add_arg (gpg, "--command-fd");
  _gpgme_gpg_add_data (gpg, tmp, -2, 0);
  gpg->cmd.cb_data = tmp;
  gpg->cmd.fnc = fnc;
  gpg->cmd.fnc_value = fnc_value;
  gpg->cmd.linked_data = linked_data;
  gpg->cmd.used = 1;
  return 0;
}


static void
free_argv ( char **argv )
{
    int i;

    for (i=0; argv[i]; i++ )
        free (argv[i]);
    free (argv);
}

static void
free_fd_data_map ( struct fd_data_map_s *fd_data_map )
{
    int i;

    if ( !fd_data_map )
        return;

    for (i=0; fd_data_map[i].data; i++ ) {
        if ( fd_data_map[i].fd != -1 )
            _gpgme_io_close (fd_data_map[i].fd);
        if ( fd_data_map[i].peer_fd != -1 )
            _gpgme_io_close (fd_data_map[i].peer_fd);
        /* don't release data because this is only a reference */
    }
    free (fd_data_map);
}


static GpgmeError
build_argv (GpgObject gpg)
{
  struct arg_and_data_s *a;
  struct fd_data_map_s *fd_data_map;
  size_t datac=0, argc=0;  
  char **argv;
  int need_special = 0;
  int use_agent = 0;
  char *p;

  /* We don't want to use the agent with a malformed environment
     variable.  This is only a very basic test but sufficient to make
     our life in the regression tests easier. */
  p = getenv ("GPG_AGENT_INFO");
  use_agent = (p && strchr (p, ':'));
       
  if (gpg->argv)
    {
      free_argv (gpg->argv);
      gpg->argv = NULL;
    }
  if (gpg->fd_data_map)
    {
      free_fd_data_map (gpg->fd_data_map);
      gpg->fd_data_map = NULL;
    }

  argc++;	/* For argv[0].  */
  for (a = gpg->arglist; a; a = a->next)
    {
      argc++;
      if (a->data)
	{
	  /*fprintf (stderr, "build_argv: data\n" );*/
	  datac++;
	  if (a->dup_to == -1 && !a->print_fd)
	    need_special = 1;
        }
      else
	{
	  /*   fprintf (stderr, "build_argv: arg=`%s'\n", a->arg );*/
        }
    }
  if (need_special)
    argc++;
  if (use_agent)
    argc++;
  if (!gpg->cmd.used)
    argc++;
  argc += 2; /* --comment */

  argv = calloc (argc + 1, sizeof *argv);
  if (!argv)
    return mk_error (Out_Of_Core);
  fd_data_map = calloc (datac + 1, sizeof *fd_data_map);
  if (!fd_data_map)
    {
      free_argv (argv);
      return mk_error (Out_Of_Core);
    }

  argc = datac = 0;
  argv[argc] = strdup ("gpg"); /* argv[0] */
  if (!argv[argc])
    {
      free (fd_data_map);
      free_argv (argv);
      return mk_error (Out_Of_Core);
    }
  argc++;
  if (need_special)
    {
      argv[argc] = strdup ("--enable-special-filenames");
      if (!argv[argc])
	{
	  free (fd_data_map);
	  free_argv (argv);
	  return mk_error (Out_Of_Core);
        }
      argc++;
    }
  if (use_agent)
    {
      argv[argc] = strdup ("--use-agent");
      if (!argv[argc])
	{
	  free (fd_data_map);
	  free_argv (argv);
	  return mk_error (Out_Of_Core);
        }
      argc++;
    }
  if (!gpg->cmd.used)
    {
      argv[argc] = strdup ("--batch");
      if (!argv[argc])
	{
	  free (fd_data_map);
	  free_argv (argv);
	  return mk_error (Out_Of_Core);
        }
      argc++;
    }
  argv[argc] = strdup ("--comment");
  if (!argv[argc])
    {
      free (fd_data_map);
      free_argv (argv);
      return mk_error (Out_Of_Core);
    }
  argc++;
  argv[argc] = strdup ("");
  if (!argv[argc])
    {
      free (fd_data_map);
      free_argv (argv);
      return mk_error (Out_Of_Core);
    }
  argc++;
  for (a = gpg->arglist; a; a = a->next)
    {
      if (a->data)
	{
	  /* Create a pipe to pass it down to gpg.  */
	  fd_data_map[datac].inbound = a->inbound;

	  /* Create a pipe.  */
	  {   
	    int fds[2];
	    
	    if (_gpgme_io_pipe (fds, fd_data_map[datac].inbound ? 1 : 0)
		== -1)
	      {
		free (fd_data_map);
		free_argv (argv);
		return mk_error (Pipe_Error);
	      }
	    if (_gpgme_io_set_close_notify (fds[0],
					    close_notify_handler, gpg)
		|| _gpgme_io_set_close_notify (fds[1],
					       close_notify_handler,
					       gpg))
	      {
		return mk_error (General_Error);
	      }
	    /* If the data_type is FD, we have to do a dup2 here.  */
	    if (fd_data_map[datac].inbound)
	      {
		fd_data_map[datac].fd       = fds[0];
		fd_data_map[datac].peer_fd  = fds[1];
	      }
	    else
	      {
		fd_data_map[datac].fd       = fds[1];
		fd_data_map[datac].peer_fd  = fds[0];
	      }
	  }

	  /* Hack to get hands on the fd later.  */
	  if (gpg->cmd.used)
	    {
	      if (gpg->cmd.cb_data == a->data)
		{
		  assert (gpg->cmd.idx == -1);
		  gpg->cmd.idx = datac;
		}
	      else if (gpg->cmd.linked_data == a->data)
		{
		  assert (gpg->cmd.linked_idx == -1);
		  gpg->cmd.linked_idx = datac;
		}
	    }

	  fd_data_map[datac].data = a->data;
	  fd_data_map[datac].dup_to = a->dup_to;
	  if (a->dup_to == -1)
	    {
	      argv[argc] = malloc (25);
	      if (!argv[argc])
		{
		  free (fd_data_map);
		  free_argv (argv);
		  return mk_error (Out_Of_Core);
                }
	      sprintf (argv[argc], 
		       a->print_fd ? "%d" : "-&%d",
		       fd_data_map[datac].peer_fd);
	      argc++;
            }
	  datac++;
        }
      else
	{
	  argv[argc] = strdup (a->arg);
	  if (!argv[argc])
	    {
	      free (fd_data_map);
	      free_argv (argv);
	      return mk_error (Out_Of_Core);
            }
            argc++;
        }
    }

  gpg->argv = argv;
  gpg->fd_data_map = fd_data_map;
  return 0;
}

static GpgmeError
_gpgme_gpg_add_io_cb (GpgObject gpg, int fd, int dir,
		      GpgmeIOCb handler, void *data, void **tag)
{
  GpgmeError err;

  err = (*gpg->io_cbs.add) (gpg->io_cbs.add_priv, fd, dir, handler, data, tag);
  if (err)
    return err;
  if (!dir)
    /* FIXME Kludge around poll() problem.  */
    err = _gpgme_io_set_nonblocking (fd);
  return err;
}

GpgmeError
_gpgme_gpg_spawn (GpgObject gpg, void *opaque)
{
  GpgmeError rc;
  int i, n;
  int status;
  struct spawn_fd_item_s *fd_child_list, *fd_parent_list;

  if (!gpg)
    return mk_error (Invalid_Value);

  if (! _gpgme_get_gpg_path ())
    return mk_error (Invalid_Engine);

  /* Kludge, so that we don't need to check the return code of all the
     gpgme_gpg_add_arg().  we bail out here instead */
  if (gpg->arg_error)
    return mk_error (Out_Of_Core);

  if (gpg->pm.active)
    return 0;

  rc = build_argv (gpg);
  if (rc)
    return rc;

  n = 3; /* status_fd, colon_fd and end of list */
  for (i = 0; gpg->fd_data_map[i].data; i++) 
    n++;
  fd_child_list = calloc (n + n, sizeof *fd_child_list);
  if (!fd_child_list)
    return mk_error (Out_Of_Core);
  fd_parent_list = fd_child_list + n;

  /* build the fd list for the child */
  n = 0;
  if (gpg->colon.fnc)
    {
      fd_child_list[n].fd = gpg->colon.fd[1]; 
      fd_child_list[n].dup_to = 1; /* dup to stdout */
      n++;
    }
  for (i = 0; gpg->fd_data_map[i].data; i++)
    {
      if (gpg->fd_data_map[i].dup_to != -1)
	{
	  fd_child_list[n].fd = gpg->fd_data_map[i].peer_fd;
	  fd_child_list[n].dup_to = gpg->fd_data_map[i].dup_to;
	  n++;
        }
    }
  fd_child_list[n].fd = -1;
  fd_child_list[n].dup_to = -1;

  /* Build the fd list for the parent.  */
  n = 0;
  if (gpg->status.fd[1] != -1)
    {
      fd_parent_list[n].fd = gpg->status.fd[1];
      fd_parent_list[n].dup_to = -1;
      n++;
      gpg->status.fd[1] = -1;
    }
  if (gpg->colon.fd[1] != -1)
    {
      fd_parent_list[n].fd = gpg->colon.fd[1];
      fd_parent_list[n].dup_to = -1;
      n++;
      gpg->colon.fd[1] = -1;
    }
  for (i = 0; gpg->fd_data_map[i].data; i++)
    {
      fd_parent_list[n].fd = gpg->fd_data_map[i].peer_fd;
      fd_parent_list[n].dup_to = -1;
      n++;
      gpg->fd_data_map[i].peer_fd = -1;
    }        
  fd_parent_list[n].fd = -1;
  fd_parent_list[n].dup_to = -1;

  status = _gpgme_io_spawn (_gpgme_get_gpg_path (),
			    gpg->argv, fd_child_list, fd_parent_list);
  free (fd_child_list);
  if (status == -1)
    return mk_error (Exec_Error);

  if (gpg->pm.used)
    gpg->pm.active = 1;

  /*_gpgme_register_term_handler ( closure, closure_value, pid );*/

  rc = _gpgme_gpg_add_io_cb (gpg, gpg->status.fd[0], 1,
			     gpg_status_handler, gpg, &gpg->status.tag);
  if (rc)
    /* FIXME: kill the child */
    return rc;

  if (gpg->colon.fnc)
    {
      assert (gpg->colon.fd[0] != -1);
      rc = _gpgme_gpg_add_io_cb (gpg, gpg->colon.fd[0], 1,
				 gpg_colon_line_handler, gpg,
				 &gpg->colon.tag);
      if (rc)
	/* FIXME: kill the child */
	return rc;
    }

  for (i = 0; gpg->fd_data_map[i].data; i++)
    {
      if (gpg->cmd.used && i == gpg->cmd.idx)
	{
	  /* Park the cmd fd.  */
	  gpg->cmd.fd = gpg->fd_data_map[i].fd;
	  gpg->fd_data_map[i].fd = -1;
	}
      else
	{
	  rc = _gpgme_gpg_add_io_cb (gpg, gpg->fd_data_map[i].fd,
				     gpg->fd_data_map[i].inbound,
				     gpg->fd_data_map[i].inbound
				     ? _gpgme_data_inbound_handler
				     : _gpgme_data_outbound_handler,
				     gpg->fd_data_map[i].data,
				     &gpg->fd_data_map[i].tag);
	  
	  if (rc)
	    /* FIXME: kill the child */
	    return rc;
	}
    }
  
  /* fixme: check what data we can release here */
  return 0;
}


static void
gpg_status_handler (void *opaque, int fd)
{
  GpgObject gpg = opaque;
  int err;

  assert (fd == gpg->status.fd[0]);
  err = read_status (gpg);
  if (err)
    {
      /* XXX Horrible kludge.  We really must not make use of
	 fnc_value.  */
      GpgmeCtx ctx = (GpgmeCtx) gpg->status.fnc_value;
      ctx->error = err;
      DEBUG1 ("gpg_handler: read_status problem %d\n - stop", err);
      _gpgme_io_close (fd);
      return;
    }
  if (gpg->status.eof)
    _gpgme_io_close (fd);
}


static int
status_cmp (const void *ap, const void *bp)
{
    const struct status_table_s *a = ap;
    const struct status_table_s *b = bp;

    return strcmp (a->name, b->name);
}



/*
 * Handle the status output of GnuPG.  This function does read entire
 * lines and passes them as C strings to the callback function (we can
 * use C Strings because the status output is always UTF-8 encoded).
 * Of course we have to buffer the lines to cope with long lines
 * e.g. with a large user ID.  Note: We can optimize this to only cope
 * with status line code we know about and skip all other stuff
 * without buffering (i.e. without extending the buffer).  */
static GpgmeError
read_status (GpgObject gpg)
{
  char *p;
  int nread;
  size_t bufsize = gpg->status.bufsize; 
  char *buffer = gpg->status.buffer;
  size_t readpos = gpg->status.readpos; 

  assert (buffer);
  if (bufsize - readpos < 256)
    { 
      /* Need more room for the read.  */
      bufsize += 1024;
      buffer = realloc (buffer, bufsize);
      if (!buffer)
	return mk_error (Out_Of_Core);
    }

  nread = _gpgme_io_read (gpg->status.fd[0],
			  buffer + readpos, bufsize-readpos);
  if (nread == -1)
    return mk_error(Read_Error);

  if (!nread)
    {
      gpg->status.eof = 1;
      if (gpg->status.fnc)
	gpg->status.fnc (gpg->status.fnc_value, GPGME_STATUS_EOF, "");
      return 0;
    }

  while (nread > 0)
    {
      for (p = buffer + readpos; nread; nread--, p++)
	{
	  if (*p == '\n')
	    {
	      /* (we require that the last line is terminated by a LF) */
	      *p = 0;
	      if (!strncmp (buffer, "[GNUPG:] ", 9)
		  && buffer[9] >= 'A' && buffer[9] <= 'Z')
		{
		  struct status_table_s t, *r;
		  char *rest;

		  rest = strchr (buffer + 9, ' ');
		  if (!rest)
		    rest = p; /* Set to an empty string.  */
		  else
		    *rest++ = 0;
                    
		  t.name = buffer+9;
		  /* (the status table has one extra element) */
		  r = bsearch (&t, status_table, DIM(status_table) - 1,
			       sizeof t, status_cmp);
		  if (r)
		    {
		      if (gpg->cmd.used
			  && (r->code == GPGME_STATUS_GET_BOOL
			      || r->code == GPGME_STATUS_GET_LINE
			      || r->code == GPGME_STATUS_GET_HIDDEN))
			{
			  gpg->cmd.code = r->code;
			  free (gpg->cmd.keyword);
			  gpg->cmd.keyword = strdup (rest);
			  if (!gpg->cmd.keyword)
			    return mk_error (Out_Of_Core);
			  /* This should be the last thing we have
			     received and the next thing will be that
			     the command handler does its action.  */
			  if (nread > 1)
			    DEBUG0 ("ERROR, unexpected data in read_status");

			  /* Before we can actually add the command
			     fd, we might have to flush the linked
			     output data pipe.  */
			  if (gpg->cmd.linked_idx != -1
			      && gpg->fd_data_map[gpg->cmd.linked_idx].fd != -1)
			    {
			      struct io_select_fd_s fds;
			      fds.fd = gpg->fd_data_map[gpg->cmd.linked_idx].fd;
			      fds.for_read = 1;
			      fds.for_write = 0;
			      fds.frozen = 0;
			      fds.opaque = NULL;
			      do
				{
				  fds.signaled = 0;
				  _gpgme_io_select (&fds, 1, 1);
				  if (fds.signaled)
				    _gpgme_data_inbound_handler
				      (gpg->cmd.linked_data, fds.fd);
				}
			      while (fds.signaled);
			    }

			  _gpgme_gpg_add_io_cb
			    (gpg, gpg->cmd.fd,
			     0, _gpgme_data_outbound_handler,
			     gpg->fd_data_map[gpg->cmd.idx].data,
			     &gpg->fd_data_map[gpg->cmd.idx].tag);
			  gpg->fd_data_map[gpg->cmd.idx].fd = gpg->cmd.fd;
			  gpg->cmd.fd = -1;
                        }
		      else if (gpg->status.fnc)
			{
			  gpg->status.fnc (gpg->status.fnc_value, 
					   r->code, rest);
                        }
                    
		      if (r->code == GPGME_STATUS_END_STREAM)
			{
			  if (gpg->cmd.used)
			    {
			      /* XXX We must check if there are any
				 more fds active after removing this
				 one.  */
			      (*gpg->io_cbs.remove)
				(gpg->fd_data_map[gpg->cmd.idx].tag);
			      gpg->cmd.fd = gpg->fd_data_map[gpg->cmd.idx].fd;
			      gpg->fd_data_map[gpg->cmd.idx].fd = -1;
			    }
                        }
                    }
                }
	      /* To reuse the buffer for the next line we have to
		 shift the remaining data to the buffer start and
		 restart the loop Hmmm: We can optimize this function
		 by looking forward in the buffer to see whether a
		 second complete line is available and in this case
		 avoid the memmove for this line.  */
	      nread--; p++;
	      if (nread)
		memmove (buffer, p, nread);
	      readpos = 0;
	      break; /* the for loop */
            }
	  else
	    readpos++;
        }
    } 

  /* Update the gpg object.  */
  gpg->status.bufsize = bufsize;
  gpg->status.buffer = buffer;
  gpg->status.readpos = readpos;
  return 0;
}


/*
 * This colonline handler thing is not the clean way to do it.
 * It might be better to enhance the GpgmeData object to act as
 * a wrapper for a callback.  Same goes for the status thing.
 * For now we use this thing here becuase it is easier to implement.
 */
static void
gpg_colon_line_handler (void *opaque, int fd)
{
  GpgObject gpg = opaque;
  GpgmeError rc = 0;

  assert (fd == gpg->colon.fd[0]);
  rc = read_colon_line (gpg);
  if (rc)
    {
      DEBUG1 ("gpg_colon_line_handler: "
	      "read problem %d\n - stop", rc);
      _gpgme_io_close (fd);
      return;
    }
  if (gpg->colon.eof)
    _gpgme_io_close (fd);
}

static GpgmeError
read_colon_line ( GpgObject gpg )
{
    char *p;
    int nread;
    size_t bufsize = gpg->colon.bufsize; 
    char *buffer = gpg->colon.buffer;
    size_t readpos = gpg->colon.readpos; 

    assert (buffer);
    if (bufsize - readpos < 256) { 
        /* need more room for the read */
        bufsize += 1024;
        buffer = realloc (buffer, bufsize);
        if ( !buffer ) 
            return mk_error (Out_Of_Core);
    }
    

    nread = _gpgme_io_read ( gpg->colon.fd[0],
                             buffer+readpos, bufsize-readpos );
    if (nread == -1)
        return mk_error(Read_Error);

    if (!nread) {
        gpg->colon.eof = 1;
        assert (gpg->colon.fnc);
        gpg->colon.fnc ( gpg->colon.fnc_value, NULL );
        return 0;
    }

    while (nread > 0) {
        for (p = buffer + readpos; nread; nread--, p++) {
            if ( *p == '\n' ) {
                /* (we require that the last line is terminated by a
                 * LF) and we skip empty lines.  Note: we use UTF8
                 * encoding and escaping of special characters
                 * We require at least one colon to cope with
                 * some other printed information.
                 */
                *p = 0;
                if ( gpg->colon.simple
                     || (*buffer && strchr (buffer, ':')) ) {
                    assert (gpg->colon.fnc);
                    gpg->colon.fnc ( gpg->colon.fnc_value, buffer );
                }
            
                /* To reuse the buffer for the next line we have to
                 * shift the remaining data to the buffer start and
                 * restart the loop Hmmm: We can optimize this
                 * function by looking forward in the buffer to see
                 * whether a second complete line is available and in
                 * this case avoid the memmove for this line.  */
                nread--; p++;
                if (nread)
                    memmove (buffer, p, nread);
                readpos = 0;
                break; /* the for loop */
            }
            else
                readpos++;
        }
    } 
    
    /* Update the gpg object.  */
    gpg->colon.bufsize = bufsize;
    gpg->colon.buffer  = buffer;
    gpg->colon.readpos = readpos;
    return 0;
}

static GpgmeError
pipemode_copy (char *buffer, size_t length, size_t *nread, GpgmeData data)
{
  size_t nbytes;
  char tmp[1000], *src, *dst;

  /* We can optimize this whole thing but for now we just return after
      each escape character.  */
  if (length > 990)
    length = 990;

  nbytes = gpgme_data_read (data, tmp, length);
  if (nbytes < 0)
    return mk_error (File_Error);
  for (src = tmp, dst = buffer; nbytes; src++, nbytes--)
    {
      *dst++ = *src;
      if (*src == '@')
	{
	  *dst++ = '@';
	  break;
	}
    }
  *nread = dst - buffer;
  return 0;
}


static int
pipemode_cb ( void *opaque, char *buffer, size_t length, size_t *nread )
{
    GpgObject gpg = opaque;
    GpgmeError err;

    if ( !buffer || !length || !nread )
        return 0; /* those values are reserved for extensions */
    *nread =0;
    if ( !gpg->pm.stream_started ) {
        assert (length > 4 );
        strcpy (buffer, "@<@B" );
        *nread = 4;
        gpg->pm.stream_started = 1;
    }
    else if ( gpg->pm.sig ) {
        err = pipemode_copy ( buffer, length, nread, gpg->pm.sig );
        if ( err == GPGME_EOF ) {
            gpg->pm.sig = NULL;
            assert (length > 4 );
            strcpy (buffer, "@t" );
            *nread = 2;
        }
        else if (err) {
            DEBUG1 ("pipemode_cb: copy sig failed: %s\n",
                     gpgme_strerror (err) );
            return -1;
        }
    }
    else if ( gpg->pm.text ) {
        err = pipemode_copy ( buffer, length, nread, gpg->pm.text );
        if ( err == GPGME_EOF ) {
            gpg->pm.text = NULL;
            assert (length > 4 );
            strcpy (buffer, "@.@>" );
            *nread = 4;
        }
        else if (err) {
            DEBUG1 ("pipemode_cb: copy data failed: %s\n",
                     gpgme_strerror (err) );
            return -1;
        }
    }
    else {
        return 0; /* eof */
    }

    return 0;
}


/* 
 * Here we handle --command-fd.  This works closely together with
 * the status handler.  
 */

static int
command_cb (void *opaque, char *buffer, size_t length, size_t *nread)
{
  GpgObject gpg = opaque;
  const char *value;
  int value_len;

  DEBUG0 ("command_cb: enter\n");
  assert (gpg->cmd.used);
  if (!buffer || !length || !nread)
    return 0; /* These values are reserved for extensions.  */
  *nread = 0;
  if (!gpg->cmd.code)
    {
      DEBUG0 ("command_cb: no code\n");
      return -1;
    }
    
  if (!gpg->cmd.fnc)
    {
      DEBUG0 ("command_cb: no user cb\n");
      return -1;
    }

  value = gpg->cmd.fnc (gpg->cmd.fnc_value, 
			gpg->cmd.code, gpg->cmd.keyword);
  if (!value)
    {
      DEBUG0 ("command_cb: no data from user cb\n");
      gpg->cmd.fnc (gpg->cmd.fnc_value, 0, value);
      return -1;
    }

  value_len = strlen (value);
  if (value_len + 1 > length)
    {
      DEBUG0 ("command_cb: too much data from user cb\n");
      gpg->cmd.fnc (gpg->cmd.fnc_value, 0, value);
      return -1;
    }

  memcpy (buffer, value, value_len);
  if (!value_len || (value_len && value[value_len-1] != '\n')) 
    buffer[value_len++] = '\n';
  *nread = value_len;
    
  gpg->cmd.fnc (gpg->cmd.fnc_value, 0, value);
  gpg->cmd.code = 0;
  /* And sleep again until read_status will wake us up again.  */
  /* XXX We must check if there are any more fds active after removing
     this one.  */
  (*gpg->io_cbs.remove) (gpg->fd_data_map[gpg->cmd.idx].tag);
  gpg->cmd.fd = gpg->fd_data_map[gpg->cmd.idx].fd;
  gpg->fd_data_map[gpg->cmd.idx].fd = -1;

  return 0;
}

GpgmeError
_gpgme_gpg_op_decrypt (GpgObject gpg, GpgmeData ciph, GpgmeData plain)
{
  GpgmeError err;

  err = _gpgme_gpg_add_arg (gpg, "--decrypt");

  /* Tell the gpg object about the data.  */
  if (!err)
    err = _gpgme_gpg_add_arg (gpg, "--output");
  if (!err)
    err = _gpgme_gpg_add_arg (gpg, "-");
  if (!err)
    err = _gpgme_gpg_add_data (gpg, plain, 1, 1);
  if (!err)
    err = _gpgme_gpg_add_data (gpg, ciph, 0, 0);

  return err;
}

GpgmeError
_gpgme_gpg_op_delete (GpgObject gpg, GpgmeKey key, int allow_secret)
{
  GpgmeError err;

  err = _gpgme_gpg_add_arg (gpg, allow_secret
			    ? "--delete-secret-and-public-key"
			    : "--delete-key");
  if (!err)
    err = _gpgme_gpg_add_arg (gpg, "--");
  if (!err)
    {
      const char *s = gpgme_key_get_string_attr (key, GPGME_ATTR_FPR, NULL, 0);
      if (!s)
	err = mk_error (Invalid_Key);
      else
	err = _gpgme_gpg_add_arg (gpg, s);
    }

  return err;
}


static GpgmeError
_gpgme_append_gpg_args_from_signers (GpgObject gpg,
				     GpgmeCtx ctx /* FIXME */)
{
  GpgmeError err = 0;
  int i;
  GpgmeKey key;

  for (i = 0; (key = gpgme_signers_enum (ctx, i)); i++)
    {
      const char *s = gpgme_key_get_string_attr (key, GPGME_ATTR_KEYID,
						 NULL, 0);
      if (s)
	{
	  if (!err)
	    err = _gpgme_gpg_add_arg (gpg, "-u");
	  if (!err)
	    err = _gpgme_gpg_add_arg (gpg, s);
	}
      gpgme_key_unref (key);
      if (err) break;
    }
  return err;
}


GpgmeError
_gpgme_gpg_op_edit (GpgObject gpg, GpgmeKey key, GpgmeData out,
		    GpgmeCtx ctx /* FIXME */)
{
  GpgmeError err;

  err = _gpgme_gpg_add_arg (gpg, "--with-colons");
  if (!err)
    err = _gpgme_append_gpg_args_from_signers (gpg, ctx);
  if (!err)
  err = _gpgme_gpg_add_arg (gpg, "--edit-key");
  if (!err)
    err = _gpgme_gpg_add_data (gpg, out, 1, 1);
  if (!err)
    err = _gpgme_gpg_add_arg (gpg, "--");
  if (!err)
    {
      const char *s = gpgme_key_get_string_attr (key, GPGME_ATTR_FPR, NULL, 0);
      if (!s)
	err = mk_error (Invalid_Key);
      else
	err = _gpgme_gpg_add_arg (gpg, s);
    }

  return err;
}


static GpgmeError
_gpgme_append_gpg_args_from_recipients (GpgObject gpg,
					const GpgmeRecipients rset)
{
  GpgmeError err = 0;
  struct user_id_s *r;

  assert (rset);
  for (r = rset->list; r; r = r->next)
    {
      err = _gpgme_gpg_add_arg (gpg, "-r");
      if (!err)
	_gpgme_gpg_add_arg (gpg, r->name);
      if (err)
	break;
    }    
  return err;
}


GpgmeError
_gpgme_gpg_op_encrypt (GpgObject gpg, GpgmeRecipients recp,
		       GpgmeData plain, GpgmeData ciph, int use_armor)
{
  GpgmeError err;
  int symmetric = !recp;

  err = _gpgme_gpg_add_arg (gpg, symmetric ? "--symmetric" : "--encrypt");

  if (!err && use_armor)
    err = _gpgme_gpg_add_arg (gpg, "--armor");

  if (!symmetric)
    {
      /* If we know that all recipients are valid (full or ultimate trust)
	 we can suppress further checks.  */
      if (!err && !symmetric && _gpgme_recipients_all_valid (recp))
	err = _gpgme_gpg_add_arg (gpg, "--always-trust");

      if (!err)
	err = _gpgme_append_gpg_args_from_recipients (gpg, recp);
    }

  /* Tell the gpg object about the data.  */
  if (!err)
    err = _gpgme_gpg_add_arg (gpg, "--output");
  if (!err)
    err = _gpgme_gpg_add_arg (gpg, "-");
  if (!err)
    err = _gpgme_gpg_add_data (gpg, ciph, 1, 1);
  if (!err)
    err = _gpgme_gpg_add_arg (gpg, "--");
  if (!err)
    err = _gpgme_gpg_add_data (gpg, plain, 0, 0);

  return err;
}

GpgmeError
_gpgme_gpg_op_encrypt_sign (GpgObject gpg, GpgmeRecipients recp,
			    GpgmeData plain, GpgmeData ciph, int use_armor,
			    GpgmeCtx ctx /* FIXME */)
{
  GpgmeError err;

  err = _gpgme_gpg_add_arg (gpg, "--encrypt");
  if (!err)
    err = _gpgme_gpg_add_arg (gpg, "--sign");
  if (!err && use_armor)
    err = _gpgme_gpg_add_arg (gpg, "--armor");

  /* If we know that all recipients are valid (full or ultimate trust)
   * we can suppress further checks */
  if (!err && _gpgme_recipients_all_valid (recp))
    err = _gpgme_gpg_add_arg (gpg, "--always-trust");

  if (!err)
    err = _gpgme_append_gpg_args_from_recipients (gpg, recp);

  if (!err)
    err = _gpgme_append_gpg_args_from_signers (gpg, ctx);

  /* Tell the gpg object about the data.  */
  if (!err)
    err = _gpgme_gpg_add_arg (gpg, "--output");
  if (!err)
    err = _gpgme_gpg_add_arg (gpg, "-");
  if (!err)
    err = _gpgme_gpg_add_data (gpg, ciph, 1, 1);
  if (!err)
    err = _gpgme_gpg_add_arg (gpg, "--");
  if (!err)
    err = _gpgme_gpg_add_data (gpg, plain, 0, 0);

  return err;
}

GpgmeError
_gpgme_gpg_op_export (GpgObject gpg, GpgmeRecipients recp,
		      GpgmeData keydata, int use_armor)
{
  GpgmeError err;

  err = _gpgme_gpg_add_arg (gpg, "--export");
  if (!err && use_armor)
    err = _gpgme_gpg_add_arg (gpg, "--armor");
  if (!err)
    err = _gpgme_gpg_add_data (gpg, keydata, 1, 1);
  if (!err)
    err = _gpgme_gpg_add_arg (gpg, "--");

  if (!err)
    {
      void *ec;
      const char *s;

      err = gpgme_recipients_enum_open (recp, &ec);
      while (!err && (s = gpgme_recipients_enum_read (recp, &ec)))
	err = _gpgme_gpg_add_arg (gpg, s);
      if (!err)
	err = gpgme_recipients_enum_close (recp, &ec);
    }

  return err;
}

GpgmeError
_gpgme_gpg_op_genkey (GpgObject gpg, GpgmeData help_data, int use_armor,
		      GpgmeData pubkey, GpgmeData seckey)
{
  GpgmeError err;

  if (!gpg)
    return mk_error (Invalid_Value);

  /* We need a special mechanism to get the fd of a pipe here, so
   * that we can use this for the %pubring and %secring parameters.
   * We don't have this yet, so we implement only the adding to the
   * standard keyrings */
  if (pubkey || seckey)
    return err = mk_error (Not_Implemented);

  err = _gpgme_gpg_add_arg (gpg, "--gen-key");
  if (!err && use_armor)
    err = _gpgme_gpg_add_arg (gpg, "--armor");
  if (!err)
    err = _gpgme_gpg_add_data (gpg, help_data, 0, 0);

  return err;
}

GpgmeError
_gpgme_gpg_op_import (GpgObject gpg, GpgmeData keydata)
{
  GpgmeError err;

  err = _gpgme_gpg_add_arg (gpg, "--import");
  if (!err)
    err = _gpgme_gpg_add_data (gpg, keydata, 0, 0);

  return err;
}


GpgmeError
_gpgme_gpg_op_keylist (GpgObject gpg, const char *pattern, int secret_only,
		       int keylist_mode)
{
  GpgmeError err;

  err = _gpgme_gpg_add_arg (gpg, "--with-colons");
  if (!err)
    err = _gpgme_gpg_add_arg (gpg, "--fixed-list-mode");
  if (!err)
    err = _gpgme_gpg_add_arg (gpg, "--with-fingerprint");
  if (!err)
    err = _gpgme_gpg_add_arg (gpg, 
                              (keylist_mode & GPGME_KEYLIST_MODE_SIGS)?
                              "--check-sigs" :
                              secret_only ? "--list-secret-keys"
			      : "--list-keys");
  
  /* Tell the gpg object about the data */
  if (!err)
    err = _gpgme_gpg_add_arg (gpg, "--");
  if (!err && pattern && *pattern)
    err = _gpgme_gpg_add_arg (gpg, pattern);

  return err;
}


GpgmeError
_gpgme_gpg_op_keylist_ext (GpgObject gpg, const char *pattern[],
			   int secret_only, int reserved, int keylist_mode)
{
  GpgmeError err;

  if (reserved)
    return mk_error (Invalid_Value);

  err = _gpgme_gpg_add_arg (gpg, "--with-colons");
  if (!err)
    err = _gpgme_gpg_add_arg (gpg, "--fixed-list-mode");
  if (!err)
    err = _gpgme_gpg_add_arg (gpg, "--with-fingerprint");
  if (!err)
    err = _gpgme_gpg_add_arg (gpg, secret_only ? "--list-secret-keys"
			      : "--list-keys");
  
  /* Tell the gpg object about the data */
  if (!err)
    err = _gpgme_gpg_add_arg (gpg, "--");
  if (!err && pattern && *pattern)
    {
      while (*pattern && **pattern)
	err = _gpgme_gpg_add_arg (gpg, *(pattern++));
    }

  return err;
}


GpgmeError
_gpgme_gpg_op_sign (GpgObject gpg, GpgmeData in, GpgmeData out,
		    GpgmeSigMode mode, int use_armor,
		    int use_textmode, GpgmeCtx ctx /* FIXME */)
{
  GpgmeError err;

  if (mode == GPGME_SIG_MODE_CLEAR)
    err = _gpgme_gpg_add_arg (gpg, "--clearsign");
  else
    {
      err = _gpgme_gpg_add_arg (gpg, "--sign");
      if (!err && mode == GPGME_SIG_MODE_DETACH)
	err = _gpgme_gpg_add_arg (gpg, "--detach");
      if (!err && use_armor)
	err = _gpgme_gpg_add_arg (gpg, "--armor");
      if (!err && use_textmode)
	_gpgme_gpg_add_arg (gpg, "--textmode");
    }

  if (!err)
    err = _gpgme_append_gpg_args_from_signers (gpg, ctx);

  /* Tell the gpg object about the data.  */
  if (!err)
    err = _gpgme_gpg_add_data (gpg, in, 0, 0);
  if (!err)
    err = _gpgme_gpg_add_data (gpg, out, 1, 1);

  return err;
}

GpgmeError
_gpgme_gpg_op_trustlist (GpgObject gpg, const char *pattern)
{
  GpgmeError err;

  err = _gpgme_gpg_add_arg (gpg, "--with-colons");
  if (!err)
    err = _gpgme_gpg_add_arg (gpg, "--list-trust-path");
  
  /* Tell the gpg object about the data */
  if (!err)
    err = _gpgme_gpg_add_arg (gpg, "--");
  if (!err)
    err = _gpgme_gpg_add_arg (gpg, pattern);

  return err;
}

GpgmeError
_gpgme_gpg_op_verify (GpgObject gpg, GpgmeData sig, GpgmeData signed_text, GpgmeData plaintext)
{
  GpgmeError err = 0;

  if (plaintext)
    {
      /* Normal or cleartext signature.  */

      err = _gpgme_gpg_add_arg (gpg, "--output");
      if (!err)
	err = _gpgme_gpg_add_arg (gpg, "-");
      if (!err)
	err = _gpgme_gpg_add_arg (gpg, "--");
      if (!err)
	err = _gpgme_gpg_add_data (gpg, sig, 0, 0);
      if (!err)
	err = _gpgme_gpg_add_data (gpg, plaintext, 1, 1);
    }
  else
    {
      if (gpg->pm.used)
	{
	  err = _gpgme_gpg_add_arg (gpg, gpg->pm.used ? "--pipemode" : "--verify");
	  if (!err)
	    err = _gpgme_gpg_add_arg (gpg, "--");
	  if (!err)
	    err = _gpgme_gpg_add_pm_data (gpg, sig, 0);
	  if (!err)
	    err = _gpgme_gpg_add_pm_data (gpg, signed_text, 1);
	}
      else
	{
	  err = _gpgme_gpg_add_arg (gpg, "--verify");
	  if (!err)
	    err = _gpgme_gpg_add_arg (gpg, "--");
	  if (!err)
	    err = _gpgme_gpg_add_data (gpg, sig, -1, 0);
	  if (signed_text)
	    {
	      if (!err)
		err = _gpgme_gpg_add_arg (gpg, "-");
	      if (!err)
		err = _gpgme_gpg_add_data (gpg, signed_text, 0, 0);
	    }
	}
    }
  return err;
}


void
_gpgme_gpg_set_io_cbs (GpgObject gpg, struct GpgmeIOCbs *io_cbs)
{
  gpg->io_cbs = *io_cbs;
}


void
_gpgme_gpg_io_event (GpgObject gpg, GpgmeEventIO type, void *type_data)
{
  if (gpg->io_cbs.event)
    (*gpg->io_cbs.event) (gpg->io_cbs.event_priv, type, type_data);
}
