/* rungpg.c - Gpg Engine.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003 g10 Code GmbH
 
   This file is part of GPGME.
 
   GPGME is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
 
   GPGME is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with GPGME; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "gpgme.h"
#include "util.h"
#include "ops.h"
#include "wait.h"
#include "context.h"  /*temp hack until we have GpmeData methods to do I/O */
#include "io.h"
#include "sema.h"
#include "debug.h"

#include "status-table.h"
#include "engine-backend.h"


/* This type is used to build a list of gpg arguments and data
   sources/sinks.  */
struct arg_and_data_s
{
  struct arg_and_data_s *next;
  gpgme_data_t data;  /* If this is not NULL, use arg below.  */
  int inbound;     /* True if this is used for reading from gpg.  */
  int dup_to;
  int print_fd;    /* Print the fd number and not the special form of it.  */
  char arg[1];     /* Used if data above is not used.  */
};


struct fd_data_map_s
{
  gpgme_data_t data;
  int inbound;  /* true if this is used for reading from gpg */
  int dup_to;
  int fd;       /* the fd to use */
  int peer_fd;  /* the outher side of the pipe */
  void *tag;
};


struct engine_gpg
{
  struct arg_and_data_s *arglist;
  struct arg_and_data_s **argtail;

  struct
  {
    int fd[2];  
    size_t bufsize;
    char *buffer;
    size_t readpos;
    int eof;
    engine_status_handler_t fnc;
    void *fnc_value;
    void *tag;
  } status;

  /* This is a kludge - see the comment at colon_line_handler.  */
  struct
  {
    int fd[2];  
    size_t bufsize;
    char *buffer;
    size_t readpos;
    int eof;
    engine_colon_line_handler_t fnc;  /* this indicate use of this structrue */
    void *fnc_value;
    void *tag;
  } colon;

  char **argv;  
  struct fd_data_map_s *fd_data_map;

  /* stuff needed for interactive (command) mode */
  struct
  {
    int used;
    int fd;
    void *cb_data;
    int idx;		/* Index in fd_data_map */
    gpgme_status_code_t code;  /* last code */
    char *keyword;       /* what has been requested (malloced) */
    engine_command_handler_t fnc; 
    void *fnc_value;
    /* The kludges never end.  This is used to couple command handlers
       with output data in edit key mode.  */
    gpgme_data_t linked_data;
    int linked_idx;
  } cmd;

  struct gpgme_io_cbs io_cbs;
};

typedef struct engine_gpg *engine_gpg_t;


static void
gpg_io_event (void *engine, gpgme_event_io_t type, void *type_data)
{
  engine_gpg_t gpg = engine;

  if (gpg->io_cbs.event)
    (*gpg->io_cbs.event) (gpg->io_cbs.event_priv, type, type_data);
}


static void
close_notify_handler (int fd, void *opaque)
{
  engine_gpg_t gpg = opaque;
  assert (fd != -1);

  if (gpg->status.fd[0] == fd)
    {
      if (gpg->status.tag)
	(*gpg->io_cbs.remove) (gpg->status.tag);
      gpg->status.fd[0] = -1;
    }
  else if (gpg->status.fd[1] == fd)
    gpg->status.fd[1] = -1;
  else if (gpg->colon.fd[0] == fd)
    {
      if (gpg->colon.tag)
	(*gpg->io_cbs.remove) (gpg->colon.tag);
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
		(*gpg->io_cbs.remove) (gpg->fd_data_map[i].tag);
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
}

static gpgme_error_t
add_arg (engine_gpg_t gpg, const char *arg)
{
  struct arg_and_data_s *a;

  assert (gpg);
  assert (arg);

  a = malloc (sizeof *a + strlen (arg));
  if (!a)
    return gpg_error_from_errno (errno);
  a->next = NULL;
  a->data = NULL;
  a->dup_to = -1;
  strcpy (a->arg, arg);
  *gpg->argtail = a;
  gpg->argtail = &a->next;
  return 0;
}

static gpgme_error_t
add_data (engine_gpg_t gpg, gpgme_data_t data, int dup_to, int inbound)
{
  struct arg_and_data_s *a;

  assert (gpg);
  assert (data);

  a = malloc (sizeof *a - 1);
  if (!a)
    return gpg_error_from_errno (errno);
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


static const char *
gpg_get_version (void)
{
  static const char *gpg_version;
  DEFINE_STATIC_LOCK (gpg_version_lock);

  LOCK (gpg_version_lock);
  if (!gpg_version)
    gpg_version = _gpgme_get_program_version (_gpgme_get_gpg_path ());
  UNLOCK (gpg_version_lock);
  return gpg_version;
}


static const char *
gpg_get_req_version (void)
{
  return NEED_GPG_VERSION;
}


static void
free_argv (char **argv)
{
  int i;

  for (i = 0; argv[i]; i++)
    free (argv[i]);
  free (argv);
}


static void
free_fd_data_map (struct fd_data_map_s *fd_data_map)
{
  int i;

  if (!fd_data_map)
    return;

  for (i = 0; fd_data_map[i].data; i++)
    {
      if (fd_data_map[i].fd != -1)
	_gpgme_io_close (fd_data_map[i].fd);
      if (fd_data_map[i].peer_fd != -1)
	_gpgme_io_close (fd_data_map[i].peer_fd);
      /* Don't release data because this is only a reference.  */
    }
  free (fd_data_map);
}


static void
gpg_release (void *engine)
{
  engine_gpg_t gpg = engine;

  if (!gpg)
    return;

  while (gpg->arglist)
    {
      struct arg_and_data_s *next = gpg->arglist->next;

      if (gpg->arglist)
	free (gpg->arglist);
      gpg->arglist = next;
    }

  if (gpg->status.buffer)
    free (gpg->status.buffer);
  if (gpg->colon.buffer)
    free (gpg->colon.buffer);
  if (gpg->argv)
    free_argv (gpg->argv);
  if (gpg->cmd.keyword)
    free (gpg->cmd.keyword);

  if (gpg->status.fd[0] != -1)
    _gpgme_io_close (gpg->status.fd[0]);
  if (gpg->status.fd[1] != -1)
    _gpgme_io_close (gpg->status.fd[1]);
  if (gpg->colon.fd[0] != -1)
    _gpgme_io_close (gpg->colon.fd[0]);
  if (gpg->colon.fd[1] != -1)
    _gpgme_io_close (gpg->colon.fd[1]);
  if (gpg->fd_data_map)
    free_fd_data_map (gpg->fd_data_map);
  if (gpg->cmd.fd != -1)
    _gpgme_io_close (gpg->cmd.fd);
  free (gpg);
}


static gpgme_error_t
gpg_new (void **engine, const char *lc_ctype, const char *lc_messages)
{
  engine_gpg_t gpg;
  gpgme_error_t rc = 0;

  gpg = calloc (1, sizeof *gpg);
  if (!gpg)
    return gpg_error_from_errno (errno);

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
      rc = gpg_error_from_errno (errno);
      goto leave;
    }
  /* In any case we need a status pipe - create it right here and
     don't handle it with our generic gpgme_data_t mechanism.  */
  if (_gpgme_io_pipe (gpg->status.fd, 1) == -1)
    {
      rc = gpg_error_from_errno (errno);
      goto leave;
    }
  if (_gpgme_io_set_close_notify (gpg->status.fd[0],
				  close_notify_handler, gpg)
      || _gpgme_io_set_close_notify (gpg->status.fd[1],
				     close_notify_handler, gpg))
    {
      rc = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }
  gpg->status.eof = 0;
  rc = add_arg (gpg, "--status-fd");
  if (rc)
    goto leave;

  {
    char buf[25];
    sprintf (buf, "%d", gpg->status.fd[1]);
    rc = add_arg (gpg, buf);
    if (rc)
      goto leave;
  }

  rc = add_arg (gpg, "--no-tty");
  if (!rc)
    rc = add_arg (gpg, "--charset");
  if (!rc)
    rc = add_arg (gpg, "utf8");
  if (!rc)
    rc = add_arg (gpg, "--enable-progress-filter");

 leave:
  if (rc)
    gpg_release (gpg);
  else
    *engine = gpg;
  return rc;
}


/* Note, that the status_handler is allowed to modifiy the args
   value.  */
static void
gpg_set_status_handler (void *engine, engine_status_handler_t fnc,
			void *fnc_value)
{
  engine_gpg_t gpg = engine;

  gpg->status.fnc = fnc;
  gpg->status.fnc_value = fnc_value;
}

/* Kludge to process --with-colon output.  */
static gpgme_error_t
gpg_set_colon_line_handler (void *engine, engine_colon_line_handler_t fnc,
			    void *fnc_value)
{
  engine_gpg_t gpg = engine;

  gpg->colon.bufsize = 1024;
  gpg->colon.readpos = 0;
  gpg->colon.buffer = malloc (gpg->colon.bufsize);
  if (!gpg->colon.buffer)
    return gpg_error_from_errno (errno);

  if (_gpgme_io_pipe (gpg->colon.fd, 1) == -1) 
    {
      int saved_errno = errno;
      free (gpg->colon.buffer);
      gpg->colon.buffer = NULL;
      return gpg_error_from_errno (saved_errno);
    }
  if (_gpgme_io_set_close_notify (gpg->colon.fd[0], close_notify_handler, gpg)
      || _gpgme_io_set_close_notify (gpg->colon.fd[1],
				     close_notify_handler, gpg))
    return gpg_error (GPG_ERR_GENERAL);
  gpg->colon.eof = 0;
  gpg->colon.fnc = fnc;
  gpg->colon.fnc_value = fnc_value;
  return 0;
}


static gpgme_error_t
command_handler (void *opaque, int fd)
{
  gpgme_error_t err;
  engine_gpg_t gpg = (engine_gpg_t) opaque;

  assert (gpg->cmd.used);
  assert (gpg->cmd.code);
  assert (gpg->cmd.fnc);

  err = gpg->cmd.fnc (gpg->cmd.fnc_value, gpg->cmd.code, gpg->cmd.keyword, fd);
  if (err)
    return err;

  gpg->cmd.code = 0;
  /* And sleep again until read_status will wake us up again.  */
  /* XXX We must check if there are any more fds active after removing
     this one.  */
  (*gpg->io_cbs.remove) (gpg->fd_data_map[gpg->cmd.idx].tag);
  gpg->cmd.fd = gpg->fd_data_map[gpg->cmd.idx].fd;
  gpg->fd_data_map[gpg->cmd.idx].fd = -1;

  return 0;
}



/* The Fnc will be called to get a value for one of the commands with
   a key KEY.  If the Code pssed to FNC is 0, the function may release
   resources associated with the returned value from another call.  To
   match such a second call to a first call, the returned value from
   the first call is passed as keyword.  */
static gpgme_error_t
gpg_set_command_handler (void *engine, engine_command_handler_t fnc,
			 void *fnc_value, gpgme_data_t linked_data)
{
  engine_gpg_t gpg = engine;
  gpgme_error_t rc;

  rc = add_arg (gpg, "--command-fd");
  if (rc)
    return rc;

  /* This is a hack.  We don't have a real data object.  The only
     thing that matters is that we use something unique, so we use the
     address of the cmd structure in the gpg object.  */
  rc = add_data (gpg, (void *) &gpg->cmd, -2, 0);
  if (rc)
    return rc;

  gpg->cmd.fnc = fnc;
  gpg->cmd.cb_data = (void *) &gpg->cmd;
  gpg->cmd.fnc_value = fnc_value;
  gpg->cmd.linked_data = linked_data;
  gpg->cmd.used = 1;
  return 0;
}


static gpgme_error_t
build_argv (engine_gpg_t gpg)
{
  gpgme_error_t err;
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
  err = _gpgme_getenv ("GPG_AGENT_INFO", &p);
  if (err)
    return err;
  use_agent = (p && strchr (p, ':'));
  if (p)
    free (p);

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
    argc++;	/* --batch */
  argc += 2; /* --comment */

  argv = calloc (argc + 1, sizeof *argv);
  if (!argv)
    return gpg_error_from_errno (errno);
  fd_data_map = calloc (datac + 1, sizeof *fd_data_map);
  if (!fd_data_map)
    {
      int saved_errno = errno;
      free_argv (argv);
      return gpg_error_from_errno (saved_errno);
    }

  argc = datac = 0;
  argv[argc] = strdup ("gpg"); /* argv[0] */
  if (!argv[argc])
    {
      int saved_errno = errno;
      free (fd_data_map);
      free_argv (argv);
      return gpg_error_from_errno (saved_errno);
    }
  argc++;
  if (need_special)
    {
      argv[argc] = strdup ("--enable-special-filenames");
      if (!argv[argc])
	{
	  int saved_errno = errno;
	  free (fd_data_map);
	  free_argv (argv);
	  return gpg_error_from_errno (saved_errno);
        }
      argc++;
    }
  if (use_agent)
    {
      argv[argc] = strdup ("--use-agent");
      if (!argv[argc])
	{
	  int saved_errno = errno;
	  free (fd_data_map);
	  free_argv (argv);
	  return gpg_error_from_errno (saved_errno);
        }
      argc++;
    }
  if (!gpg->cmd.used)
    {
      argv[argc] = strdup ("--batch");
      if (!argv[argc])
	{
	  int saved_errno = errno;
	  free (fd_data_map);
	  free_argv (argv);
	  return gpg_error_from_errno (saved_errno);
        }
      argc++;
    }
  argv[argc] = strdup ("--comment");
  if (!argv[argc])
    {
      int saved_errno = errno;
      free (fd_data_map);
      free_argv (argv);
      return gpg_error_from_errno (saved_errno);
    }
  argc++;
  argv[argc] = strdup ("");
  if (!argv[argc])
    {
      int saved_errno = errno;
      free (fd_data_map);
      free_argv (argv);
      return gpg_error_from_errno (saved_errno);
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
		int saved_errno = errno;
		free (fd_data_map);
		free_argv (argv);
		return gpg_error (saved_errno);
	      }
	    if (_gpgme_io_set_close_notify (fds[0],
					    close_notify_handler, gpg)
		|| _gpgme_io_set_close_notify (fds[1],
					       close_notify_handler,
					       gpg))
	      {
		return gpg_error (GPG_ERR_GENERAL);
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
		  int saved_errno = errno;
		  free (fd_data_map);
		  free_argv (argv);
		  return gpg_error_from_errno (saved_errno);
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
	      int saved_errno = errno;
	      free (fd_data_map);
	      free_argv (argv);
	      return gpg_error_from_errno (saved_errno);
            }
            argc++;
        }
    }

  gpg->argv = argv;
  gpg->fd_data_map = fd_data_map;
  return 0;
}


static gpgme_error_t
add_io_cb (engine_gpg_t gpg, int fd, int dir, gpgme_io_cb_t handler, void *data,
	   void **tag)
{
  gpgme_error_t err;

  err = (*gpg->io_cbs.add) (gpg->io_cbs.add_priv, fd, dir, handler, data, tag);
  if (err)
    return err;
  if (!dir)
    /* FIXME Kludge around poll() problem.  */
    err = _gpgme_io_set_nonblocking (fd);
  return err;
}


static int
status_cmp (const void *ap, const void *bp)
{
  const struct status_table_s *a = ap;
  const struct status_table_s *b = bp;

  return strcmp (a->name, b->name);
}


/* Handle the status output of GnuPG.  This function does read entire
   lines and passes them as C strings to the callback function (we can
   use C Strings because the status output is always UTF-8 encoded).
   Of course we have to buffer the lines to cope with long lines
   e.g. with a large user ID.  Note: We can optimize this to only cope
   with status line code we know about and skip all other stuff
   without buffering (i.e. without extending the buffer).  */
static gpgme_error_t
read_status (engine_gpg_t gpg)
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
	return gpg_error_from_errno (errno);
    }

  nread = _gpgme_io_read (gpg->status.fd[0],
			  buffer + readpos, bufsize-readpos);
  if (nread == -1)
    return gpg_error_from_errno (errno);

  if (!nread)
    {
      gpg->status.eof = 1;
      if (gpg->status.fnc)
	{
	  gpgme_error_t err;
	  err = gpg->status.fnc (gpg->status.fnc_value, GPGME_STATUS_EOF, "");
	  if (err)
	    return err;
	}
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
			  if (gpg->cmd.keyword)
			    free (gpg->cmd.keyword);
			  gpg->cmd.keyword = strdup (rest);
			  if (!gpg->cmd.keyword)
			    return gpg_error_from_errno (errno);
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

			  add_io_cb (gpg, gpg->cmd.fd, 0,
				     command_handler, gpg,
				     &gpg->fd_data_map[gpg->cmd.idx].tag);
			  gpg->fd_data_map[gpg->cmd.idx].fd = gpg->cmd.fd;
			  gpg->cmd.fd = -1;
                        }
		      else if (gpg->status.fnc)
			{
			  gpgme_error_t err;
			  err = gpg->status.fnc (gpg->status.fnc_value, 
						 r->code, rest);
			  if (err)
			    return err;
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


static gpgme_error_t
status_handler (void *opaque, int fd)
{
  engine_gpg_t gpg = opaque;
  int err;

  assert (fd == gpg->status.fd[0]);
  err = read_status (gpg);
  if (err)
    return err;
  if (gpg->status.eof)
    _gpgme_io_close (fd);
  return 0;
}


static gpgme_error_t
read_colon_line (engine_gpg_t gpg)
{
  char *p;
  int nread;
  size_t bufsize = gpg->colon.bufsize; 
  char *buffer = gpg->colon.buffer;
  size_t readpos = gpg->colon.readpos; 

  assert (buffer);
  if (bufsize - readpos < 256)
    { 
      /* Need more room for the read.  */
      bufsize += 1024;
      buffer = realloc (buffer, bufsize);
      if (!buffer) 
	return gpg_error_from_errno (errno);
    }

  nread = _gpgme_io_read (gpg->colon.fd[0], buffer+readpos, bufsize-readpos);
  if (nread == -1)
    return gpg_error_from_errno (errno);

  if (!nread)
    {
      gpg->colon.eof = 1;
      assert (gpg->colon.fnc);
      gpg->colon.fnc (gpg->colon.fnc_value, NULL);
      return 0;
    }

  while (nread > 0)
    {
      for (p = buffer + readpos; nread; nread--, p++)
	{
	  if ( *p == '\n' )
	    {
	      /* (we require that the last line is terminated by a LF)
		 and we skip empty lines.  Note: we use UTF8 encoding
		 and escaping of special characters We require at
		 least one colon to cope with some other printed
		 information.  */
	      *p = 0;
	      if (*buffer && strchr (buffer, ':'))
		{
		  assert (gpg->colon.fnc);
		  gpg->colon.fnc (gpg->colon.fnc_value, buffer);
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
	      break; /* The for loop.  */
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


/* This colonline handler thing is not the clean way to do it.  It
   might be better to enhance the gpgme_data_t object to act as a wrapper
   for a callback.  Same goes for the status thing.  For now we use
   this thing here because it is easier to implement.  */
static gpgme_error_t
colon_line_handler (void *opaque, int fd)
{
  engine_gpg_t gpg = opaque;
  gpgme_error_t rc = 0;

  assert (fd == gpg->colon.fd[0]);
  rc = read_colon_line (gpg);
  if (rc)
    return rc;
  if (gpg->colon.eof)
    _gpgme_io_close (fd);
  return 0;
}


static gpgme_error_t
start (engine_gpg_t gpg)
{
  gpgme_error_t rc;
  int saved_errno;
  int i, n;
  int status;
  struct spawn_fd_item_s *fd_child_list, *fd_parent_list;

  if (!gpg)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (! _gpgme_get_gpg_path ())
    return gpg_error (GPG_ERR_INV_ENGINE);

  rc = build_argv (gpg);
  if (rc)
    return rc;

  n = 3; /* status_fd, colon_fd and end of list */
  for (i = 0; gpg->fd_data_map[i].data; i++) 
    n++;
  fd_child_list = calloc (n + n, sizeof *fd_child_list);
  if (!fd_child_list)
    return gpg_error_from_errno (errno);
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
    }
  if (gpg->colon.fd[1] != -1)
    {
      fd_parent_list[n].fd = gpg->colon.fd[1];
      fd_parent_list[n].dup_to = -1;
      n++;
    }
  for (i = 0; gpg->fd_data_map[i].data; i++)
    {
      fd_parent_list[n].fd = gpg->fd_data_map[i].peer_fd;
      fd_parent_list[n].dup_to = -1;
      n++;
    }        
  fd_parent_list[n].fd = -1;
  fd_parent_list[n].dup_to = -1;

  status = _gpgme_io_spawn (_gpgme_get_gpg_path (),
			    gpg->argv, fd_child_list, fd_parent_list);
  saved_errno = errno;
  free (fd_child_list);
  if (status == -1)
    return gpg_error_from_errno (saved_errno);

  /*_gpgme_register_term_handler ( closure, closure_value, pid );*/

  rc = add_io_cb (gpg, gpg->status.fd[0], 1, status_handler, gpg,
		  &gpg->status.tag);
  if (rc)
    /* FIXME: kill the child */
    return rc;

  if (gpg->colon.fnc)
    {
      assert (gpg->colon.fd[0] != -1);
      rc = add_io_cb (gpg, gpg->colon.fd[0], 1, colon_line_handler, gpg,
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
	  rc = add_io_cb (gpg, gpg->fd_data_map[i].fd,
			  gpg->fd_data_map[i].inbound,
			  gpg->fd_data_map[i].inbound
			  ? _gpgme_data_inbound_handler
			  : _gpgme_data_outbound_handler,
			  gpg->fd_data_map[i].data, &gpg->fd_data_map[i].tag);
	  
	  if (rc)
	    /* FIXME: kill the child */
	    return rc;
	}
    }

  (*gpg->io_cbs.event) (gpg->io_cbs.event_priv, GPGME_EVENT_START, NULL);
  
  /* fixme: check what data we can release here */
  return 0;
}


static gpgme_error_t
gpg_decrypt (void *engine, gpgme_data_t ciph, gpgme_data_t plain)
{
  engine_gpg_t gpg = engine;
  gpgme_error_t err;

  err = add_arg (gpg, "--decrypt");

  /* Tell the gpg object about the data.  */
  if (!err)
    err = add_arg (gpg, "--output");
  if (!err)
    err = add_arg (gpg, "-");
  if (!err)
    err = add_data (gpg, plain, 1, 1);
  if (!err)
    err = add_data (gpg, ciph, 0, 0);

  if (!err)
    start (gpg);
  return err;
}

static gpgme_error_t
gpg_delete (void *engine, gpgme_key_t key, int allow_secret)
{
  engine_gpg_t gpg = engine;
  gpgme_error_t err;

  err = add_arg (gpg, allow_secret ? "--delete-secret-and-public-key"
		 : "--delete-key");
  if (!err)
    err = add_arg (gpg, "--");
  if (!err)
    {
      if (!key->subkeys || !key->subkeys->fpr)
	return gpg_error (GPG_ERR_INV_VALUE);
      else
	err = add_arg (gpg, key->subkeys->fpr);
    }

  if (!err)
    start (gpg);
  return err;
}


static gpgme_error_t
append_args_from_signers (engine_gpg_t gpg, gpgme_ctx_t ctx /* FIXME */)
{
  gpgme_error_t err = 0;
  int i;
  gpgme_key_t key;

  for (i = 0; (key = gpgme_signers_enum (ctx, i)); i++)
    {
      const char *s = key->subkeys ? key->subkeys->keyid : NULL;
      if (s)
	{
	  if (!err)
	    err = add_arg (gpg, "-u");
	  if (!err)
	    err = add_arg (gpg, s);
	}
      gpgme_key_unref (key);
      if (err) break;
    }
  return err;
}


static gpgme_error_t
gpg_edit (void *engine, int type, gpgme_key_t key, gpgme_data_t out,
	  gpgme_ctx_t ctx /* FIXME */)
{
  engine_gpg_t gpg = engine;
  gpgme_error_t err;

  err = add_arg (gpg, "--with-colons");
  if (!err)
    err = append_args_from_signers (gpg, ctx);
  if (!err)
  err = add_arg (gpg, type == 0 ? "--edit-key" : "--card-edit");
  if (!err)
    err = add_data (gpg, out, 1, 1);
  if (!err)
    err = add_arg (gpg, "--");
  if (!err)
    {
      const char *s = key->subkeys ? key->subkeys->fpr : NULL;
      if (!s)
	err = gpg_error (GPG_ERR_INV_VALUE);
      else
	err = add_arg (gpg, s);
    }
  if (!err)
    err = start (gpg);

  return err;
}


static gpgme_error_t
append_args_from_recipients (engine_gpg_t gpg, gpgme_key_t recp[])
{
  gpgme_error_t err = 0;
  int i = 0;

  while (recp[i])
    {
      if (!recp[i]->subkeys || !recp[i]->subkeys->fpr)
	err = gpg_error (GPG_ERR_INV_VALUE);
      if (!err)
	err = add_arg (gpg, "-r");
      if (!err)
	err = add_arg (gpg, recp[i]->subkeys->fpr);
      if (err)
	break;
      i++;
    }    
  return err;
}


static gpgme_error_t
gpg_encrypt (void *engine, gpgme_key_t recp[], gpgme_encrypt_flags_t flags,
	     gpgme_data_t plain, gpgme_data_t ciph, int use_armor)
{
  engine_gpg_t gpg = engine;
  gpgme_error_t err;
  int symmetric = !recp;

  err = add_arg (gpg, symmetric ? "--symmetric" : "--encrypt");

  if (!err && use_armor)
    err = add_arg (gpg, "--armor");

  if (!symmetric)
    {
      /* If we know that all recipients are valid (full or ultimate trust)
	 we can suppress further checks.  */
      if (!err && !symmetric && (flags & GPGME_ENCRYPT_ALWAYS_TRUST))
	err = add_arg (gpg, "--always-trust");

      if (!err)
	err = append_args_from_recipients (gpg, recp);
    }

  /* Tell the gpg object about the data.  */
  if (!err)
    err = add_arg (gpg, "--output");
  if (!err)
    err = add_arg (gpg, "-");
  if (!err)
    err = add_data (gpg, ciph, 1, 1);
  if (!err)
    err = add_arg (gpg, "--");
  if (!err)
    err = add_data (gpg, plain, 0, 0);

  if (!err)
    err = start (gpg);

  return err;
}


static gpgme_error_t
gpg_encrypt_sign (void *engine, gpgme_key_t recp[],
		  gpgme_encrypt_flags_t flags, gpgme_data_t plain,
		  gpgme_data_t ciph, int use_armor,
		  gpgme_ctx_t ctx /* FIXME */)
{
  engine_gpg_t gpg = engine;
  gpgme_error_t err;

  err = add_arg (gpg, "--encrypt");
  if (!err)
    err = add_arg (gpg, "--sign");
  if (!err && use_armor)
    err = add_arg (gpg, "--armor");

  /* If we know that all recipients are valid (full or ultimate trust)
     we can suppress further checks.  */
  if (!err && (flags & GPGME_ENCRYPT_ALWAYS_TRUST))
    err = add_arg (gpg, "--always-trust");

  if (!err)
    err = append_args_from_recipients (gpg, recp);

  if (!err)
    err = append_args_from_signers (gpg, ctx);

  /* Tell the gpg object about the data.  */
  if (!err)
    err = add_arg (gpg, "--output");
  if (!err)
    err = add_arg (gpg, "-");
  if (!err)
    err = add_data (gpg, ciph, 1, 1);
  if (!err)
    err = add_arg (gpg, "--");
  if (!err)
    err = add_data (gpg, plain, 0, 0);

  if (!err)
    err = start (gpg);

  return err;
}


static gpgme_error_t
gpg_export (void *engine, const char *pattern, unsigned int reserved,
	    gpgme_data_t keydata, int use_armor)
{
  engine_gpg_t gpg = engine;
  gpgme_error_t err;

  if (reserved)
    return gpg_error (GPG_ERR_INV_VALUE);

  err = add_arg (gpg, "--export");
  if (!err && use_armor)
    err = add_arg (gpg, "--armor");
  if (!err)
    err = add_data (gpg, keydata, 1, 1);
  if (!err)
    err = add_arg (gpg, "--");

  if (!err && pattern && *pattern)
    err = add_arg (gpg, pattern);

  if (!err)
    err = start (gpg);

  return err;
}


static gpgme_error_t
gpg_export_ext (void *engine, const char *pattern[], unsigned int reserved,
		gpgme_data_t keydata, int use_armor)
{
  engine_gpg_t gpg = engine;
  gpgme_error_t err;

  if (reserved)
    return gpg_error (GPG_ERR_INV_VALUE);

  err = add_arg (gpg, "--export");
  if (!err && use_armor)
    err = add_arg (gpg, "--armor");
  if (!err)
    err = add_data (gpg, keydata, 1, 1);
  if (!err)
    err = add_arg (gpg, "--");

  if (pattern)
    {
      while (!err && *pattern && **pattern)
	err = add_arg (gpg, *(pattern++));
    }

  if (!err)
    err = start (gpg);

  return err;
}


static gpgme_error_t
gpg_genkey (void *engine, gpgme_data_t help_data, int use_armor,
	    gpgme_data_t pubkey, gpgme_data_t seckey)
{
  engine_gpg_t gpg = engine;
  gpgme_error_t err;

  if (!gpg)
    return gpg_error (GPG_ERR_INV_VALUE);

  /* We need a special mechanism to get the fd of a pipe here, so that
     we can use this for the %pubring and %secring parameters.  We
     don't have this yet, so we implement only the adding to the
     standard keyrings.  */
  if (pubkey || seckey)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  err = add_arg (gpg, "--gen-key");
  if (!err && use_armor)
    err = add_arg (gpg, "--armor");
  if (!err)
    err = add_data (gpg, help_data, 0, 0);

  if (!err)
    err = start (gpg);

  return err;
}


static gpgme_error_t
gpg_import (void *engine, gpgme_data_t keydata)
{
  engine_gpg_t gpg = engine;
  gpgme_error_t err;

  err = add_arg (gpg, "--import");
  if (!err)
    err = add_data (gpg, keydata, 0, 0);

  if (!err)
    err = start (gpg);

  return err;
}


static gpgme_error_t
gpg_keylist (void *engine, const char *pattern, int secret_only,
	     gpgme_keylist_mode_t mode)
{
  engine_gpg_t gpg = engine;
  gpgme_error_t err;

  err = add_arg (gpg, "--with-colons");
  if (!err)
    err = add_arg (gpg, "--fixed-list-mode");
  if (!err)
    err = add_arg (gpg, "--with-fingerprint");
  if (!err)
    err = add_arg (gpg, "--with-fingerprint");
  if (!err)
    err = add_arg (gpg, secret_only ? "--list-secret-keys"
		   : ((mode & GPGME_KEYLIST_MODE_SIGS)
		      ? "--check-sigs" : "--list-keys"));
  
  /* Tell the gpg object about the data.  */
  if (!err)
    err = add_arg (gpg, "--");
  if (!err && pattern && *pattern)
    err = add_arg (gpg, pattern);

  if (!err)
    err = start (gpg);

  return err;
}


static gpgme_error_t
gpg_keylist_ext (void *engine, const char *pattern[], int secret_only,
		 int reserved, gpgme_keylist_mode_t mode)
{
  engine_gpg_t gpg = engine;
  gpgme_error_t err;

  if (reserved)
    return gpg_error (GPG_ERR_INV_VALUE);

  err = add_arg (gpg, "--with-colons");
  if (!err)
    err = add_arg (gpg, "--fixed-list-mode");
  if (!err)
    err = add_arg (gpg, "--with-fingerprint");
  if (!err)
    err = add_arg (gpg, "--with-fingerprint");
  if (!err)
    err = add_arg (gpg, secret_only ? "--list-secret-keys"
		   : ((mode & GPGME_KEYLIST_MODE_SIGS)
		      ? "--check-sigs" : "--list-keys"));
  if (!err)
    err = add_arg (gpg, "--");

  if (pattern)
    {
      while (!err && *pattern && **pattern)
	err = add_arg (gpg, *(pattern++));
    }

  if (!err)
    err = start (gpg);

  return err;
}


static gpgme_error_t
gpg_sign (void *engine, gpgme_data_t in, gpgme_data_t out,
	  gpgme_sig_mode_t mode, int use_armor, int use_textmode,
	  int include_certs, gpgme_ctx_t ctx /* FIXME */)
{
  engine_gpg_t gpg = engine;
  gpgme_error_t err;

  if (mode == GPGME_SIG_MODE_CLEAR)
    err = add_arg (gpg, "--clearsign");
  else
    {
      err = add_arg (gpg, "--sign");
      if (!err && mode == GPGME_SIG_MODE_DETACH)
	err = add_arg (gpg, "--detach");
      if (!err && use_armor)
	err = add_arg (gpg, "--armor");
      if (!err && use_textmode)
	err = add_arg (gpg, "--textmode");
    }

  if (!err)
    err = append_args_from_signers (gpg, ctx);

  /* Tell the gpg object about the data.  */
  if (!err)
    err = add_data (gpg, in, 0, 0);
  if (!err)
    err = add_data (gpg, out, 1, 1);

  if (!err)
    start (gpg);

  return err;
}

static gpgme_error_t
gpg_trustlist (void *engine, const char *pattern)
{
  engine_gpg_t gpg = engine;
  gpgme_error_t err;

  err = add_arg (gpg, "--with-colons");
  if (!err)
    err = add_arg (gpg, "--list-trust-path");
  
  /* Tell the gpg object about the data.  */
  if (!err)
    err = add_arg (gpg, "--");
  if (!err)
    err = add_arg (gpg, pattern);

  if (!err)
    err = start (gpg);

  return err;
}


static gpgme_error_t
gpg_verify (void *engine, gpgme_data_t sig, gpgme_data_t signed_text,
	    gpgme_data_t plaintext)
{
  engine_gpg_t gpg = engine;
  gpgme_error_t err = 0;

  if (plaintext)
    {
      /* Normal or cleartext signature.  */

      err = add_arg (gpg, "--output");
      if (!err)
	err = add_arg (gpg, "-");
      if (!err)
	err = add_arg (gpg, "--");
      if (!err)
	err = add_data (gpg, sig, 0, 0);
      if (!err)
	err = add_data (gpg, plaintext, 1, 1);
    }
  else
    {
      err = add_arg (gpg, "--verify");
      if (!err)
	err = add_arg (gpg, "--");
      if (!err)
	err = add_data (gpg, sig, -1, 0);
      if (signed_text)
	{
	  if (!err)
	    err = add_arg (gpg, "-");
	  if (!err)
	    err = add_data (gpg, signed_text, 0, 0);
	}
    }

  if (!err)
    err = start (gpg);

  return err;
}


static void
gpg_set_io_cbs (void *engine, gpgme_io_cbs_t io_cbs)
{
  engine_gpg_t gpg = engine;

  gpg->io_cbs = *io_cbs;
}


struct engine_ops _gpgme_engine_ops_gpg =
  {
    /* Static functions.  */
    _gpgme_get_gpg_path,
    gpg_get_version,
    gpg_get_req_version,
    gpg_new,

    /* Member functions.  */
    gpg_release,
    gpg_set_status_handler,
    gpg_set_command_handler,
    gpg_set_colon_line_handler,
    gpg_decrypt,
    gpg_delete,
    gpg_edit,
    gpg_encrypt,
    gpg_encrypt_sign,
    gpg_export,
    gpg_export_ext,
    gpg_genkey,
    gpg_import,
    gpg_keylist,
    gpg_keylist_ext,
    gpg_sign,
    gpg_trustlist,
    gpg_verify,
    gpg_set_io_cbs,
    gpg_io_event
  };
