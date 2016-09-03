/* engine-gpg.c - Gpg Engine.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007,
                 2009, 2010, 2012, 2013 g10 Code GmbH

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
   License along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif

#include "gpgme.h"
#include "util.h"
#include "ops.h"
#include "wait.h"
#include "context.h"  /*temp hack until we have GpmeData methods to do I/O */
#include "priv-io.h"
#include "sema.h"
#include "debug.h"
#include "data.h"

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
  int *arg_locp;   /* Write back the argv idx of this argument when
		      building command line to this location.  */
  char arg[1];     /* Used if data above is not used.  */
};


struct fd_data_map_s
{
  gpgme_data_t data;
  int inbound;  /* true if this is used for reading from gpg */
  int dup_to;
  int fd;       /* the fd to use */
  int peer_fd;  /* the other side of the pipe */
  int arg_loc;  /* The index into the argv for translation purposes.  */
  void *tag;
};


typedef gpgme_error_t (*colon_preprocessor_t) (char *line, char **rline);

struct engine_gpg
{
  char *file_name;
  char *version;

  char *lc_messages;
  char *lc_ctype;

  struct arg_and_data_s *arglist;
  struct arg_and_data_s **argtail;

  struct
  {
    int fd[2];
    int arg_loc;
    size_t bufsize;
    char *buffer;
    size_t readpos;
    int eof;
    engine_status_handler_t fnc;
    void *fnc_value;
    gpgme_status_cb_t mon_cb;
    void *mon_cb_value;
    void *tag;
  } status;

  /* This is a kludge - see the comment at colon_line_handler.  */
  struct
  {
    int fd[2];
    int arg_loc;
    size_t bufsize;
    char *buffer;
    size_t readpos;
    int eof;
    engine_colon_line_handler_t fnc;  /* this indicate use of this structrue */
    void *fnc_value;
    void *tag;
    colon_preprocessor_t preprocess_fnc;
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
  gpgme_pinentry_mode_t pinentry_mode;
};

typedef struct engine_gpg *engine_gpg_t;


static void
gpg_io_event (void *engine, gpgme_event_io_t type, void *type_data)
{
  engine_gpg_t gpg = engine;

  TRACE3 (DEBUG_ENGINE, "gpgme:gpg_io_event", gpg,
          "event %p, type %d, type_data %p",
          gpg->io_cbs.event, type, type_data);
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
  else if (gpg->cmd.fd == fd)
    gpg->cmd.fd = -1;
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

/* If FRONT is true, push at the front of the list.  Use this for
   options added late in the process.  */
static gpgme_error_t
_add_arg (engine_gpg_t gpg, const char *prefix, const char *arg, size_t arglen,
          int front, int *arg_locp)
{
  struct arg_and_data_s *a;
  size_t prefixlen = prefix? strlen (prefix) : 0;

  assert (gpg);
  assert (arg);

  a = malloc (sizeof *a + prefixlen + arglen);
  if (!a)
    return gpg_error_from_syserror ();

  a->data = NULL;
  a->dup_to = -1;
  a->arg_locp = arg_locp;

  if (prefixlen)
    memcpy (a->arg, prefix, prefixlen);
  memcpy (a->arg + prefixlen, arg, arglen);
  a->arg[prefixlen + arglen] = 0;
  if (front)
    {
      a->next = gpg->arglist;
      if (!gpg->arglist)
	{
	  /* If this is the first argument, we need to update the tail
	     pointer.  */
	  gpg->argtail = &a->next;
	}
      gpg->arglist = a;
    }
  else
    {
      a->next = NULL;
      *gpg->argtail = a;
      gpg->argtail = &a->next;
    }

  return 0;
}


static gpgme_error_t
add_arg_ext (engine_gpg_t gpg, const char *arg, int front)
{
  return _add_arg (gpg, NULL, arg, strlen (arg), front, NULL);
}

static gpgme_error_t
add_arg_with_locp (engine_gpg_t gpg, const char *arg, int *locp)
{
  return _add_arg (gpg, NULL, arg, strlen (arg), 0, locp);
}

static gpgme_error_t
add_arg (engine_gpg_t gpg, const char *arg)
{
  return _add_arg (gpg, NULL, arg, strlen (arg), 0, NULL);
}

static gpgme_error_t
add_arg_pfx (engine_gpg_t gpg, const char *prefix, const char *arg)
{
  return _add_arg (gpg, prefix, arg, strlen (arg), 0, NULL);
}

static gpgme_error_t
add_arg_len (engine_gpg_t gpg, const char *prefix,
             const char *arg, size_t arglen)
{
  return _add_arg (gpg, prefix, arg, arglen, 0, NULL);
}


static gpgme_error_t
add_data (engine_gpg_t gpg, gpgme_data_t data, int dup_to, int inbound)
{
  struct arg_and_data_s *a;

  assert (gpg);
  assert (data);

  a = malloc (sizeof *a - 1);
  if (!a)
    return gpg_error_from_syserror ();
  a->next = NULL;
  a->data = data;
  a->inbound = inbound;
  a->arg_locp = NULL;

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


/* Return true if the engine's version is at least VERSION.  */
static int
have_gpg_version (engine_gpg_t gpg, const char *version)
{
  return _gpgme_compare_versions (gpg->version, version);
}



static char *
gpg_get_version (const char *file_name)
{
  return _gpgme_get_program_version (file_name ? file_name
				     : _gpgme_get_default_gpg_name ());
}


static const char *
gpg_get_req_version (void)
{
  return "1.4.0";
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


static gpgme_error_t
gpg_cancel (void *engine)
{
  engine_gpg_t gpg = engine;

  if (!gpg)
    return gpg_error (GPG_ERR_INV_VALUE);

  /* If gpg may be waiting for a cmd, close the cmd fd first.  On
     Windows, close operations block on the reader/writer thread.  */
  if (gpg->cmd.used)
    {
      if (gpg->cmd.fd != -1)
	_gpgme_io_close (gpg->cmd.fd);
      else if (gpg->fd_data_map
	       && gpg->fd_data_map[gpg->cmd.idx].fd != -1)
	_gpgme_io_close (gpg->fd_data_map[gpg->cmd.idx].fd);
    }

  if (gpg->status.fd[0] != -1)
    _gpgme_io_close (gpg->status.fd[0]);
  if (gpg->status.fd[1] != -1)
    _gpgme_io_close (gpg->status.fd[1]);
  if (gpg->colon.fd[0] != -1)
    _gpgme_io_close (gpg->colon.fd[0]);
  if (gpg->colon.fd[1] != -1)
    _gpgme_io_close (gpg->colon.fd[1]);
  if (gpg->fd_data_map)
    {
      free_fd_data_map (gpg->fd_data_map);
      gpg->fd_data_map = NULL;
    }

  return 0;
}

static void
gpg_release (void *engine)
{
  engine_gpg_t gpg = engine;

  if (!gpg)
    return;

  gpg_cancel (engine);

  if (gpg->file_name)
    free (gpg->file_name);
  if (gpg->version)
    free (gpg->version);

  if (gpg->lc_messages)
    free (gpg->lc_messages);
  if (gpg->lc_ctype)
    free (gpg->lc_ctype);

  while (gpg->arglist)
    {
      struct arg_and_data_s *next = gpg->arglist->next;

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

  free (gpg);
}


static gpgme_error_t
gpg_new (void **engine, const char *file_name, const char *home_dir,
         const char *version)
{
  engine_gpg_t gpg;
  gpgme_error_t rc = 0;
  char *dft_display = NULL;
  char dft_ttyname[64];
  char *dft_ttytype = NULL;
  char *env_tty = NULL;

  gpg = calloc (1, sizeof *gpg);
  if (!gpg)
    return gpg_error_from_syserror ();

  if (file_name)
    {
      gpg->file_name = strdup (file_name);
      if (!gpg->file_name)
	{
	  rc = gpg_error_from_syserror ();
	  goto leave;
	}
    }

  if (version)
    {
      gpg->version = strdup (version);
      if (!gpg->version)
	{
	  rc = gpg_error_from_syserror ();
	  goto leave;
	}
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
      rc = gpg_error_from_syserror ();
      goto leave;
    }
  /* In any case we need a status pipe - create it right here and
     don't handle it with our generic gpgme_data_t mechanism.  */
  if (_gpgme_io_pipe (gpg->status.fd, 1) == -1)
    {
      rc = gpg_error_from_syserror ();
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

  if (home_dir)
    {
      rc = add_arg (gpg, "--homedir");
      if (!rc)
	rc = add_arg (gpg, home_dir);
      if (rc)
	goto leave;
    }

  rc = add_arg (gpg, "--status-fd");
  if (rc)
    goto leave;

  {
    char buf[25];
    _gpgme_io_fd2str (buf, sizeof (buf), gpg->status.fd[1]);
    rc = add_arg_with_locp (gpg, buf, &gpg->status.arg_loc);
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
  if (rc)
    goto leave;

  rc = _gpgme_getenv ("DISPLAY", &dft_display);
  if (rc)
    goto leave;
  if (dft_display)
    {
      rc = add_arg (gpg, "--display");
      if (!rc)
	rc = add_arg (gpg, dft_display);

      free (dft_display);
      if (rc)
	goto leave;
    }

  rc = _gpgme_getenv ("GPG_TTY", &env_tty);
  if (isatty (1) || env_tty || rc)
    {
      int err = 0;

      if (rc)
        goto leave;
      else if (env_tty)
        {
          snprintf (dft_ttyname, sizeof (dft_ttyname), "%s", env_tty);
          free (env_tty);
        }
      else
        err = ttyname_r (1, dft_ttyname, sizeof (dft_ttyname));

      /* Even though isatty() returns 1, ttyname_r() may fail in many
	 ways, e.g., when /dev/pts is not accessible under chroot.  */
      if (!err)
	{
          if (*dft_ttyname)
            {
              rc = add_arg (gpg, "--ttyname");
              if (!rc)
                rc = add_arg (gpg, dft_ttyname);
            }
          else
            rc = 0;
          if (!rc)
	    {
	      rc = _gpgme_getenv ("TERM", &dft_ttytype);
	      if (rc)
		goto leave;

              if (dft_ttytype)
                {
                  rc = add_arg (gpg, "--ttytype");
                  if (!rc)
                    rc = add_arg (gpg, dft_ttytype);
                }

	      free (dft_ttytype);
	    }
	  if (rc)
	    goto leave;
	}
    }

 leave:
  if (rc)
    gpg_release (gpg);
  else
    *engine = gpg;
  return rc;
}


static gpgme_error_t
gpg_set_locale (void *engine, int category, const char *value)
{
  engine_gpg_t gpg = engine;

  if (0)
    ;
#ifdef LC_CTYPE
  else if (category == LC_CTYPE)
    {
      if (gpg->lc_ctype)
        {
          free (gpg->lc_ctype);
          gpg->lc_ctype = NULL;
        }
      if (value)
	{
	  gpg->lc_ctype = strdup (value);
	  if (!gpg->lc_ctype)
	    return gpg_error_from_syserror ();
	}
    }
#endif
#ifdef LC_MESSAGES
  else if (category == LC_MESSAGES)
    {
      if (gpg->lc_messages)
        {
          free (gpg->lc_messages);
          gpg->lc_messages = NULL;
        }
      if (value)
	{
	  gpg->lc_messages = strdup (value);
	  if (!gpg->lc_messages)
	    return gpg_error_from_syserror ();
	}
    }
#endif /* LC_MESSAGES */
  else
    return gpg_error (GPG_ERR_INV_VALUE);

  return 0;
}

/* This sets a status callback for monitoring status lines before they
 * are passed to a caller set handler.  */
static void
gpg_set_status_cb (void *engine, gpgme_status_cb_t cb, void *cb_value)
{
  engine_gpg_t gpg = engine;

  gpg->status.mon_cb = cb;
  gpg->status.mon_cb_value = cb_value;
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
    return gpg_error_from_syserror ();

  if (_gpgme_io_pipe (gpg->colon.fd, 1) == -1)
    {
      int saved_err = gpg_error_from_syserror ();
      free (gpg->colon.buffer);
      gpg->colon.buffer = NULL;
      return saved_err;
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
  struct io_cb_data *data = (struct io_cb_data *) opaque;
  engine_gpg_t gpg = (engine_gpg_t) data->handler_value;
  gpgme_error_t err;
  int processed = 0;
  assert (gpg->cmd.used);
  assert (gpg->cmd.code);
  assert (gpg->cmd.fnc);

  err = gpg->cmd.fnc (gpg->cmd.fnc_value, gpg->cmd.code, gpg->cmd.keyword, fd,
		      &processed);

  gpg->cmd.code = 0;
  /* And sleep again until read_status will wake us up again.  */
  /* XXX We must check if there are any more fds active after removing
     this one.  */
  (*gpg->io_cbs.remove) (gpg->fd_data_map[gpg->cmd.idx].tag);
  gpg->cmd.fd = gpg->fd_data_map[gpg->cmd.idx].fd;
  gpg->fd_data_map[gpg->cmd.idx].fd = -1;

  if (err)
    return err;

  /* We always need to send at least a newline character.  */
  if (!processed)
    _gpgme_io_write (fd, "\n", 1);

  return 0;
}



/* The Fnc will be called to get a value for one of the commands with
   a key KEY.  If the Code passed to FNC is 0, the function may release
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
build_argv (engine_gpg_t gpg, const char *pgmname)
{
  gpgme_error_t err;
  struct arg_and_data_s *a;
  struct fd_data_map_s *fd_data_map;
  size_t datac=0, argc=0;
  char **argv;
  int need_special = 0;
  int use_agent = 0;
  char *p;

  if (_gpgme_in_gpg_one_mode ())
    {
      /* In GnuPG-1 mode we don't want to use the agent with a
         malformed environment variable.  This is only a very basic
         test but sufficient to make our life in the regression tests
         easier.  With GnuPG-2 the agent is anyway required and on
         modern installations GPG_AGENT_INFO is optional.  */
      err = _gpgme_getenv ("GPG_AGENT_INFO", &p);
      if (err)
        return err;
      use_agent = (p && strchr (p, ':'));
      if (p)
        free (p);
    }

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
  if (gpg->pinentry_mode)
    argc++;
  if (!gpg->cmd.used)
    argc++;	/* --batch */
  argc += 1;	/* --no-sk-comments */

  argv = calloc (argc + 1, sizeof *argv);
  if (!argv)
    return gpg_error_from_syserror ();
  fd_data_map = calloc (datac + 1, sizeof *fd_data_map);
  if (!fd_data_map)
    {
      int saved_err = gpg_error_from_syserror ();
      free_argv (argv);
      return saved_err;
    }

  argc = datac = 0;
  argv[argc] = strdup (_gpgme_get_basename (pgmname)); /* argv[0] */
  if (!argv[argc])
    {
      int saved_err = gpg_error_from_syserror ();
      free (fd_data_map);
      free_argv (argv);
      return saved_err;
    }
  argc++;
  if (need_special)
    {
      argv[argc] = strdup ("--enable-special-filenames");
      if (!argv[argc])
	{
          int saved_err = gpg_error_from_syserror ();
	  free (fd_data_map);
	  free_argv (argv);
	  return saved_err;
        }
      argc++;
    }
  if (use_agent)
    {
      argv[argc] = strdup ("--use-agent");
      if (!argv[argc])
	{
          int saved_err = gpg_error_from_syserror ();
	  free (fd_data_map);
	  free_argv (argv);
	  return saved_err;
        }
      argc++;
    }

  if (gpg->pinentry_mode && have_gpg_version (gpg, "2.1.0"))
    {
      const char *s = NULL;
      switch (gpg->pinentry_mode)
        {
        case GPGME_PINENTRY_MODE_DEFAULT: break;
        case GPGME_PINENTRY_MODE_ASK:     s = "--pinentry-mode=ask"; break;
        case GPGME_PINENTRY_MODE_CANCEL:  s = "--pinentry-mode=cancel"; break;
        case GPGME_PINENTRY_MODE_ERROR:   s = "--pinentry-mode=error"; break;
        case GPGME_PINENTRY_MODE_LOOPBACK:s = "--pinentry-mode=loopback"; break;
        }
      if (s)
        {
          argv[argc] = strdup (s);
          if (!argv[argc])
            {
              int saved_err = gpg_error_from_syserror ();
              free (fd_data_map);
              free_argv (argv);
              return saved_err;
            }
          argc++;
        }
    }

  if (!gpg->cmd.used)
    {
      argv[argc] = strdup ("--batch");
      if (!argv[argc])
	{
          int saved_err = gpg_error_from_syserror ();
	  free (fd_data_map);
	  free_argv (argv);
	  return saved_err;
        }
      argc++;
    }
  argv[argc] = strdup ("--no-sk-comments");
  if (!argv[argc])
    {
      int saved_err = gpg_error_from_syserror ();
      free (fd_data_map);
      free_argv (argv);
      return saved_err;
    }
  argc++;
  for (a = gpg->arglist; a; a = a->next)
    {
      if (a->arg_locp)
	*(a->arg_locp) = argc;

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
                /* We leak fd_data_map and the fds.  This is not easy
                   to avoid and given that we reach this here only
                   after a malloc failure for a small object, it is
                   probably better not to do anything.  */
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
	      char *ptr;
	      int buflen = 25;

	      argv[argc] = malloc (buflen);
	      if (!argv[argc])
		{
                  int saved_err = gpg_error_from_syserror ();
		  free (fd_data_map);
		  free_argv (argv);
		  return saved_err;
                }

	      ptr = argv[argc];
	      if (!a->print_fd)
		{
		  *(ptr++) = '-';
		  *(ptr++) = '&';
		  buflen -= 2;
		}

	      _gpgme_io_fd2str (ptr, buflen, fd_data_map[datac].peer_fd);
	      fd_data_map[datac].arg_loc = argc;
	      argc++;
            }
	  datac++;
        }
      else
	{
	  argv[argc] = strdup (a->arg);
	  if (!argv[argc])
	    {
              int saved_err = gpg_error_from_syserror ();
	      free (fd_data_map);
	      free_argv (argv);
	      return saved_err;
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
  gpgme_error_t err;

  assert (buffer);
  if (bufsize - readpos < 256)
    {
      /* Need more room for the read.  */
      bufsize += 1024;
      buffer = realloc (buffer, bufsize);
      if (!buffer)
	return gpg_error_from_syserror ();
    }

  nread = _gpgme_io_read (gpg->status.fd[0],
			  buffer + readpos, bufsize-readpos);
  if (nread == -1)
    return gpg_error_from_syserror ();

  if (!nread)
    {
      err = 0;
      gpg->status.eof = 1;
      if (gpg->status.mon_cb)
        err = gpg->status.mon_cb (gpg->status.mon_cb_value, "", "");
      if (gpg->status.fnc)
        {
          char emptystring[1] = {0};
          err = gpg->status.fnc (gpg->status.fnc_value,
                                 GPGME_STATUS_EOF, emptystring);
          if (gpg_err_code (err) == GPG_ERR_FALSE)
            err = 0; /* Drop special error code.  */
        }

      return err;
    }

  while (nread > 0)
    {
      for (p = buffer + readpos; nread; nread--, p++)
	{
	  if (*p == '\n')
	    {
	      /* (we require that the last line is terminated by a LF) */
	      if (p > buffer && p[-1] == '\r')
		p[-1] = 0;
	      *p = 0;
	      if (!strncmp (buffer, "[GNUPG:] ", 9)
		  && buffer[9] >= 'A' && buffer[9] <= 'Z')
		{
		  char *rest;
		  gpgme_status_code_t r;

		  rest = strchr (buffer + 9, ' ');
		  if (!rest)
		    rest = p; /* Set to an empty string.  */
		  else
		    *rest++ = 0;

		  r = _gpgme_parse_status (buffer + 9);
                  if (gpg->status.mon_cb && r != GPGME_STATUS_PROGRESS)
                    {
                      /* Note that we call the monitor even if we do
                       * not know the status code (r < 0).  */
                      err = gpg->status.mon_cb (gpg->status.mon_cb_value,
                                                buffer + 9, rest);
                      if (err)
                        return err;
                    }
		  if (r >= 0)
		    {
		      if (gpg->cmd.used
			  && (r == GPGME_STATUS_GET_BOOL
			      || r == GPGME_STATUS_GET_LINE
			      || r == GPGME_STATUS_GET_HIDDEN))
			{
			  gpg->cmd.code = r;
			  if (gpg->cmd.keyword)
			    free (gpg->cmd.keyword);
			  gpg->cmd.keyword = strdup (rest);
			  if (!gpg->cmd.keyword)
			    return gpg_error_from_syserror ();
			  /* This should be the last thing we have
			     received and the next thing will be that
			     the command handler does its action.  */
			  if (nread > 1)
			    TRACE0 (DEBUG_CTX, "gpgme:read_status", 0,
				    "error: unexpected data");

			  add_io_cb (gpg, gpg->cmd.fd, 0,
				     command_handler, gpg,
				     &gpg->fd_data_map[gpg->cmd.idx].tag);
			  gpg->fd_data_map[gpg->cmd.idx].fd = gpg->cmd.fd;
			  gpg->cmd.fd = -1;
                        }
		      else if (gpg->status.fnc)
			{
			  err = gpg->status.fnc (gpg->status.fnc_value,
						 r, rest);
                          if (gpg_err_code (err) == GPG_ERR_FALSE)
                            err = 0; /* Drop special error code.  */
			  if (err)
			    return err;
                        }

		      if (r == GPGME_STATUS_END_STREAM)
			{
			  if (gpg->cmd.used)
			    {
			      /* Before we can actually add the
				 command fd, we might have to flush
				 the linked output data pipe.  */
			      if (gpg->cmd.linked_idx != -1
				  && gpg->fd_data_map[gpg->cmd.linked_idx].fd
				  != -1)
				{
				  struct io_select_fd_s fds;
				  fds.fd =
				    gpg->fd_data_map[gpg->cmd.linked_idx].fd;
				  fds.for_read = 1;
				  fds.for_write = 0;
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
  struct io_cb_data *data = (struct io_cb_data *) opaque;
  engine_gpg_t gpg = (engine_gpg_t) data->handler_value;
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
	return gpg_error_from_syserror ();
    }

  nread = _gpgme_io_read (gpg->colon.fd[0], buffer+readpos, bufsize-readpos);
  if (nread == -1)
    return gpg_error_from_syserror ();

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
		 and escaping of special characters.  We require at
		 least one colon to cope with some other printed
		 information.  */
	      *p = 0;
	      if (*buffer && strchr (buffer, ':'))
		{
		  char *line = NULL;

		  if (gpg->colon.preprocess_fnc)
		    {
		      gpgme_error_t err;

		      err = gpg->colon.preprocess_fnc (buffer, &line);
		      if (err)
			return err;
		    }

		  assert (gpg->colon.fnc);
                  if (line)
                    {
                      char *linep = line;
                      char *endp;

                      do
                        {
                          endp = strchr (linep, '\n');
                          if (endp)
                            *endp++ = 0;
                          gpg->colon.fnc (gpg->colon.fnc_value, linep);
                          linep = endp;
                        }
                      while (linep && *linep);

                      free (line);
                    }
                  else
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
  struct io_cb_data *data = (struct io_cb_data *) opaque;
  engine_gpg_t gpg = (engine_gpg_t) data->handler_value;
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
  int i, n;
  int status;
  struct spawn_fd_item_s *fd_list;
  pid_t pid;
  const char *pgmname;

  if (!gpg)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!gpg->file_name && !_gpgme_get_default_gpg_name ())
    return trace_gpg_error (GPG_ERR_INV_ENGINE);

  if (gpg->lc_ctype)
    {
      rc = add_arg_ext (gpg, gpg->lc_ctype, 1);
      if (!rc)
	rc = add_arg_ext (gpg, "--lc-ctype", 1);
      if (rc)
	return rc;
    }

  if (gpg->lc_messages)
    {
      rc = add_arg_ext (gpg, gpg->lc_messages, 1);
      if (!rc)
	rc = add_arg_ext (gpg, "--lc-messages", 1);
      if (rc)
	return rc;
    }

  pgmname = gpg->file_name ? gpg->file_name : _gpgme_get_default_gpg_name ();
  rc = build_argv (gpg, pgmname);
  if (rc)
    return rc;

  /* status_fd, colon_fd and end of list.  */
  n = 3;
  for (i = 0; gpg->fd_data_map[i].data; i++)
    n++;
  fd_list = calloc (n, sizeof *fd_list);
  if (! fd_list)
    return gpg_error_from_syserror ();

  /* Build the fd list for the child.  */
  n = 0;
  fd_list[n].fd = gpg->status.fd[1];
  fd_list[n].dup_to = -1;
  fd_list[n].arg_loc = gpg->status.arg_loc;
  n++;
  if (gpg->colon.fnc)
    {
      fd_list[n].fd = gpg->colon.fd[1];
      fd_list[n].dup_to = 1;
      n++;
    }
  for (i = 0; gpg->fd_data_map[i].data; i++)
    {
      fd_list[n].fd = gpg->fd_data_map[i].peer_fd;
      fd_list[n].dup_to = gpg->fd_data_map[i].dup_to;
      fd_list[n].arg_loc = gpg->fd_data_map[i].arg_loc;
      n++;
    }
  fd_list[n].fd = -1;
  fd_list[n].dup_to = -1;

  status = _gpgme_io_spawn (pgmname, gpg->argv,
                            (IOSPAWN_FLAG_DETACHED |IOSPAWN_FLAG_ALLOW_SET_FG),
                            fd_list, NULL, NULL, &pid);
  {
    int saved_err = gpg_error_from_syserror ();
    free (fd_list);
    if (status == -1)
      return saved_err;
  }

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

  gpg_io_event (gpg, GPGME_EVENT_START, NULL);

  /* fixme: check what data we can release here */
  return 0;
}


/* Add the --input-size-hint option if requested.  */
static gpgme_error_t
add_input_size_hint (engine_gpg_t gpg, gpgme_data_t data)
{
  gpgme_error_t err;
  gpgme_off_t value = _gpgme_data_get_size_hint (data);
  char numbuf[50];  /* Large enough for even 2^128 in base-10.  */
  char *p;

  if (!value || !have_gpg_version (gpg, "2.1.15"))
    return 0;

  err = add_arg (gpg, "--input-size-hint");
  if (!err)
    {
      p = numbuf + sizeof numbuf;
      *--p = 0;
      do
        {
          *--p = '0' + (value % 10);
          value /= 10;
        }
      while (value);
      err = add_arg (gpg, p);
    }
  return err;
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
    err = add_input_size_hint (gpg, ciph);
  if (!err)
    err = add_arg (gpg, "--");
  if (!err)
    err = add_data (gpg, ciph, -1, 0);

  if (!err)
    err = start (gpg);
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
    err = start (gpg);
  return err;
}


static gpgme_error_t
gpg_passwd (void *engine, gpgme_key_t key, unsigned int flags)
{
  engine_gpg_t gpg = engine;
  gpgme_error_t err;

  (void)flags;

  if (!key || !key->subkeys || !key->subkeys->fpr)
    return gpg_error (GPG_ERR_INV_CERT_OBJ);

  err = add_arg (gpg, "--passwd");
  if (!err)
    err = add_arg (gpg, key->subkeys->fpr);
  if (!err)
    err = start (gpg);
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
      if (err)
        break;
    }
  return err;
}


static gpgme_error_t
append_args_from_sig_notations (engine_gpg_t gpg, gpgme_ctx_t ctx /* FIXME */)
{
  gpgme_error_t err = 0;
  gpgme_sig_notation_t notation;

  notation = gpgme_sig_notation_get (ctx);

  while (!err && notation)
    {
      if (notation->name
	  && !(notation->flags & GPGME_SIG_NOTATION_HUMAN_READABLE))
	err = gpg_error (GPG_ERR_INV_VALUE);
      else if (notation->name)
	{
	  char *arg;

	  /* Maximum space needed is one byte for the "critical" flag,
	     the name, one byte for '=', the value, and a terminating
	     '\0'.  */

	  arg = malloc (1 + notation->name_len + 1 + notation->value_len + 1);
	  if (!arg)
	    err = gpg_error_from_syserror ();

	  if (!err)
	    {
	      char *argp = arg;

	      if (notation->critical)
		*(argp++) = '!';

	      memcpy (argp, notation->name, notation->name_len);
	      argp += notation->name_len;

	      *(argp++) = '=';

	      /* We know that notation->name is '\0' terminated.  */
	      strcpy (argp, notation->value);
	    }

	  if (!err)
	    err = add_arg (gpg, "--sig-notation");
	  if (!err)
	    err = add_arg (gpg, arg);

	  if (arg)
	    free (arg);
	}
      else
	{
	  /* This is a policy URL.  */

	  char *value;

	  if (notation->critical)
	    {
	      value = malloc (1 + notation->value_len + 1);
	      if (!value)
		err = gpg_error_from_syserror ();
	      else
		{
		  value[0] = '!';
		  /* We know that notation->value is '\0' terminated.  */
		  strcpy (&value[1], notation->value);
		}
	    }
	  else
	    value = notation->value;

	  if (!err)
	    err = add_arg (gpg, "--sig-policy-url");
	  if (!err)
	    err = add_arg (gpg, value);

	  if (value != notation->value)
	    free (value);
      	}

      notation = notation->next;
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
  if (!err && type == 0)
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
  gpgme_error_t err = 0;

  if (recp)
    err = add_arg (gpg, "--encrypt");

  if (!err && ((flags & GPGME_ENCRYPT_SYMMETRIC) || !recp))
    err = add_arg (gpg, "--symmetric");

  if (!err && use_armor)
    err = add_arg (gpg, "--armor");

  if (!err && (flags & GPGME_ENCRYPT_NO_COMPRESS))
    err = add_arg (gpg, "--compress-algo=none");

  if (gpgme_data_get_encoding (plain) == GPGME_DATA_ENCODING_MIME
      && have_gpg_version (gpg, "2.1.14"))
    err = add_arg (gpg, "--mimemode");

  if (recp)
    {
      /* If we know that all recipients are valid (full or ultimate trust)
	 we can suppress further checks.  */
      if (!err && (flags & GPGME_ENCRYPT_ALWAYS_TRUST))
	err = add_arg (gpg, "--always-trust");

      if (!err && (flags & GPGME_ENCRYPT_NO_ENCRYPT_TO))
	err = add_arg (gpg, "--no-encrypt-to");

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
  if (gpgme_data_get_file_name (plain))
    {
      if (!err)
	err = add_arg (gpg, "--set-filename");
      if (!err)
	err = add_arg (gpg, gpgme_data_get_file_name (plain));
    }
  if (!err)
    err = add_input_size_hint (gpg, plain);
  if (!err)
    err = add_arg (gpg, "--");
  if (!err)
    err = add_data (gpg, plain, -1, 0);

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
  gpgme_error_t err = 0;

  if (recp)
    err = add_arg (gpg, "--encrypt");

  if (!err && ((flags & GPGME_ENCRYPT_SYMMETRIC) || !recp))
    err = add_arg (gpg, "--symmetric");

  if (!err)
    err = add_arg (gpg, "--sign");
  if (!err && use_armor)
    err = add_arg (gpg, "--armor");

  if (!err && (flags & GPGME_ENCRYPT_NO_COMPRESS))
    err = add_arg (gpg, "--compress-algo=none");

  if (gpgme_data_get_encoding (plain) == GPGME_DATA_ENCODING_MIME
      && have_gpg_version (gpg, "2.1.14"))
    err = add_arg (gpg, "--mimemode");

  if (recp)
    {
      /* If we know that all recipients are valid (full or ultimate trust)
	 we can suppress further checks.  */
      if (!err && (flags & GPGME_ENCRYPT_ALWAYS_TRUST))
	err = add_arg (gpg, "--always-trust");

      if (!err && (flags & GPGME_ENCRYPT_NO_ENCRYPT_TO))
	err = add_arg (gpg, "--no-encrypt-to");

      if (!err)
	err = append_args_from_recipients (gpg, recp);
    }

  if (!err)
    err = append_args_from_signers (gpg, ctx);

  if (!err)
    err = append_args_from_sig_notations (gpg, ctx);

  /* Tell the gpg object about the data.  */
  if (!err)
    err = add_arg (gpg, "--output");
  if (!err)
    err = add_arg (gpg, "-");
  if (!err)
    err = add_data (gpg, ciph, 1, 1);
  if (gpgme_data_get_file_name (plain))
    {
      if (!err)
	err = add_arg (gpg, "--set-filename");
      if (!err)
	err = add_arg (gpg, gpgme_data_get_file_name (plain));
    }
  if (!err)
    err = add_input_size_hint (gpg, plain);
  if (!err)
    err = add_arg (gpg, "--");
  if (!err)
    err = add_data (gpg, plain, -1, 0);

  if (!err)
    err = start (gpg);

  return err;
}


static gpgme_error_t
export_common (engine_gpg_t gpg, gpgme_export_mode_t mode,
               gpgme_data_t keydata, int use_armor)
{
  gpgme_error_t err = 0;

  if ((mode & ~(GPGME_EXPORT_MODE_EXTERN
                |GPGME_EXPORT_MODE_MINIMAL
                |GPGME_EXPORT_MODE_SECRET)))
    return gpg_error (GPG_ERR_NOT_SUPPORTED);

  if ((mode & GPGME_EXPORT_MODE_MINIMAL))
    err = add_arg (gpg, "--export-options=export-minimal");

  if (err)
    ;
  else if ((mode & GPGME_EXPORT_MODE_EXTERN))
    {
      err = add_arg (gpg, "--send-keys");
    }
  else
    {
      if ((mode & GPGME_EXPORT_MODE_SECRET))
        err = add_arg (gpg, "--export-secret-keys");
      else
        err = add_arg (gpg, "--export");
      if (!err && use_armor)
        err = add_arg (gpg, "--armor");
      if (!err)
        err = add_data (gpg, keydata, 1, 1);
    }
  if (!err)
    err = add_arg (gpg, "--");

  return err;
}


static gpgme_error_t
gpg_export (void *engine, const char *pattern, gpgme_export_mode_t mode,
	    gpgme_data_t keydata, int use_armor)
{
  engine_gpg_t gpg = engine;
  gpgme_error_t err;

  err = export_common (gpg, mode, keydata, use_armor);

  if (!err && pattern && *pattern)
    err = add_arg (gpg, pattern);

  if (!err)
    err = start (gpg);

  return err;
}


static gpgme_error_t
gpg_export_ext (void *engine, const char *pattern[], gpgme_export_mode_t mode,
		gpgme_data_t keydata, int use_armor)
{
  engine_gpg_t gpg = engine;
  gpgme_error_t err;

  err = export_common (gpg, mode, keydata, use_armor);

  if (pattern)
    {
      while (!err && *pattern && **pattern)
	err = add_arg (gpg, *(pattern++));
    }

  if (!err)
    err = start (gpg);

  return err;
}



/* Helper to add algo, usage, and expire to the list of args.  */
static gpgme_error_t
gpg_add_algo_usage_expire (engine_gpg_t gpg,
                           const char *algo,
                           unsigned long expires,
                           unsigned int flags)
{
  gpg_error_t err;

  /* This condition is only required to allow the use of gpg < 2.1.16 */
  if (algo
      || (flags & (GPGME_CREATE_SIGN | GPGME_CREATE_ENCR
                   | GPGME_CREATE_CERT | GPGME_CREATE_AUTH))
      || expires)
    {
      err = add_arg (gpg, algo? algo : "default");
      if (!err)
        {
          char tmpbuf[5*4+1];
          snprintf (tmpbuf, sizeof tmpbuf, "%s%s%s%s",
                    (flags & GPGME_CREATE_SIGN)? " sign":"",
                    (flags & GPGME_CREATE_ENCR)? " encr":"",
                    (flags & GPGME_CREATE_CERT)? " cert":"",
                    (flags & GPGME_CREATE_AUTH)? " auth":"");
          err = add_arg (gpg, *tmpbuf? tmpbuf : "default");
        }
      if (!err && expires)
        {
          char tmpbuf[8+20];
          snprintf (tmpbuf, sizeof tmpbuf, "seconds=%lu", expires);
          err = add_arg (gpg, tmpbuf);
        }
    }
  else
    err = 0;

  return err;
}


static gpgme_error_t
gpg_createkey_from_param (engine_gpg_t gpg,
                          gpgme_data_t help_data, unsigned int extraflags)
{
  gpgme_error_t err;

  err = add_arg (gpg, "--gen-key");
  if (!err && (extraflags & GENKEY_EXTRAFLAG_ARMOR))
    err = add_arg (gpg, "--armor");
  if (!err)
    err = add_arg (gpg, "--");
  if (!err)
    err = add_data (gpg, help_data, -1, 0);
  if (!err)
    err = start (gpg);
  return err;
}


static gpgme_error_t
gpg_createkey (engine_gpg_t gpg,
               const char *userid, const char *algo,
               unsigned long expires,
               unsigned int flags,
               unsigned int extraflags)
{
  gpgme_error_t err;

  err = add_arg (gpg, "--quick-gen-key");
  if (!err && (extraflags & GENKEY_EXTRAFLAG_ARMOR))
    err = add_arg (gpg, "--armor");
  if (!err && (flags & GPGME_CREATE_NOPASSWD))
    {
      err = add_arg (gpg, "--passphrase");
      if (!err)
        err = add_arg (gpg, "");
    }
  if (!err && (flags & GPGME_CREATE_FORCE))
    err = add_arg (gpg, "--yes");
  if (!err)
    err = add_arg (gpg, "--");
  if (!err)
    err = add_arg (gpg, userid);

  if (!err)
    err = gpg_add_algo_usage_expire (gpg, algo, expires, flags);

  if (!err)
    err = start (gpg);
  return err;
}


static gpgme_error_t
gpg_addkey (engine_gpg_t gpg,
            const char *algo,
            unsigned long expires,
            gpgme_key_t key,
            unsigned int flags,
            unsigned int extraflags)
{
  gpgme_error_t err;

  if (!key || !key->fpr)
    return gpg_error (GPG_ERR_INV_ARG);

  err = add_arg (gpg, "--quick-addkey");
  if (!err && (extraflags & GENKEY_EXTRAFLAG_ARMOR))
    err = add_arg (gpg, "--armor");
  if (!err && (flags & GPGME_CREATE_NOPASSWD))
    {
      err = add_arg (gpg, "--passphrase");
      if (!err)
        err = add_arg (gpg, "");
    }
  if (!err)
    err = add_arg (gpg, "--");
  if (!err)
    err = add_arg (gpg, key->fpr);

  if (!err)
    err = gpg_add_algo_usage_expire (gpg, algo, expires, flags);

  if (!err)
    err = start (gpg);
  return err;
}


static gpgme_error_t
gpg_adduid (engine_gpg_t gpg,
            gpgme_key_t key,
            const char *userid,
            unsigned int extraflags)
{
  gpgme_error_t err;

  if (!key || !key->fpr || !userid)
    return gpg_error (GPG_ERR_INV_ARG);

  if ((extraflags & GENKEY_EXTRAFLAG_REVOKE))
    err = add_arg (gpg, "--quick-revuid");
  else
    err = add_arg (gpg, "--quick-adduid");

  if (!err)
    err = add_arg (gpg, "--");
  if (!err)
    err = add_arg (gpg, key->fpr);
  if (!err)
    err = add_arg (gpg, userid);

  if (!err)
    err = start (gpg);
  return err;
}


static gpgme_error_t
gpg_genkey (void *engine,
            const char *userid, const char *algo,
            unsigned long reserved, unsigned long expires,
            gpgme_key_t key, unsigned int flags,
            gpgme_data_t help_data, unsigned int extraflags,
	    gpgme_data_t pubkey, gpgme_data_t seckey)
{
  engine_gpg_t gpg = engine;
  gpgme_error_t err;

  (void)reserved;

  if (!gpg)
    return gpg_error (GPG_ERR_INV_VALUE);

  /* If HELP_DATA is given the use of the old interface
   * (gpgme_op_genkey) has been requested.  The other modes are:
   *
   *  USERID && !KEY          - Create a new keyblock.
   * !USERID &&  KEY          - Add a new subkey to KEY (gpg >= 2.1.14)
   *  USERID &&  KEY && !ALGO - Add a new user id to KEY (gpg >= 2.1.14).
   *
   */
  if (help_data)
    {
      /* We need a special mechanism to get the fd of a pipe here, so
         that we can use this for the %pubring and %secring
         parameters.  We don't have this yet, so we implement only the
         adding to the standard keyrings.  */
      if (pubkey || seckey)
        err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
      else
        err = gpg_createkey_from_param (gpg, help_data, extraflags);
    }
  else if (!have_gpg_version (gpg, "2.1.13"))
    err = gpg_error (GPG_ERR_NOT_SUPPORTED);
  else if (userid && !key)
    err = gpg_createkey (gpg, userid, algo, expires, flags, extraflags);
  else if (!userid && key)
    err = gpg_addkey (gpg, algo, expires, key, flags, extraflags);
  else if (userid && key && !algo)
    err = gpg_adduid (gpg, key, userid, extraflags);
  else
    err = gpg_error (GPG_ERR_INV_VALUE);

  return err;
}

/* Return the next DELIM delimited string from DATA as a C-string.
   The caller needs to provide the address of a pointer variable which
   he has to set to NULL before the first call.  After the last call
   to this function, this function needs to be called once more with
   DATA set to NULL so that the function can release its internal
   state.  After that the pointer variable is free for use again.
   Note that we use a delimiter and thus a trailing delimiter is not
   required.  DELIM may not be changed after the first call. */
static const char *
string_from_data (gpgme_data_t data, int delim,
                  void **helpptr, gpgme_error_t *r_err)
{
#define MYBUFLEN 2000 /* Fixme: We don't support URLs longer than that.  */
  struct {
    int  eof_seen;
    int  nbytes;      /* Length of the last returned string including
                         the delimiter. */
    int  buflen;      /* Valid length of BUF.  */
    char buf[MYBUFLEN+1];  /* Buffer with one byte extra space.  */
  } *self;
  char *p;
  int nread;

  *r_err = 0;
  if (!data)
    {
      if (*helpptr)
        {
          free (*helpptr);
          *helpptr = NULL;
        }
      return NULL;
    }

  if (*helpptr)
    self = *helpptr;
  else
    {
      self = malloc (sizeof *self);
      if (!self)
        {
          *r_err = gpg_error_from_syserror ();
          return NULL;
        }
      *helpptr = self;
      self->eof_seen = 0;
      self->nbytes = 0;
      self->buflen = 0;
    }

  if (self->eof_seen)
    return NULL;

  assert (self->nbytes <= self->buflen);
  memmove (self->buf, self->buf + self->nbytes, self->buflen - self->nbytes);
  self->buflen -= self->nbytes;
  self->nbytes = 0;

  do
    {
      /* Fixme: This is fairly infective scanning because we may scan
         the buffer several times.  */
      p = memchr (self->buf, delim, self->buflen);
      if (p)
        {
          *p = 0;
          self->nbytes = p - self->buf + 1;
          return self->buf;
        }

      if ( !(MYBUFLEN - self->buflen) )
        {
          /* Not enough space - URL too long.  */
          *r_err = gpg_error (GPG_ERR_TOO_LARGE);
          return NULL;
        }

      nread = gpgme_data_read (data, self->buf + self->buflen,
                               MYBUFLEN - self->buflen);
      if (nread < 0)
        {
          *r_err = gpg_error_from_syserror ();
          return NULL;
        }
      self->buflen += nread;
    }
  while (nread);

  /* EOF reached.  If we have anything in the buffer, append a Nul and
     return it. */
  self->eof_seen = 1;
  if (self->buflen)
    {
      self->buf[self->buflen] = 0;  /* (we allocated one extra byte)  */
      return self->buf;
    }
  return NULL;
#undef MYBUFLEN
}



static gpgme_error_t
gpg_import (void *engine, gpgme_data_t keydata, gpgme_key_t *keyarray)
{
  engine_gpg_t gpg = engine;
  gpgme_error_t err;
  int idx;
  gpgme_data_encoding_t dataenc;

  if (keydata && keyarray)
    return gpg_error (GPG_ERR_INV_VALUE); /* Only one is allowed.  */

  dataenc = gpgme_data_get_encoding (keydata);

  if (keyarray)
    {
      err = add_arg (gpg, "--recv-keys");
      if (!err)
        err = add_arg (gpg, "--");
      for (idx=0; !err && keyarray[idx]; idx++)
        {
          if (keyarray[idx]->protocol != GPGME_PROTOCOL_OpenPGP)
            ;
          else if (!keyarray[idx]->subkeys)
            ;
          else if (keyarray[idx]->subkeys->fpr && *keyarray[idx]->subkeys->fpr)
            err = add_arg (gpg, keyarray[idx]->subkeys->fpr);
          else if (*keyarray[idx]->subkeys->keyid)
            err = add_arg (gpg, keyarray[idx]->subkeys->keyid);
        }
    }
  else if (dataenc == GPGME_DATA_ENCODING_URL
           || dataenc == GPGME_DATA_ENCODING_URL0)
    {
      void *helpptr;
      const char *string;
      gpgme_error_t xerr;
      int delim = (dataenc == GPGME_DATA_ENCODING_URL)? '\n': 0;

      /* FIXME: --fetch-keys is probably not correct because it can't
         grok all kinds of URLs.  On Unix it should just work but on
         Windows we will build the command line and that may fail for
         some embedded control characters.  It is anyway limited to
         the maximum size of the command line.  We need another
         command which can take its input from a file.  Maybe we
         should use an option to gpg to modify such commands (ala
         --multifile).  */
      err = add_arg (gpg, "--fetch-keys");
      if (!err)
        err = add_arg (gpg, "--");
      helpptr = NULL;
      while (!err
             && (string = string_from_data (keydata, delim, &helpptr, &xerr)))
        err = add_arg (gpg, string);
      if (!err)
        err = xerr;
      string_from_data (NULL, delim, &helpptr, &xerr);
    }
  else if (dataenc == GPGME_DATA_ENCODING_URLESC)
    {
      /* Already escaped URLs are not yet supported.  */
      err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
    }
  else
    {
      err = add_arg (gpg, "--import");
      if (!err)
        err = add_arg (gpg, "--");
      if (!err)
        err = add_data (gpg, keydata, -1, 0);
    }

  if (!err)
    err = start (gpg);

  return err;
}


/* The output for external keylistings in GnuPG is different from all
   the other key listings.  We catch this here with a special
   preprocessor that reformats the colon handler lines.  */
static gpgme_error_t
gpg_keylist_preprocess (char *line, char **r_line)
{
  enum
    {
      RT_NONE, RT_INFO, RT_PUB, RT_UID
    }
  rectype = RT_NONE;
#define NR_FIELDS 16
  char *field[NR_FIELDS];
  int fields = 0;
  size_t n;

  *r_line = NULL;

  while (line && fields < NR_FIELDS)
    {
      field[fields++] = line;
      line = strchr (line, ':');
      if (line)
	*(line++) = '\0';
    }

  if (!strcmp (field[0], "info"))
    rectype = RT_INFO;
  else if (!strcmp (field[0], "pub"))
    rectype = RT_PUB;
  else if (!strcmp (field[0], "uid"))
    rectype = RT_UID;
  else
    rectype = RT_NONE;

  switch (rectype)
    {
    case RT_INFO:
      /* FIXME: Eventually, check the version number at least.  */
      return 0;

    case RT_PUB:
      if (fields < 7)
	return 0;

      /* The format is:

	 pub:<keyid>:<algo>:<keylen>:<creationdate>:<expirationdate>:<flags>

	 as defined in 5.2. Machine Readable Indexes of the OpenPGP
	 HTTP Keyserver Protocol (draft).  Modern versions of the SKS
	 keyserver return the fingerprint instead of the keyid.  We
	 detect this here and use the v4 fingerprint format to convert
	 it to a key id.

	 We want:
	 pub:o<flags>:<keylen>:<algo>:<keyid>:<creatdate>:<expdate>::::::::
      */

      n = strlen (field[1]);
      if (n > 16)
        {
          if (asprintf (r_line,
                        "pub:o%s:%s:%s:%s:%s:%s::::::::\n"
                        "fpr:::::::::%s:",
                        field[6], field[3], field[2], field[1] + n - 16,
                        field[4], field[5], field[1]) < 0)
            return gpg_error_from_syserror ();
        }
      else
        {
          if (asprintf (r_line,
                        "pub:o%s:%s:%s:%s:%s:%s::::::::",
                        field[6], field[3], field[2], field[1],
                        field[4], field[5]) < 0)
            return gpg_error_from_syserror ();
        }

      return 0;

    case RT_UID:
      /* The format is:

         uid:<escaped uid string>:<creationdate>:<expirationdate>:<flags>

	 as defined in 5.2. Machine Readable Indexes of the OpenPGP
	 HTTP Keyserver Protocol (draft).

	 We want:
	 uid:o<flags>::::<creatdate>:<expdate>:::<c-coded uid>:
      */

      {
	/* The user ID is percent escaped, but we want c-coded.
	   Because we have to replace each '%HL' by '\xHL', we need at
	   most 4/3 th the number of bytes.  But because we also need
	   to escape the backslashes we allocate twice as much.  */
	char *uid = malloc (2 * strlen (field[1]) + 1);
	char *src;
	char *dst;

	if (! uid)
	  return gpg_error_from_syserror ();
	src = field[1];
	dst = uid;
	while (*src)
	  {
	    if (*src == '%')
	      {
		*(dst++) = '\\';
		*(dst++) = 'x';
		src++;
		/* Copy the next two bytes unconditionally.  */
		if (*src)
		  *(dst++) = *(src++);
		if (*src)
		  *(dst++) = *(src++);
	      }
	    else if (*src == '\\')
              {
                *dst++ = '\\';
                *dst++ = '\\';
                src++;
              }
	    else
	      *(dst++) = *(src++);
	  }
	*dst = '\0';

	if (asprintf (r_line, "uid:o%s::::%s:%s:::%s:",
		      field[4], field[2], field[3], uid) < 0)
	  return gpg_error_from_syserror ();
      }
      return 0;

    case RT_NONE:
      /* Unknown record.  */
      break;
    }
  return 0;

}


static gpg_error_t
gpg_keylist_build_options (engine_gpg_t gpg, int secret_only,
                           gpgme_keylist_mode_t mode)
{
  gpg_error_t err;

  err = add_arg (gpg, "--with-colons");

  /* Since gpg 2.1.15 fingerprints are always printed, thus there is
   * no more need to explictly request them.  */
  if (!have_gpg_version (gpg, "2.1.15"))
    {
      if (!err)
        err = add_arg (gpg, "--fixed-list-mode");
      if (!err)
        err = add_arg (gpg, "--with-fingerprint");
      if (!err)
        err = add_arg (gpg, "--with-fingerprint");
    }

  if (!err && (mode & GPGME_KEYLIST_MODE_WITH_TOFU)
      && have_gpg_version (gpg, "2.1.16"))
    err = add_arg (gpg, "--with-tofu-info");

  if (!err && (mode & GPGME_KEYLIST_MODE_WITH_SECRET))
    err = add_arg (gpg, "--with-secret");

  if (!err
      && (mode & GPGME_KEYLIST_MODE_SIGS)
      && (mode & GPGME_KEYLIST_MODE_SIG_NOTATIONS))
    {
      err = add_arg (gpg, "--list-options");
      if (!err)
	err = add_arg (gpg, "show-sig-subpackets=\"20,26\"");
    }

  if (!err)
    {
      if ( (mode & GPGME_KEYLIST_MODE_EXTERN) )
	{
          if (secret_only)
            err = gpg_error (GPG_ERR_NOT_SUPPORTED);
          else if ( (mode & GPGME_KEYLIST_MODE_LOCAL))
            {
              /* The local+extern mode is special.  It works only with
                 gpg >= 2.0.10.  FIXME: We should check that we have
                 such a version to that we can return a proper error
                 code.  The problem is that we don't know the context
                 here and thus can't access the cached version number
                 for the engine info structure.  */
              err = add_arg (gpg, "--locate-keys");
              if ((mode & GPGME_KEYLIST_MODE_SIGS))
                err = add_arg (gpg, "--with-sig-check");
            }
          else
            {
              err = add_arg (gpg, "--search-keys");
              gpg->colon.preprocess_fnc = gpg_keylist_preprocess;
            }
	}
      else
        {
          err = add_arg (gpg, secret_only ? "--list-secret-keys"
                         : ((mode & GPGME_KEYLIST_MODE_SIGS)
                            ? "--check-sigs" : "--list-keys"));
        }
    }

  if (!err)
    err = add_arg (gpg, "--");

  return err;
}


static gpgme_error_t
gpg_keylist (void *engine, const char *pattern, int secret_only,
	     gpgme_keylist_mode_t mode, int engine_flags)
{
  engine_gpg_t gpg = engine;
  gpgme_error_t err;

  (void)engine_flags;

  err = gpg_keylist_build_options (gpg, secret_only, mode);

  if (!err && pattern && *pattern)
    err = add_arg (gpg, pattern);

  if (!err)
    err = start (gpg);

  return err;
}


static gpgme_error_t
gpg_keylist_ext (void *engine, const char *pattern[], int secret_only,
		 int reserved, gpgme_keylist_mode_t mode, int engine_flags)
{
  engine_gpg_t gpg = engine;
  gpgme_error_t err;

  (void)engine_flags;

  if (reserved)
    return gpg_error (GPG_ERR_INV_VALUE);

  err = gpg_keylist_build_options (gpg, secret_only, mode);

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
gpg_keysign (void *engine, gpgme_key_t key, const char *userid,
             unsigned long expire, unsigned int flags,
             gpgme_ctx_t ctx)
{
  engine_gpg_t gpg = engine;
  gpgme_error_t err;
  const char *s;

  if (!key || !key->fpr)
    return gpg_error (GPG_ERR_INV_ARG);

  if (!have_gpg_version (gpg, "2.1.12"))
    return gpg_error (GPG_ERR_NOT_SUPPORTED);

  if ((flags & GPGME_KEYSIGN_LOCAL))
    err = add_arg (gpg, "--quick-lsign-key");
  else
    err = add_arg (gpg, "--quick-sign-key");

  if (!err)
    err = append_args_from_signers (gpg, ctx);

  /* If an expiration time has been given use that.  If none has been
   * given the default from gpg.conf is used.  To make sure not to set
   * an expiration time at all the flag GPGME_KEYSIGN_NOEXPIRE can be
   * used.  */
  if (!err && (expire || (flags & GPGME_KEYSIGN_NOEXPIRE)))
    {
      char tmpbuf[8+20];

      if ((flags & GPGME_KEYSIGN_NOEXPIRE))
        expire = 0;
      snprintf (tmpbuf, sizeof tmpbuf, "seconds=%lu", expire);
      err = add_arg (gpg, "--default-cert-expire");
      if (!err)
        err = add_arg (gpg, tmpbuf);
    }

  if (!err)
    err = add_arg (gpg, "--");

  if (!err)
    err = add_arg (gpg, key->fpr);
  if (!err && userid)
    {
      if ((flags & GPGME_KEYSIGN_LFSEP))
        {
          for (; !err && (s = strchr (userid, '\n')); userid = s + 1)
            if ((s - userid))
              err = add_arg_len (gpg, "=", userid, s - userid);
          if (!err && *userid)
            err = add_arg_pfx (gpg, "=", userid);
        }
      else
        err = add_arg_pfx (gpg, "=", userid);
    }

  if (!err)
    err = start (gpg);

  return err;
}


static gpgme_error_t
gpg_tofu_policy (void *engine, gpgme_key_t key, gpgme_tofu_policy_t policy)
{
  engine_gpg_t gpg = engine;
  gpgme_error_t err;
  const char *policystr = NULL;

  if (!key || !key->fpr)
    return gpg_error (GPG_ERR_INV_ARG);

  switch (policy)
    {
    case GPGME_TOFU_POLICY_NONE:                           break;
    case GPGME_TOFU_POLICY_AUTO:    policystr = "auto";    break;
    case GPGME_TOFU_POLICY_GOOD:    policystr = "good";    break;
    case GPGME_TOFU_POLICY_BAD:     policystr = "bad";     break;
    case GPGME_TOFU_POLICY_ASK:     policystr = "ask";     break;
    case GPGME_TOFU_POLICY_UNKNOWN: policystr = "unknown"; break;
    }
  if (!policystr)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!have_gpg_version (gpg, "2.1.10"))
    return gpg_error (GPG_ERR_NOT_SUPPORTED);

  err = add_arg (gpg, "--tofu-policy");
  if (!err)
    err = add_arg (gpg, "--");
  if (!err)
    err = add_arg (gpg, policystr);
  if (!err)
    err = add_arg (gpg, key->fpr);

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

  (void)include_certs;

  if (mode == GPGME_SIG_MODE_CLEAR)
    err = add_arg (gpg, "--clearsign");
  else
    {
      err = add_arg (gpg, "--sign");
      if (!err && mode == GPGME_SIG_MODE_DETACH)
	err = add_arg (gpg, "--detach");
      if (!err && use_armor)
	err = add_arg (gpg, "--armor");
      if (!err)
        {
          if (gpgme_data_get_encoding (in) == GPGME_DATA_ENCODING_MIME
              && have_gpg_version (gpg, "2.1.14"))
            err = add_arg (gpg, "--mimemode");
          else if (use_textmode)
            err = add_arg (gpg, "--textmode");
        }
    }

  if (!err)
    err = append_args_from_signers (gpg, ctx);
  if (!err)
    err = append_args_from_sig_notations (gpg, ctx);

  if (gpgme_data_get_file_name (in))
    {
      if (!err)
	err = add_arg (gpg, "--set-filename");
      if (!err)
	err = add_arg (gpg, gpgme_data_get_file_name (in));
    }

  /* Tell the gpg object about the data.  */
  if (!err)
    err = add_input_size_hint (gpg, in);
  if (!err)
    err = add_arg (gpg, "--");
  if (!err)
    err = add_data (gpg, in, -1, 0);
  if (!err)
    err = add_data (gpg, out, 1, 1);

  if (!err)
    err = start (gpg);

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
        err = add_input_size_hint (gpg, sig);
      if (!err)
	err = add_arg (gpg, "--");
      if (!err)
	err = add_data (gpg, sig, -1, 0);
      if (!err)
	err = add_data (gpg, plaintext, 1, 1);
    }
  else
    {
      err = add_arg (gpg, "--verify");
      if (!err)
        err = add_input_size_hint (gpg, signed_text);
      if (!err)
	err = add_arg (gpg, "--");
      if (!err)
	err = add_data (gpg, sig, -1, 0);
      if (!err && signed_text)
	err = add_data (gpg, signed_text, -1, 0);
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


static gpgme_error_t
gpg_set_pinentry_mode (void *engine, gpgme_pinentry_mode_t mode)
{
  engine_gpg_t gpg = engine;

  gpg->pinentry_mode = mode;
  return 0;
}



struct engine_ops _gpgme_engine_ops_gpg =
  {
    /* Static functions.  */
    _gpgme_get_default_gpg_name,
    NULL,
    gpg_get_version,
    gpg_get_req_version,
    gpg_new,

    /* Member functions.  */
    gpg_release,
    NULL,				/* reset */
    gpg_set_status_cb,
    gpg_set_status_handler,
    gpg_set_command_handler,
    gpg_set_colon_line_handler,
    gpg_set_locale,
    NULL,				/* set_protocol */
    gpg_decrypt,
    gpg_decrypt,			/* decrypt_verify */
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
    gpg_keysign,
    gpg_tofu_policy,    /* tofu_policy */
    gpg_sign,
    gpg_trustlist,
    gpg_verify,
    NULL,		/* getauditlog */
    NULL,               /* opassuan_transact */
    NULL,		/* conf_load */
    NULL,		/* conf_save */
    gpg_set_io_cbs,
    gpg_io_event,
    gpg_cancel,
    NULL,		/* cancel_op */
    gpg_passwd,
    gpg_set_pinentry_mode,
    NULL                /* opspawn */
  };
