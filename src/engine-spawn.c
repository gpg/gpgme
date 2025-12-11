/* engine-spawn.c - Run an arbitrary program
 * Copyright (C) 2014 g10 Code GmbH
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

#include "engine-backend.h"


/* This type is used to build a list of data sources/sinks.  */
struct datalist_s
{
  struct datalist_s *next;
  gpgme_data_t data;  /* The data object. */
  int inbound;        /* True if this is used for reading from the peer.  */
  int dup_to;         /* The fd used by the peer.  */
};


struct fd_data_map_s
{
  gpgme_data_t data;
  int inbound;  /* True if this is used for reading from the peer. */
  int dup_to;   /* Dup the fd to that one.  */
  int fd;       /* The fd to use.  */
  int peer_fd;  /* The other side of the pipe. */
  void *tag;    /* Tag used by the I/O callback.  */
};


struct engine_spawn
{
  struct datalist_s *arglist;
  struct datalist_s **argtail;

  struct fd_data_map_s *fd_data_map;

  struct gpgme_io_cbs io_cbs;
};
typedef struct engine_spawn *engine_spawn_t;


static void engspawn_io_event (void *engine,
                               gpgme_event_io_t type, void *type_data);
static gpgme_error_t engspawn_cancel (void *engine);



static void
close_notify_handler (int fd, void *opaque)
{
  engine_spawn_t esp = opaque;
  int i;

  assert (fd != -1);

  if (esp->fd_data_map)
    {
      for (i = 0; esp->fd_data_map[i].data; i++)
	{
	  if (esp->fd_data_map[i].fd == fd)
	    {
	      if (esp->fd_data_map[i].tag)
		(*esp->io_cbs.remove) (esp->fd_data_map[i].tag);
	      esp->fd_data_map[i].fd = -1;
	      break;
            }
	  if (esp->fd_data_map[i].peer_fd == fd)
	    {
	      esp->fd_data_map[i].peer_fd = -1;
	      break;
            }
        }
    }
}


static gpgme_error_t
add_data (engine_spawn_t esp, gpgme_data_t data, int dup_to, int inbound)
{
  struct datalist_s *a;

  assert (esp);
  assert (data);

  a = malloc (sizeof *a);
  if (!a)
    return gpg_error_from_syserror ();
  a->next = NULL;
  a->data = data;
  a->inbound = inbound;
  a->dup_to = dup_to;
  *esp->argtail = a;
  esp->argtail = &a->next;
  return 0;
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
build_fd_data_map (engine_spawn_t esp)
{
  struct datalist_s *a;
  size_t datac;
  int fds[2];

  for (datac = 0, a = esp->arglist; a; a = a->next)
    if (a->data)
      datac++;

  free_fd_data_map (esp->fd_data_map);
  esp->fd_data_map = calloc (datac + 1, sizeof *esp->fd_data_map);
  if (!esp->fd_data_map)
    return gpg_error_from_syserror ();

  for (datac = 0, a = esp->arglist; a; a = a->next)
    {
      assert (a->data);

      if (_gpgme_io_pipe (fds, a->inbound ? 1 : 0) == -1)
        {
          free (esp->fd_data_map);
          esp->fd_data_map = NULL;
          return gpg_error_from_syserror ();
        }
      if (_gpgme_io_set_close_notify (fds[0], close_notify_handler, esp)
          || _gpgme_io_set_close_notify (fds[1], close_notify_handler, esp))
        {
          /* FIXME: Need error cleanup.  */
          return gpg_error (GPG_ERR_GENERAL);
        }

      esp->fd_data_map[datac].inbound = a->inbound;
      if (a->inbound)
        {
          esp->fd_data_map[datac].fd       = fds[0];
          esp->fd_data_map[datac].peer_fd  = fds[1];
        }
      else
        {
          esp->fd_data_map[datac].fd       = fds[1];
          esp->fd_data_map[datac].peer_fd  = fds[0];
        }
      esp->fd_data_map[datac].data    = a->data;
      esp->fd_data_map[datac].dup_to  = a->dup_to;
      datac++;
    }

  return 0;
}


static gpgme_error_t
add_io_cb (engine_spawn_t esp, int fd, int dir, gpgme_io_cb_t handler,
           void *data, void **tag)
{
  gpgme_error_t err;

  err = (*esp->io_cbs.add) (esp->io_cbs.add_priv, fd, dir, handler, data, tag);
  if (err)
    return err;
  if (!dir) /* Fixme: Kludge around poll() problem.  */
    err = _gpgme_io_set_nonblocking (fd);
  return err;
}


static gpgme_error_t
engspawn_start (engine_spawn_t esp, const char *file, const char *argv[],
                unsigned int flags)
{
  gpgme_error_t err;
  int i, n;
  int status;
  struct spawn_fd_item_s *fd_list;
  unsigned int spflags;
  const char *save_argv0 = NULL;

  if (!esp || !file || !argv || !argv[0])
    return gpg_error (GPG_ERR_INV_VALUE);

  spflags = 0;
  if ((flags & GPGME_SPAWN_DETACHED))
    spflags |= IOSPAWN_FLAG_DETACHED;
  if ((flags & GPGME_SPAWN_ALLOW_SET_FG))
    spflags |= IOSPAWN_FLAG_ALLOW_SET_FG;
  if ((flags & GPGME_SPAWN_SHOW_WINDOW))
    spflags |= IOSPAWN_FLAG_SHOW_WINDOW;

  err = build_fd_data_map (esp);
  if (err)
    return err;

  n = 0;
  for (i = 0; esp->fd_data_map[i].data; i++)
    n++;
  fd_list = calloc (n+1, sizeof *fd_list);
  if (!fd_list)
    return gpg_error_from_syserror ();

  /* Build the fd list for the child.  */
  n = 0;
  for (i = 0; esp->fd_data_map[i].data; i++)
    {
      fd_list[n].fd = esp->fd_data_map[i].peer_fd;
      fd_list[n].dup_to = esp->fd_data_map[i].dup_to;
      n++;
    }
  fd_list[n].fd = -1;
  fd_list[n].dup_to = -1;

  if (argv[0] && !*argv[0])
    {
      save_argv0 = argv[0];
      argv[0] = _gpgme_get_basename (file);
    }
  status = _gpgme_io_spawn (file, (char * const *)argv, spflags,
                            fd_list, NULL, NULL, NULL);
  if (save_argv0)
    argv[0] = save_argv0;
  free (fd_list);
  if (status == -1)
    return gpg_error_from_syserror ();

  for (i = 0; esp->fd_data_map[i].data; i++)
    {
      err = add_io_cb (esp, esp->fd_data_map[i].fd,
                       esp->fd_data_map[i].inbound,
                       esp->fd_data_map[i].inbound
                       ? _gpgme_data_inbound_handler
                       : _gpgme_data_outbound_handler,
                       esp->fd_data_map[i].data, &esp->fd_data_map[i].tag);
      if (err)
        return err;  /* FIXME: kill the child */
    }

  engspawn_io_event (esp, GPGME_EVENT_START, NULL);

  return 0;
}



/*
    Public functions
 */

static const char *
engspawn_get_file_name (void)
{
  return "/nonexistent";
}


static char *
engspawn_get_version (const char *file_name)
{
  (void)file_name;
  return NULL;
}


static const char *
engspawn_get_req_version (void)
{
  return NULL;
}


static gpgme_error_t
engspawn_new (void **engine, const char *file_name, const char *home_dir,
              const char *version)
{
  engine_spawn_t esp;

  (void)file_name;
  (void)home_dir;
  (void)version;

  esp = calloc (1, sizeof *esp);
  if (!esp)
    return gpg_error_from_syserror ();

  esp->argtail = &esp->arglist;
  *engine = esp;
  return 0;
}


static void
engspawn_release (void *engine)
{
  engine_spawn_t esp = engine;

  if (!esp)
    return;

  engspawn_cancel (engine);

  while (esp->arglist)
    {
      struct datalist_s *next = esp->arglist->next;

      free (esp->arglist);
      esp->arglist = next;
    }

  free (esp);
}


static void
engspawn_set_io_cbs (void *engine, gpgme_io_cbs_t io_cbs)
{
  engine_spawn_t esp = engine;

  esp->io_cbs = *io_cbs;
}


static void
engspawn_io_event (void *engine, gpgme_event_io_t type, void *type_data)
{
  engine_spawn_t esp = engine;

  TRACE (DEBUG_ENGINE, "gpgme:engspawn_io_event", esp,
          "event %p, type %d, type_data %p",
          esp->io_cbs.event, type, type_data);
  if (esp->io_cbs.event)
    (*esp->io_cbs.event) (esp->io_cbs.event_priv, type, type_data);
}


static gpgme_error_t
engspawn_cancel (void *engine)
{
  engine_spawn_t esp = engine;

  if (!esp)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (esp->fd_data_map)
    {
      free_fd_data_map (esp->fd_data_map);
      esp->fd_data_map = NULL;
    }

  return 0;
}


static gpgme_error_t
engspawn_op_spawn (void *engine,
                   const char *file, const char *argv[],
                   gpgme_data_t datain,
                   gpgme_data_t dataout, gpgme_data_t dataerr,
                   unsigned int flags)
{
  engine_spawn_t esp = engine;
  gpgme_error_t err = 0;

  if (datain)
    err = add_data (esp, datain, 0, 0);
  if (!err && dataout)
    err = add_data (esp, dataout, 1, 1);
  if (!err && dataerr)
    err = add_data (esp, dataerr, 2, 1);

  if (!err)
    err = engspawn_start (esp, file, argv, flags);

  return err;
}



struct engine_ops _gpgme_engine_ops_spawn =
  {
    /* Static functions.  */
    engspawn_get_file_name,
    NULL,               /* get_home_dir */
    engspawn_get_version,
    engspawn_get_req_version,
    engspawn_new,

    /* Member functions.  */
    engspawn_release,
    NULL,		/* reset */
    NULL,               /* set_status_cb */
    NULL,		/* set_status_handler */
    NULL,		/* set_command_handler */
    NULL,		/* set_colon_line_handler */
    NULL,		/* set_locale */
    NULL,		/* set_protocol */
    NULL,               /* set_engine_flags */
    NULL,		/* decrypt */
    NULL,		/* delete */
    NULL,		/* edit */
    NULL,		/* encrypt */
    NULL,		/* encrypt_sign */
    NULL,		/* export */
    NULL,		/* export_ext */
    NULL,		/* genkey */
    NULL,		/* import */
    NULL,		/* keylist */
    NULL,		/* keylist_ext */
    NULL,               /* keylist_data */
    NULL,               /* keysign */
    NULL,               /* revsig */
    NULL,               /* tofu_policy */
    NULL,		/* sign */
    NULL,		/* verify */
    NULL,		/* getauditlog */
    NULL,               /* setexpire */
    NULL,               /* setownertrust */
    NULL,               /* opassuan_transact */
    NULL,               /* getdirect */
    NULL,		/* conf_load */
    NULL,		/* conf_save */
    NULL,		/* conf_dir */
    NULL,               /* query_swdb */
    engspawn_set_io_cbs,
    engspawn_io_event,	/* io_event */
    engspawn_cancel,	/* cancel */
    NULL,               /* cancel_op */
    NULL,               /* passwd */
    NULL,               /* set_pinentry_mode */
    engspawn_op_spawn   /* opspawn */
  };
