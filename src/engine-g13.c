/* engine-g13.c - G13 engine.
 * Copyright (C) 2000 Werner Koch (dd9jn)
 * Copyright (C) 2001, 2002, 2003, 2004, 2005, 2007, 2009 g10 Code GmbH
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

#include <stdlib.h>
#include <string.h>
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#include <assert.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif
#include <fcntl.h> /* FIXME */
#include <errno.h>

#include "gpgme.h"
#include "util.h"
#include "ops.h"
#include "wait.h"
#include "priv-io.h"
#include "sema.h"

#include "assuan.h"
#include "debug.h"

#include "engine-backend.h"


typedef struct
{
  int fd;	/* FD we talk about.  */
  int server_fd;/* Server FD for this connection.  */
  int dir;	/* Inbound/Outbound, maybe given implicit?  */
  void *data;	/* Handler-specific data.  */
  void *tag;	/* ID from the user for gpgme_remove_io_callback.  */
  char server_fd_str[15]; /* Same as SERVER_FD but as a string.  We
                             need this because _gpgme_io_fd2str can't
                             be used on a closed descriptor.  */
} iocb_data_t;


struct engine_g13
{
  assuan_context_t assuan_ctx;

  int lc_ctype_set;
  int lc_messages_set;

  iocb_data_t status_cb;

  struct gpgme_io_cbs io_cbs;

  /* User provided callbacks.  */
  struct {
    gpgme_assuan_data_cb_t data_cb;
    void *data_cb_value;

    gpgme_assuan_inquire_cb_t inq_cb;
    void *inq_cb_value;

    gpgme_assuan_status_cb_t status_cb;
    void *status_cb_value;
  } user;
};

typedef struct engine_g13 *engine_g13_t;


static void g13_io_event (void *engine,
                            gpgme_event_io_t type, void *type_data);



static char *
g13_get_version (const char *file_name)
{
  return _gpgme_get_program_version (file_name ? file_name
				     : _gpgme_get_default_g13_name ());
}


static const char *
g13_get_req_version (void)
{
  return "2.1.0";
}


static void
close_notify_handler (int fd, void *opaque)
{
  engine_g13_t g13 = opaque;

  assert (fd != -1);
  if (g13->status_cb.fd == fd)
    {
      if (g13->status_cb.tag)
	(*g13->io_cbs.remove) (g13->status_cb.tag);
      g13->status_cb.fd = -1;
      g13->status_cb.tag = NULL;
    }
}


/* This is the default inquiry callback.  We use it to handle the
   Pinentry notifications.  */
static gpgme_error_t
default_inq_cb (engine_g13_t g13, const char *keyword, const char *args)
{
  gpg_error_t err;

  if (!strcmp (keyword, "PINENTRY_LAUNCHED"))
    {
      _gpgme_allow_set_foreground_window ((pid_t)strtoul (args, NULL, 10));
    }

  if (g13->user.inq_cb)
    {
      gpgme_data_t data = NULL;

      err = g13->user.inq_cb (g13->user.inq_cb_value,
                                keyword, args, &data);
      if (!err && data)
        {
          /* FIXME: Returning data is not yet implemented.  However we
             need to allow the caller to cleanup his data object.
             Thus we run the callback in finish mode immediately.  */
          err = g13->user.inq_cb (g13->user.inq_cb_value,
				  NULL, NULL, &data);
        }
    }
  else
    err = 0;

  return err;
}


static gpgme_error_t
g13_cancel (void *engine)
{
  engine_g13_t g13 = engine;

  if (!g13)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (g13->status_cb.fd != -1)
    _gpgme_io_close (g13->status_cb.fd);

  if (g13->assuan_ctx)
    {
      assuan_release (g13->assuan_ctx);
      g13->assuan_ctx = NULL;
    }

  return 0;
}


static gpgme_error_t
g13_cancel_op (void *engine)
{
  engine_g13_t g13 = engine;

  if (!g13)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (g13->status_cb.fd != -1)
    _gpgme_io_close (g13->status_cb.fd);

  return 0;
}


static void
g13_release (void *engine)
{
  engine_g13_t g13 = engine;

  if (!g13)
    return;

  g13_cancel (engine);

  free (g13);
}


static gpgme_error_t
g13_new (void **engine, const char *file_name, const char *home_dir,
         const char *version)
{
  gpgme_error_t err = 0;
  engine_g13_t g13;
  const char *pgmname;
  int argc;
  const char *argv[5];
  char *dft_display = NULL;
  char dft_ttyname[64];
  char *env_tty = NULL;
  char *dft_ttytype = NULL;
  char *optstr;

  (void)version; /* Not yet used.  */

  g13 = calloc (1, sizeof *g13);
  if (!g13)
    return gpg_error_from_syserror ();

  g13->status_cb.fd = -1;
  g13->status_cb.dir = 1;
  g13->status_cb.tag = 0;
  g13->status_cb.data = g13;

  pgmname = file_name ? file_name : _gpgme_get_default_g13_name ();
  argc = 0;
  argv[argc++] = _gpgme_get_basename (pgmname);
  if (home_dir)
    {
      argv[argc++] = "--homedir";
      argv[argc++] = home_dir;
    }
  argv[argc++] = "--server";
  argv[argc++] = NULL;

  err = assuan_new_ext (&g13->assuan_ctx, GPG_ERR_SOURCE_GPGME,
			&_gpgme_assuan_malloc_hooks, _gpgme_assuan_log_cb,
			NULL);
  if (err)
    goto leave;
  assuan_ctx_set_system_hooks (g13->assuan_ctx, &_gpgme_assuan_system_hooks);

#if USE_DESCRIPTOR_PASSING
  err = assuan_pipe_connect (g13->assuan_ctx, pgmname, argv,
                             NULL, NULL, NULL, ASSUAN_PIPE_CONNECT_FDPASSING);
#else
  err = assuan_pipe_connect (g13->assuan_ctx, pgmname, argv,
                             NULL, NULL, NULL, 0);
#endif
  if (err)
    goto leave;

  err = _gpgme_getenv ("DISPLAY", &dft_display);
  if (err)
    goto leave;
  if (dft_display)
    {
      if (gpgrt_asprintf (&optstr, "OPTION display=%s", dft_display) < 0)
        {
	  free (dft_display);
	  err = gpg_error_from_syserror ();
	  goto leave;
	}
      free (dft_display);

      err = assuan_transact (g13->assuan_ctx, optstr, NULL, NULL, NULL,
			     NULL, NULL, NULL);
      gpgrt_free (optstr);
      if (err)
	goto leave;
    }

  err = _gpgme_getenv ("GPG_TTY", &env_tty);
  if (isatty (1) || env_tty || err)
    {
      int rc = 0;

      if (err)
        goto leave;
      else if (env_tty)
        {
          snprintf (dft_ttyname, sizeof (dft_ttyname), "%s", env_tty);
          free (env_tty);
        }
      else
        rc = ttyname_r (1, dft_ttyname, sizeof (dft_ttyname));

      /* Even though isatty() returns 1, ttyname_r() may fail in many
	 ways, e.g., when /dev/pts is not accessible under chroot.  */
      if (!rc)
	{
	  if (gpgrt_asprintf (&optstr, "OPTION ttyname=%s", dft_ttyname) < 0)
	    {
	      err = gpg_error_from_syserror ();
	      goto leave;
	    }
	  err = assuan_transact (g13->assuan_ctx, optstr, NULL, NULL, NULL,
				 NULL, NULL, NULL);
	  gpgrt_free (optstr);
	  if (err)
	    goto leave;

	  err = _gpgme_getenv ("TERM", &dft_ttytype);
	  if (err)
	    goto leave;
	  if (dft_ttytype)
	    {
	      if (gpgrt_asprintf (&optstr, "OPTION ttytype=%s", dft_ttytype)< 0)
		{
		  free (dft_ttytype);
		  err = gpg_error_from_syserror ();
		  goto leave;
		}
	      free (dft_ttytype);

	      err = assuan_transact (g13->assuan_ctx, optstr, NULL, NULL,
				     NULL, NULL, NULL, NULL);
	      gpgrt_free (optstr);
	      if (err)
		goto leave;
	    }
	}
    }

#ifdef HAVE_W32_SYSTEM
  /* Under Windows we need to use AllowSetForegroundWindow.  Tell
     g13 to tell us when it needs it.  */
  if (!err)
    {
      err = assuan_transact (g13->assuan_ctx, "OPTION allow-pinentry-notify",
                             NULL, NULL, NULL, NULL, NULL, NULL);
      if (gpg_err_code (err) == GPG_ERR_UNKNOWN_OPTION)
        err = 0; /* This is a new feature of g13.  */
    }
#endif /*HAVE_W32_SYSTEM*/

 leave:

  if (err)
    g13_release (g13);
  else
    *engine = g13;

  return err;
}


static gpgme_error_t
g13_set_locale (void *engine, int category, const char *value)
{
  engine_g13_t g13 = engine;
  gpgme_error_t err;
  char *optstr;
  const char *catstr;

  /* FIXME: If value is NULL, we need to reset the option to default.
     But we can't do this.  So we error out here.  G13 needs support
     for this.  */
  if (0)
    ;
#ifdef LC_CTYPE
  else if (category == LC_CTYPE)
    {
      catstr = "lc-ctype";
      if (!value && g13->lc_ctype_set)
	return gpg_error (GPG_ERR_INV_VALUE);
      if (value)
	g13->lc_ctype_set = 1;
    }
#endif
#ifdef LC_MESSAGES
  else if (category == LC_MESSAGES)
    {
      catstr = "lc-messages";
      if (!value && g13->lc_messages_set)
	return gpg_error (GPG_ERR_INV_VALUE);
      if (value)
	g13->lc_messages_set = 1;
    }
#endif /* LC_MESSAGES */
  else
    return gpg_error (GPG_ERR_INV_VALUE);

  /* FIXME: Reset value to default.  */
  if (!value)
    return 0;

  if (gpgrt_asprintf (&optstr, "OPTION %s=%s", catstr, value) < 0)
    err = gpg_error_from_syserror ();
  else
    {
      err = assuan_transact (g13->assuan_ctx, optstr, NULL, NULL,
			     NULL, NULL, NULL, NULL);
      gpgrt_free (optstr);
    }

  return err;
}


#if USE_DESCRIPTOR_PASSING
static gpgme_error_t
g13_assuan_simple_command (assuan_context_t ctx, const char *cmd,
			   engine_status_handler_t status_fnc,
			   void *status_fnc_value)
{
  gpg_error_t err;
  char *line;
  size_t linelen;

  (void)status_fnc;
  (void)status_fnc_value;

  err = assuan_write_line (ctx, cmd);
  if (err)
    return err;

  do
    {
      err = assuan_read_line (ctx, &line, &linelen);
      if (err)
	return err;

      if (*line == '#' || !linelen)
	continue;

      if (linelen >= 2
	  && line[0] == 'O' && line[1] == 'K'
	  && (line[2] == '\0' || line[2] == ' '))
	return 0;
      else if (linelen >= 4
	  && line[0] == 'E' && line[1] == 'R' && line[2] == 'R'
	  && line[3] == ' ')
	err = atoi (&line[4]);
      else if (linelen >= 2
	       && line[0] == 'S' && line[1] == ' ')
	{
	  char *rest;

	  rest = strchr (line + 2, ' ');
	  if (!rest)
	    rest = line + linelen; /* set to an empty string */
	  else
	    *(rest++) = 0;

	  /* Nothing to do with status lines.  */
	}
      else
	err = gpg_error (GPG_ERR_GENERAL);
    }
  while (!err);

  return err;
}
#endif


static gpgme_error_t
status_handler (void *opaque, int fd)
{
  struct io_cb_data *data = (struct io_cb_data *) opaque;
  engine_g13_t g13 = (engine_g13_t) data->handler_value;
  gpgme_error_t err = 0;
  char *line;
  size_t linelen;

  do
    {
      err = assuan_read_line (g13->assuan_ctx, &line, &linelen);
      if (err)
	{
	  /* Try our best to terminate the connection friendly.  */
	  /*	  assuan_write_line (g13->assuan_ctx, "BYE"); */
          TRACE (DEBUG_CTX, "gpgme:status_handler", g13,
		  "fd 0x%x: error reading assuan line: %s",
                  fd, gpg_strerror (err));
	}
      else if (linelen >= 3
	       && line[0] == 'E' && line[1] == 'R' && line[2] == 'R'
	       && (line[3] == '\0' || line[3] == ' '))
	{
	  if (line[3] == ' ')
	    err = atoi (&line[4]);
	  if (! err)
	    err = gpg_error (GPG_ERR_GENERAL);
          TRACE (DEBUG_CTX, "gpgme:status_handler", g13,
		  "fd 0x%x: ERR line: %s",
                  fd, err ? gpg_strerror (err) : "ok");

	  /* Command execution errors are not fatal, as we use
	     a session based protocol.  */
	  data->op_err = err;

	  /* The caller will do the rest (namely, call cancel_op,
	     which closes status_fd).  */
	  return 0;
	}
      else if (linelen >= 2
	       && line[0] == 'O' && line[1] == 'K'
	       && (line[2] == '\0' || line[2] == ' '))
	{
          TRACE (DEBUG_CTX, "gpgme:status_handler", g13,
		  "fd 0x%x: OK line", fd);

	  _gpgme_io_close (g13->status_cb.fd);
	  return 0;
	}
      else if (linelen > 2
	       && line[0] == 'D' && line[1] == ' ')
        {
	  /* We are using the colon handler even for plain inline data
             - strange name for that function but for historic reasons
             we keep it.  */
          /* FIXME We can't use this for binary data because we
             assume this is a string.  For the current usage of colon
             output it is correct.  */
          char *src = line + 2;
	  char *end = line + linelen;
	  char *dst = src;

          linelen = 0;
          while (src < end)
            {
              if (*src == '%' && src + 2 < end)
                {
                  /* Handle escaped characters.  */
                  ++src;
                  *dst++ = _gpgme_hextobyte (src);
                  src += 2;
                }
              else
                *dst++ = *src++;

              linelen++;
            }

          src = line + 2;
          if (linelen && g13->user.data_cb)
            err = g13->user.data_cb (g13->user.data_cb_value,
                                       src, linelen);
          else
            err = 0;

          TRACE (DEBUG_CTX, "gpgme:g13_status_handler", g13,
		  "fd 0x%x: D inlinedata; status from cb: %s",
                  fd, (g13->user.data_cb ?
                       (err? gpg_strerror (err):"ok"):"no callback"));

        }
      else if (linelen > 2
	       && line[0] == 'S' && line[1] == ' ')
	{
	  char *src;
	  char *args;

	  src = line + 2;
          while (*src == ' ')
            src++;

	  args = strchr (line + 2, ' ');
	  if (!args)
	    args = line + linelen; /* set to an empty string */
	  else
	    *(args++) = 0;

          while (*args == ' ')
            args++;

          if (g13->user.status_cb)
            err = g13->user.status_cb (g13->user.status_cb_value,
				       src, args);
          else
            err = 0;

          TRACE (DEBUG_CTX, "gpgme:g13_status_handler", g13,
		  "fd 0x%x: S line (%s) - status from cb: %s",
                  fd, line+2, (g13->user.status_cb ?
                               (err? gpg_strerror (err):"ok"):"no callback"));
	}
      else if (linelen >= 7
               && line[0] == 'I' && line[1] == 'N' && line[2] == 'Q'
               && line[3] == 'U' && line[4] == 'I' && line[5] == 'R'
               && line[6] == 'E'
               && (line[7] == '\0' || line[7] == ' '))
        {
          char *src;
	  char *args;

          for (src=line+7; *src == ' '; src++)
            ;

	  args = strchr (src, ' ');
	  if (!args)
	    args = line + linelen; /* Let it point to an empty string.  */
	  else
	    *(args++) = 0;

          while (*args == ' ')
            args++;

          err = default_inq_cb (g13, src, args);
          if (!err)
            {
              /* Flush and send END.  */
              err = assuan_send_data (g13->assuan_ctx, NULL, 0);
            }
          else if (gpg_err_code (err) == GPG_ERR_ASS_CANCELED)
            {
              /* Flush and send CANcel.  */
              err = assuan_send_data (g13->assuan_ctx, NULL, 1);
            }
          assuan_write_line (g13->assuan_ctx, "END");
        }
    }
  while (!err && assuan_pending_line (g13->assuan_ctx));

  return err;
}


static gpgme_error_t
add_io_cb (engine_g13_t g13, iocb_data_t *iocbd, gpgme_io_cb_t handler)
{
  gpgme_error_t err;

  TRACE_BEG  (DEBUG_ENGINE, "engine-g13:add_io_cb", g13,
              "fd=%d, dir %d", iocbd->fd, iocbd->dir);
  err = (*g13->io_cbs.add) (g13->io_cbs.add_priv,
			      iocbd->fd, iocbd->dir,
			      handler, iocbd->data, &iocbd->tag);
  if (err)
    return TRACE_ERR (err);
  if (!iocbd->dir)
    /* FIXME Kludge around poll() problem.  */
    err = _gpgme_io_set_nonblocking (iocbd->fd);
  return TRACE_ERR (err);
}


static gpgme_error_t
start (engine_g13_t g13, const char *command)
{
  gpgme_error_t err;
  assuan_fd_t afdlist[5];
  int fdlist[5];
  int nfds;
  int i;

  /* We need to know the fd used by assuan for reads.  We do this by
     using the assumption that the first returned fd from
     assuan_get_active_fds() is always this one.  */
  nfds = assuan_get_active_fds (g13->assuan_ctx, 0 /* read fds */,
                                afdlist, DIM (afdlist));
  if (nfds < 1)
    return gpg_error (GPG_ERR_GENERAL);	/* FIXME */
  /* For now... */
  for (i = 0; i < nfds; i++)
    fdlist[i] = (int) afdlist[i];

  /* We "duplicate" the file descriptor, so we can close it here (we
     can't close fdlist[0], as that is closed by libassuan, and
     closing it here might cause libassuan to close some unrelated FD
     later).  Alternatively, we could special case status_fd and
     register/unregister it manually as needed, but this increases
     code duplication and is more complicated as we can not use the
     close notifications etc.  A third alternative would be to let
     Assuan know that we closed the FD, but that complicates the
     Assuan interface.  */

  g13->status_cb.fd = _gpgme_io_dup (fdlist[0]);
  if (g13->status_cb.fd < 0)
    return gpg_error_from_syserror ();

  if (_gpgme_io_set_close_notify (g13->status_cb.fd,
				  close_notify_handler, g13))
    {
      _gpgme_io_close (g13->status_cb.fd);
      g13->status_cb.fd = -1;
      return gpg_error (GPG_ERR_GENERAL);
    }

  err = add_io_cb (g13, &g13->status_cb, status_handler);
  if (!err)
    err = assuan_write_line (g13->assuan_ctx, command);

  if (!err)
    g13_io_event (g13, GPGME_EVENT_START, NULL);

  return err;
}


#if USE_DESCRIPTOR_PASSING
static gpgme_error_t
g13_reset (void *engine)
{
  engine_g13_t g13 = engine;

  /* We must send a reset because we need to reset the list of
     signers.  Note that RESET does not reset OPTION commands. */
  return g13_assuan_simple_command (g13->assuan_ctx, "RESET", NULL, NULL);
}
#endif


static gpgme_error_t
g13_transact (void *engine,
                const char *command,
                gpgme_assuan_data_cb_t data_cb,
                void *data_cb_value,
                gpgme_assuan_inquire_cb_t inq_cb,
                void *inq_cb_value,
                gpgme_assuan_status_cb_t status_cb,
                void *status_cb_value)
{
  engine_g13_t g13 = engine;
  gpgme_error_t err;

  if (!g13 || !command || !*command)
    return gpg_error (GPG_ERR_INV_VALUE);

  g13->user.data_cb = data_cb;
  g13->user.data_cb_value = data_cb_value;
  g13->user.inq_cb = inq_cb;
  g13->user.inq_cb_value = inq_cb_value;
  g13->user.status_cb = status_cb;
  g13->user.status_cb_value = status_cb_value;

  err = start (g13, command);
  return err;
}



static void
g13_set_io_cbs (void *engine, gpgme_io_cbs_t io_cbs)
{
  engine_g13_t g13 = engine;
  g13->io_cbs = *io_cbs;
}


static void
g13_io_event (void *engine, gpgme_event_io_t type, void *type_data)
{
  engine_g13_t g13 = engine;

  TRACE (DEBUG_ENGINE, "gpgme:g13_io_event", g13,
          "event %p, type %d, type_data %p",
          g13->io_cbs.event, type, type_data);
  if (g13->io_cbs.event)
    (*g13->io_cbs.event) (g13->io_cbs.event_priv, type, type_data);
}


struct engine_ops _gpgme_engine_ops_g13 =
  {
    /* Static functions.  */
    _gpgme_get_default_g13_name,
    NULL,
    g13_get_version,
    g13_get_req_version,
    g13_new,

    /* Member functions.  */
    g13_release,
#if USE_DESCRIPTOR_PASSING
    g13_reset,
#else
    NULL,			/* reset */
#endif
    NULL,               /* set_status_cb */
    NULL,               /* set_status_handler */
    NULL,		/* set_command_handler */
    NULL,               /* set_colon_line_handler */
    g13_set_locale,
    NULL,		/* set_protocol */
    NULL,               /* set_engine_flags */
    NULL,               /* decrypt */
    NULL,               /* delete */
    NULL,		/* edit */
    NULL,               /* encrypt */
    NULL,		/* encrypt_sign */
    NULL,               /* export */
    NULL,               /* export_ext */
    NULL,               /* genkey */
    NULL,               /* import */
    NULL,               /* keylist */
    NULL,               /* keylist_ext */
    NULL,               /* keylist_data */
    NULL,               /* keysign */
    NULL,               /* revsig */
    NULL,               /* tofu_policy */
    NULL,               /* sign */
    NULL,               /* verify */
    NULL,               /* getauditlog */
    NULL,               /* setexpire */
    NULL,               /* setownertrust */
    g13_transact,
    NULL,               /* getdirect */
    NULL,		/* conf_load */
    NULL,		/* conf_save */
    NULL,		/* conf_dir */
    NULL,               /* query_swdb */
    g13_set_io_cbs,
    g13_io_event,
    g13_cancel,
    g13_cancel_op,
    NULL,               /* passwd */
    NULL,               /* set_pinentry_mode */
    NULL                /* opspawn */
  };
