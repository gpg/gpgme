/* engine-assuan.c - Low-level Assuan protocol engine
 * Copyright (C) 2009 g10 Code GmbH
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

/*
   Note: This engine requires a modern Assuan server which uses
   gpg-error codes.  In particular there is no backward compatible
   mapping of old Assuan error codes implemented.
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
} iocb_data_t;

/* Engine instance data.  */
struct engine_llass
{
  assuan_context_t assuan_ctx;

  int lc_ctype_set;
  int lc_messages_set;

  iocb_data_t status_cb;

  struct gpgme_io_cbs io_cbs;

  /* Hack for old opassuan.c interface, see there the result struct.  */
  gpg_error_t last_op_err;

  /* User provided callbacks.  */
  struct {
    gpgme_assuan_data_cb_t data_cb;
    void *data_cb_value;

    gpgme_assuan_inquire_cb_t inq_cb;
    void *inq_cb_value;

    gpgme_assuan_status_cb_t status_cb;
    void *status_cb_value;
  } user;

  /* Option flags.  */
  struct {
    int gpg_agent:1;  /* Assume this is a gpg-agent connection.  */
  } opt;

  char request_origin[10];  /* Copy from the CTX.  */
};
typedef struct engine_llass *engine_llass_t;


gpg_error_t _gpgme_engine_assuan_last_op_err (void *engine)
{
  engine_llass_t llass = engine;
  return llass->last_op_err;
}


/* Prototypes.  */
static void llass_io_event (void *engine,
                            gpgme_event_io_t type, void *type_data);





/* return the default home directory.  */
static const char *
llass_get_home_dir (void)
{
  /* For this engine the home directory is not a filename but a string
     used to convey options.  The exclamation mark is a marker to show
     that this is not a directory name. Options are strings delimited
     by a space.  The only option defined for now is GPG_AGENT to
     enable GPG_AGENT specific commands to send to the server at
     connection startup.  */
  return "!GPG_AGENT";
}

static char *
llass_get_version (const char *file_name)
{
  (void)file_name;
  return NULL;
}


static const char *
llass_get_req_version (void)
{
  return NULL;
}


static void
close_notify_handler (int fd, void *opaque)
{
  engine_llass_t llass = opaque;

  assert (fd != -1);
  if (llass->status_cb.fd == fd)
    {
      if (llass->status_cb.tag)
	llass->io_cbs.remove (llass->status_cb.tag);
      llass->status_cb.fd = -1;
      llass->status_cb.tag = NULL;
    }
}



static gpgme_error_t
llass_cancel (void *engine)
{
  engine_llass_t llass = engine;

  if (!llass)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (llass->status_cb.fd != -1)
    _gpgme_io_close (llass->status_cb.fd);

  if (llass->assuan_ctx)
    {
      assuan_release (llass->assuan_ctx);
      llass->assuan_ctx = NULL;
    }

  return 0;
}


static gpgme_error_t
llass_cancel_op (void *engine)
{
  engine_llass_t llass = engine;

  if (!llass)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (llass->status_cb.fd != -1)
    _gpgme_io_close (llass->status_cb.fd);

  return 0;
}


static void
llass_release (void *engine)
{
  engine_llass_t llass = engine;

  if (!llass)
    return;

  llass_cancel (engine);

  free (llass);
}


/* Create a new instance. If HOME_DIR is NULL standard options for use
   with gpg-agent are issued.  */
static gpgme_error_t
llass_new (void **engine, const char *file_name, const char *home_dir,
           const char *version)
{
  gpgme_error_t err = 0;
  engine_llass_t llass;
  char *optstr;
  char *env_tty = NULL;

  (void)version; /* Not yet used.  */

  llass = calloc (1, sizeof *llass);
  if (!llass)
    return gpg_error_from_syserror ();

  llass->status_cb.fd = -1;
  llass->status_cb.dir = 1;
  llass->status_cb.tag = 0;
  llass->status_cb.data = llass;

  /* Parse_options.  */
  if (home_dir && *home_dir == '!')
    {
      home_dir++;
      /* Very simple parser only working for the one option we support.  */
      /* Note that wk promised to write a regression test if this
         parser will be extended.  */
      if (!strncmp (home_dir, "GPG_AGENT", 9)
          && (!home_dir[9] || home_dir[9] == ' '))
        llass->opt.gpg_agent = 1;
    }

  err = assuan_new_ext (&llass->assuan_ctx, GPG_ERR_SOURCE_GPGME,
			&_gpgme_assuan_malloc_hooks, _gpgme_assuan_log_cb,
			NULL);
  if (err)
    goto leave;
  assuan_ctx_set_system_hooks (llass->assuan_ctx, &_gpgme_assuan_system_hooks);
  assuan_set_flag (llass->assuan_ctx, ASSUAN_CONVEY_COMMENTS, 1);

  err = assuan_socket_connect (llass->assuan_ctx, file_name, 0, 0);
  if (err)
    goto leave;

  if (llass->opt.gpg_agent)
    {
      char *dft_display = NULL;

      err = _gpgme_getenv ("DISPLAY", &dft_display);
      if (err)
        goto leave;
      if (dft_display && *dft_display)
        {
          if (gpgrt_asprintf (&optstr, "OPTION display=%s", dft_display) < 0)
            {
              err = gpg_error_from_syserror ();
              free (dft_display);
              goto leave;
            }
          free (dft_display);

          err = assuan_transact (llass->assuan_ctx, optstr, NULL, NULL, NULL,
                                 NULL, NULL, NULL);
          gpgrt_free (optstr);
          if (err)
            goto leave;
        }
      else
        free (dft_display);
    }


  if (llass->opt.gpg_agent)
    err = _gpgme_getenv ("GPG_TTY", &env_tty);

  if (llass->opt.gpg_agent && (isatty (1) || env_tty || err))
    {
      int rc = 0;
      char dft_ttyname[64];
      char *dft_ttytype = NULL;

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
	  err = assuan_transact (llass->assuan_ctx, optstr, NULL, NULL, NULL,
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
		  err = gpg_error_from_syserror ();
		  free (dft_ttytype);
		  goto leave;
		}
	      free (dft_ttytype);

	      err = assuan_transact (llass->assuan_ctx, optstr, NULL, NULL,
				     NULL, NULL, NULL, NULL);
	      gpgrt_free (optstr);
	      if (err)
                goto leave;
	    }
	}
    }


#ifdef HAVE_W32_SYSTEM
  /* Under Windows we need to use AllowSetForegroundWindow.  Tell
     llass to tell us when it needs it.  */
  if (!err && llass->opt.gpg_agent)
    {
      err = assuan_transact (llass->assuan_ctx, "OPTION allow-pinentry-notify",
                             NULL, NULL, NULL, NULL, NULL, NULL);
      if (gpg_err_code (err) == GPG_ERR_UNKNOWN_OPTION)
        err = 0; /* This work only with recent gpg-agents.  */
    }
#endif /*HAVE_W32_SYSTEM*/


 leave:
  /* Close the server ends of the pipes (because of this, we must use
     the stored server_fd_str in the function start).  Our ends are
     closed in llass_release().  */

  if (err)
    llass_release (llass);
  else
    *engine = llass;

  return err;
}


/* Copy flags from CTX into the engine object.  */
static void
llass_set_engine_flags (void *engine, const gpgme_ctx_t ctx)
{
  engine_llass_t llass = engine;

  if (ctx->request_origin)
    {
      if (strlen (ctx->request_origin) + 1 > sizeof llass->request_origin)
        strcpy (llass->request_origin, "xxx"); /* Too long  - force error */
      else
        strcpy (llass->request_origin, ctx->request_origin);
    }
  else
    *llass->request_origin = 0;
}


static gpgme_error_t
llass_set_locale (void *engine, int category, const char *value)
{
  gpgme_error_t err;
  engine_llass_t llass = engine;
  char *optstr;
  const char *catstr;

  if (!llass->opt.gpg_agent)
    return 0;

  /* FIXME: If value is NULL, we need to reset the option to default.
     But we can't do this.  So we error out here.  gpg-agent needs
     support for this.  */
  if (0)
    ;
#ifdef LC_CTYPE
  else if (category == LC_CTYPE)
    {
      catstr = "lc-ctype";
      if (!value && llass->lc_ctype_set)
	return gpg_error (GPG_ERR_INV_VALUE);
      if (value)
	llass->lc_ctype_set = 1;
    }
#endif
#ifdef LC_MESSAGES
  else if (category == LC_MESSAGES)
    {
      catstr = "lc-messages";
      if (!value && llass->lc_messages_set)
	return gpg_error (GPG_ERR_INV_VALUE);
      if (value)
	llass->lc_messages_set = 1;
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
      err = assuan_transact (llass->assuan_ctx, optstr, NULL, NULL,
			     NULL, NULL, NULL, NULL);
      gpgrt_free (optstr);
    }
  return err;
}


/* This is the inquiry callback.  It handles stuff which ee need to
   handle here and passes everything on to the user callback.  */
static gpgme_error_t
inquire_cb (engine_llass_t llass, const char *keyword, const char *args)
{
  gpg_error_t err, err2;
  gpgme_data_t data = NULL;
  char buf[1024];
  gpgme_ssize_t n;

  if (llass->opt.gpg_agent && !strcmp (keyword, "PINENTRY_LAUNCHED"))
    {
      _gpgme_allow_set_foreground_window ((pid_t)strtoul (args, NULL, 10));
    }

  if (llass->user.inq_cb)
    {
      err = llass->user.inq_cb (llass->user.inq_cb_value,
                                keyword, args, &data);
      if (!err && data)
        {
          while ((n = gpgme_data_read (data, buf, sizeof buf)) > 0)
            {
              err = assuan_send_data (llass->assuan_ctx, buf, n);
              if (err)
                break;
            }
          /* Tell the caller that we are finished with the data
           * object.  The error code from assuan_send_data has
           * priority over the one from the cleanup function. */
          err2 = llass->user.inq_cb (llass->user.inq_cb_value,
                                     NULL, NULL, &data);
          if (!err)
            err = err2;
        }
    }
  else
    err = 0;

  return err;
}


static gpgme_error_t
llass_status_handler (void *opaque, int fd)
{
  struct io_cb_data *data = (struct io_cb_data *) opaque;
  engine_llass_t llass = (engine_llass_t) data->handler_value;
  gpgme_error_t err = 0;
  char *line;
  size_t linelen;

  do
    {
      err = assuan_read_line (llass->assuan_ctx, &line, &linelen);
      if (err)
	{
	  /* Reading a full line may not be possible when
	     communicating over a socket in nonblocking mode.  In this
	     case, we are done for now.  */
	  if (gpg_err_code (err) == GPG_ERR_EAGAIN)
	    {
	      TRACE (DEBUG_CTX, "gpgme:llass_status_handler", llass,
		      "fd 0x%x: EAGAIN reading assuan line (ignored)", fd);
	      err = 0;
	      continue;
	    }

	  TRACE (DEBUG_CTX, "gpgme:llass_status_handler", llass,
		  "fd 0x%x: error reading assuan line: %s",
                  fd, gpg_strerror (err));
	}
      else if (linelen >= 2 && line[0] == 'D' && line[1] == ' ')
        {
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
          if (linelen && llass->user.data_cb)
            err = llass->user.data_cb (llass->user.data_cb_value,
                                       src, linelen);

          TRACE (DEBUG_CTX, "gpgme:llass_status_handler", llass,
		  "fd 0x%x: D inlinedata; status from cb: %s",
                  fd, (llass->user.data_cb ?
                       (err? gpg_strerror (err):"ok"):"no callback"));
        }
      else if (linelen >= 3
               && line[0] == 'E' && line[1] == 'N' && line[2] == 'D'
               && (line[3] == '\0' || line[3] == ' '))
        {
          /* END received.  Tell the data callback.  */
          if (llass->user.data_cb)
            err = llass->user.data_cb (llass->user.data_cb_value, NULL, 0);

          TRACE (DEBUG_CTX, "gpgme:llass_status_handler", llass,
		  "fd 0x%x: END line; status from cb: %s",
                  fd, (llass->user.data_cb ?
                       (err? gpg_strerror (err):"ok"):"no callback"));
        }
      else if (linelen > 2 && line[0] == 'S' && line[1] == ' ')
	{
	  char *args;
          char *src;

          for (src=line+2; *src == ' '; src++)
            ;

	  args = strchr (src, ' ');
	  if (!args)
	    args = line + linelen; /* Let it point to an empty string.  */
	  else
	    *(args++) = 0;

          while (*args == ' ')
            args++;

          if (llass->user.status_cb)
            err = llass->user.status_cb (llass->user.status_cb_value,
                                         src, args);

          TRACE (DEBUG_CTX, "gpgme:llass_status_handler", llass,
		  "fd 0x%x: S line (%s) - status from cb: %s",
                  fd, line+2, (llass->user.status_cb ?
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

          err = inquire_cb (llass, src, args);
          if (!err)
            {
              /* Flush and send END.  */
              err = assuan_send_data (llass->assuan_ctx, NULL, 0);
            }
          else if (gpg_err_code (err) == GPG_ERR_ASS_CANCELED)
            {
              /* Flush and send CANcel.  */
              err = assuan_send_data (llass->assuan_ctx, NULL, 1);
            }
        }
      else if (linelen >= 3
	       && line[0] == 'E' && line[1] == 'R' && line[2] == 'R'
	       && (line[3] == '\0' || line[3] == ' '))
	{
	  if (line[3] == ' ')
	    err = atoi (line+4);
	  else
	    err = gpg_error (GPG_ERR_GENERAL);
          TRACE (DEBUG_CTX, "gpgme:llass_status_handler", llass,
		  "fd 0x%x: ERR line: %s",
                  fd, err ? gpg_strerror (err) : "ok");

	  /* Command execution errors are not fatal, as we use
	     a session based protocol.  */
	  data->op_err = err;
	  llass->last_op_err = err;

	  /* The caller will do the rest (namely, call cancel_op,
	     which closes status_fd).  */
	  return 0;
	}
      else if (linelen >= 2
	       && line[0] == 'O' && line[1] == 'K'
	       && (line[2] == '\0' || line[2] == ' '))
	{
          TRACE (DEBUG_CTX, "gpgme:llass_status_handler", llass,
		  "fd 0x%x: OK line", fd);

	  llass->last_op_err = 0;

	  _gpgme_io_close (llass->status_cb.fd);
	  return 0;
	}
      else
        {
          /* Comment line or invalid line.  */
        }

    }
  while (!err && assuan_pending_line (llass->assuan_ctx));

  return err;
}


static gpgme_error_t
add_io_cb (engine_llass_t llass, iocb_data_t *iocbd, gpgme_io_cb_t handler)
{
  gpgme_error_t err;

  TRACE_BEG  (DEBUG_ENGINE, "engine-assuan:add_io_cb", llass,
              "fd=%d, dir %d", iocbd->fd, iocbd->dir);
  err = (*llass->io_cbs.add) (llass->io_cbs.add_priv,
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
start (engine_llass_t llass, const char *command)
{
  gpgme_error_t err;
  assuan_fd_t afdlist[5];
  int fdlist[5];
  int nfds;
  int i;

  if (*llass->request_origin && llass->opt.gpg_agent)
    {
      char *cmd;

      cmd = _gpgme_strconcat ("OPTION pretend-request-origin=",
                              llass->request_origin, NULL);
      if (!cmd)
        return gpg_error_from_syserror ();
      err = assuan_transact (llass->assuan_ctx, cmd, NULL, NULL, NULL,
                             NULL, NULL, NULL);
      free (cmd);
      if (err && gpg_err_code (err) != GPG_ERR_UNKNOWN_OPTION)
        return err;
    }

  /* We need to know the fd used by assuan for reads.  We do this by
     using the assumption that the first returned fd from
     assuan_get_active_fds() is always this one.  */
  nfds = assuan_get_active_fds (llass->assuan_ctx, 0 /* read fds */,
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

  llass->status_cb.fd = _gpgme_io_dup (fdlist[0]);
  if (llass->status_cb.fd < 0)
    return gpg_error_from_syserror ();

  if (_gpgme_io_set_close_notify (llass->status_cb.fd,
				  close_notify_handler, llass))
    {
      _gpgme_io_close (llass->status_cb.fd);
      llass->status_cb.fd = -1;
      return gpg_error (GPG_ERR_GENERAL);
    }

  err = add_io_cb (llass, &llass->status_cb, llass_status_handler);
  if (!err)
    err = assuan_write_line (llass->assuan_ctx, command);

  /* FIXME: If *command == '#' no answer is expected.  */

  if (!err)
    llass_io_event (llass, GPGME_EVENT_START, NULL);

  return err;
}



static gpgme_error_t
llass_transact (void *engine,
                const char *command,
                gpgme_assuan_data_cb_t data_cb,
                void *data_cb_value,
                gpgme_assuan_inquire_cb_t inq_cb,
                void *inq_cb_value,
                gpgme_assuan_status_cb_t status_cb,
                void *status_cb_value)
{
  engine_llass_t llass = engine;
  gpgme_error_t err;

  if (!llass || !command || !*command)
    return gpg_error (GPG_ERR_INV_VALUE);

  llass->user.data_cb = data_cb;
  llass->user.data_cb_value = data_cb_value;
  llass->user.inq_cb = inq_cb;
  llass->user.inq_cb_value = inq_cb_value;
  llass->user.status_cb = status_cb;
  llass->user.status_cb_value = status_cb_value;

  err = start (llass, command);
  return err;
}



static void
llass_set_io_cbs (void *engine, gpgme_io_cbs_t io_cbs)
{
  engine_llass_t llass = engine;
  llass->io_cbs = *io_cbs;
}


static void
llass_io_event (void *engine, gpgme_event_io_t type, void *type_data)
{
  engine_llass_t llass = engine;

  TRACE (DEBUG_ENGINE, "gpgme:llass_io_event", llass,
          "event %p, type %d, type_data %p",
          llass->io_cbs.event, type, type_data);
  if (llass->io_cbs.event)
    (*llass->io_cbs.event) (llass->io_cbs.event_priv, type, type_data);
}


struct engine_ops _gpgme_engine_ops_assuan =
  {
    /* Static functions.  */
    _gpgme_get_default_agent_socket,
    llass_get_home_dir,
    llass_get_version,
    llass_get_req_version,
    llass_new,

    /* Member functions.  */
    llass_release,
    NULL,		/* reset */
    NULL,               /* set_status_cb */
    NULL,               /* set_status_handler */
    NULL,		/* set_command_handler */
    NULL,               /* set_colon_line_handler */
    llass_set_locale,
    NULL,		/* set_protocol */
    llass_set_engine_flags,
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
    llass_transact,     /* opassuan_transact */
    NULL,               /* getdirect */
    NULL,		/* conf_load */
    NULL,		/* conf_save */
    NULL,		/* conf_dir */
    NULL,               /* query_swdb */
    llass_set_io_cbs,
    llass_io_event,
    llass_cancel,
    llass_cancel_op,
    NULL,               /* passwd */
    NULL,               /* set_pinentry_mode */
    NULL                /* opspawn */
  };
