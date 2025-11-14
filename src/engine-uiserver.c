/* engine-uiserver.c - Uiserver engine.
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

/* Peculiar: Use special keys from email address for recipient and
   signer (==sender).  Use no data objects with encryption for
   prep_encrypt.  */

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
#include <locale.h>
#include <fcntl.h> /* FIXME */
#include <errno.h>

#include "gpgme.h"
#include "util.h"
#include "ops.h"
#include "wait.h"
#include "priv-io.h"
#include "sema.h"
#include "data.h"

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


struct engine_uiserver
{
  assuan_context_t assuan_ctx;

  int lc_ctype_set;
  int lc_messages_set;
  gpgme_protocol_t protocol;

  iocb_data_t status_cb;

  /* Input, output etc are from the servers perspective.  */
  iocb_data_t input_cb;
  gpgme_data_t input_helper_data;  /* Input helper data object.  */
  void *input_helper_memory;       /* Input helper memory block.  */

  iocb_data_t output_cb;

  iocb_data_t message_cb;

  struct
  {
    engine_status_handler_t fnc;
    void *fnc_value;
    gpgme_status_cb_t mon_cb;
    void *mon_cb_value;
  } status;

  struct
  {
    engine_colon_line_handler_t fnc;
    void *fnc_value;
    struct
    {
      char *line;
      int linesize;
      int linelen;
    } attic;
    int any; /* any data line seen */
  } colon;

  gpgme_data_t inline_data;  /* Used to collect D lines.  */

  struct gpgme_io_cbs io_cbs;
};

typedef struct engine_uiserver *engine_uiserver_t;


static void uiserver_io_event (void *engine,
                            gpgme_event_io_t type, void *type_data);



static char *
uiserver_get_version (const char *file_name)
{
  (void)file_name;
  return NULL;
}


static const char *
uiserver_get_req_version (void)
{
  return NULL;
}


static void
close_notify_handler (int fd, void *opaque)
{
  engine_uiserver_t uiserver = opaque;

  assert (fd != -1);
  if (uiserver->status_cb.fd == fd)
    {
      if (uiserver->status_cb.tag)
	(*uiserver->io_cbs.remove) (uiserver->status_cb.tag);
      uiserver->status_cb.fd = -1;
      uiserver->status_cb.tag = NULL;
    }
  else if (uiserver->input_cb.fd == fd)
    {
      if (uiserver->input_cb.tag)
	(*uiserver->io_cbs.remove) (uiserver->input_cb.tag);
      uiserver->input_cb.fd = -1;
      uiserver->input_cb.tag = NULL;
      if (uiserver->input_helper_data)
        {
          gpgme_data_release (uiserver->input_helper_data);
          uiserver->input_helper_data = NULL;
        }
      if (uiserver->input_helper_memory)
        {
          free (uiserver->input_helper_memory);
          uiserver->input_helper_memory = NULL;
        }
    }
  else if (uiserver->output_cb.fd == fd)
    {
      if (uiserver->output_cb.tag)
	(*uiserver->io_cbs.remove) (uiserver->output_cb.tag);
      uiserver->output_cb.fd = -1;
      uiserver->output_cb.tag = NULL;
    }
  else if (uiserver->message_cb.fd == fd)
    {
      if (uiserver->message_cb.tag)
	(*uiserver->io_cbs.remove) (uiserver->message_cb.tag);
      uiserver->message_cb.fd = -1;
      uiserver->message_cb.tag = NULL;
    }
}


/* This is the default inquiry callback.  We use it to handle the
   Pinentry notifications.  */
static gpgme_error_t
default_inq_cb (engine_uiserver_t uiserver, const char *line)
{
  (void)uiserver;

  if (!strncmp (line, "PINENTRY_LAUNCHED", 17) && (line[17]==' '||!line[17]))
    {
      _gpgme_allow_set_foreground_window ((pid_t)strtoul (line+17, NULL, 10));
    }

  return 0;
}


static gpgme_error_t
uiserver_cancel (void *engine)
{
  engine_uiserver_t uiserver = engine;

  if (!uiserver)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (uiserver->status_cb.fd != -1)
    _gpgme_io_close (uiserver->status_cb.fd);
  if (uiserver->input_cb.fd != -1)
    _gpgme_io_close (uiserver->input_cb.fd);
  if (uiserver->output_cb.fd != -1)
    _gpgme_io_close (uiserver->output_cb.fd);
  if (uiserver->message_cb.fd != -1)
    _gpgme_io_close (uiserver->message_cb.fd);

  if (uiserver->assuan_ctx)
    {
      assuan_release (uiserver->assuan_ctx);
      uiserver->assuan_ctx = NULL;
    }

  return 0;
}


static void
uiserver_release (void *engine)
{
  engine_uiserver_t uiserver = engine;

  if (!uiserver)
    return;

  uiserver_cancel (engine);

  free (uiserver->colon.attic.line);
  free (uiserver);
}


static gpgme_error_t
uiserver_new (void **engine, const char *file_name, const char *home_dir,
              const char *version)
{
  gpgme_error_t err = 0;
  engine_uiserver_t uiserver;
  char *dft_display = NULL;
  char dft_ttyname[64];
  char *env_tty = NULL;
  char *dft_ttytype = NULL;
  char *optstr;

  (void)home_dir;
  (void)version; /* Not yet used.  */

  uiserver = calloc (1, sizeof *uiserver);
  if (!uiserver)
    return gpg_error_from_syserror ();

  uiserver->protocol = GPGME_PROTOCOL_DEFAULT;
  uiserver->status_cb.fd = -1;
  uiserver->status_cb.dir = 1;
  uiserver->status_cb.tag = 0;
  uiserver->status_cb.data = uiserver;

  uiserver->input_cb.fd = -1;
  uiserver->input_cb.dir = 0;
  uiserver->input_cb.tag = 0;
  uiserver->input_cb.server_fd = -1;
  *uiserver->input_cb.server_fd_str = 0;
  uiserver->output_cb.fd = -1;
  uiserver->output_cb.dir = 1;
  uiserver->output_cb.tag = 0;
  uiserver->output_cb.server_fd = -1;
  *uiserver->output_cb.server_fd_str = 0;
  uiserver->message_cb.fd = -1;
  uiserver->message_cb.dir = 0;
  uiserver->message_cb.tag = 0;
  uiserver->message_cb.server_fd = -1;
  *uiserver->message_cb.server_fd_str = 0;

  uiserver->status.fnc = 0;
  uiserver->colon.fnc = 0;
  uiserver->colon.attic.line = 0;
  uiserver->colon.attic.linesize = 0;
  uiserver->colon.attic.linelen = 0;
  uiserver->colon.any = 0;

  uiserver->inline_data = NULL;

  uiserver->io_cbs.add = NULL;
  uiserver->io_cbs.add_priv = NULL;
  uiserver->io_cbs.remove = NULL;
  uiserver->io_cbs.event = NULL;
  uiserver->io_cbs.event_priv = NULL;

  err = assuan_new_ext (&uiserver->assuan_ctx, GPG_ERR_SOURCE_GPGME,
			&_gpgme_assuan_malloc_hooks, _gpgme_assuan_log_cb,
			NULL);
  if (err)
    goto leave;
  assuan_ctx_set_system_hooks (uiserver->assuan_ctx,
			       &_gpgme_assuan_system_hooks);

  err = assuan_socket_connect (uiserver->assuan_ctx,
			       file_name ?
			       file_name : _gpgme_get_default_uisrv_socket (),
			       0, ASSUAN_SOCKET_SERVER_FDPASSING);
  if (err)
    goto leave;

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

      err = assuan_transact (uiserver->assuan_ctx, optstr, NULL, NULL, NULL,
			     NULL, NULL, NULL);
      gpgrt_free (optstr);
      if (err)
	goto leave;
    }
  else
    free (dft_display);

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
	  err = assuan_transact (uiserver->assuan_ctx, optstr, NULL, NULL, NULL,
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

	      err = assuan_transact (uiserver->assuan_ctx, optstr, NULL, NULL,
				     NULL, NULL, NULL, NULL);
	      gpgrt_free (optstr);
	      if (err)
		goto leave;
	    }
	}
    }

#ifdef HAVE_W32_SYSTEM
  /* Under Windows we need to use AllowSetForegroundWindow.  Tell
     uiserver to tell us when it needs it.  */
  if (!err)
    {
      err = assuan_transact (uiserver->assuan_ctx, "OPTION allow-pinentry-notify",
                             NULL, NULL, NULL, NULL, NULL, NULL);
      if (gpg_err_code (err) == GPG_ERR_UNKNOWN_OPTION)
        err = 0; /* This is a new feature of uiserver.  */
    }
#endif /*HAVE_W32_SYSTEM*/

 leave:
  if (err)
    uiserver_release (uiserver);
  else
    *engine = uiserver;

  return err;
}


static gpgme_error_t
uiserver_set_locale (void *engine, int category, const char *value)
{
  engine_uiserver_t uiserver = engine;
  gpgme_error_t err;
  char *optstr;
  const char *catstr;

  /* FIXME: If value is NULL, we need to reset the option to default.
     But we can't do this.  So we error out here.  UISERVER needs support
     for this.  */
  if (category == LC_CTYPE)
    {
      catstr = "lc-ctype";
      if (!value && uiserver->lc_ctype_set)
	return gpg_error (GPG_ERR_INV_VALUE);
      if (value)
	uiserver->lc_ctype_set = 1;
    }
#ifdef LC_MESSAGES
  else if (category == LC_MESSAGES)
    {
      catstr = "lc-messages";
      if (!value && uiserver->lc_messages_set)
	return gpg_error (GPG_ERR_INV_VALUE);
      if (value)
	uiserver->lc_messages_set = 1;
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
      err = assuan_transact (uiserver->assuan_ctx, optstr, NULL, NULL,
			     NULL, NULL, NULL, NULL);
      gpgrt_free (optstr);
    }

  return err;
}


static gpgme_error_t
uiserver_set_protocol (void *engine, gpgme_protocol_t protocol)
{
  engine_uiserver_t uiserver = engine;

  if (protocol != GPGME_PROTOCOL_OpenPGP
      && protocol != GPGME_PROTOCOL_CMS
      && protocol != GPGME_PROTOCOL_DEFAULT)
    return gpg_error (GPG_ERR_INV_VALUE);

  uiserver->protocol = protocol;
  return 0;
}


static gpgme_error_t
uiserver_assuan_simple_command (engine_uiserver_t uiserver, const char *cmd,
                                engine_status_handler_t status_fnc,
                                void *status_fnc_value)
{
  assuan_context_t ctx = uiserver->assuan_ctx;
  gpg_error_t err;
  char *line;
  size_t linelen;

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
	  gpgme_status_code_t r;

	  rest = strchr (line + 2, ' ');
	  if (!rest)
	    rest = line + linelen; /* set to an empty string */
	  else
	    *(rest++) = 0;

	  r = _gpgme_parse_status (line + 2);
          if (uiserver->status.mon_cb && r != GPGME_STATUS_PROGRESS)
            {
              /* Note that we call the monitor even if we do
               * not know the status code (r < 0).  */
              err = uiserver->status.mon_cb (uiserver->status.mon_cb_value,
                                             line + 2, rest);
            }

          if (err)
            ;
	  else if (r >= 0 && status_fnc)
	    err = status_fnc (status_fnc_value, r, rest);
	  else
	    err = gpg_error (GPG_ERR_GENERAL);
	}
      else
	err = gpg_error (GPG_ERR_GENERAL);
    }
  while (!err);

  return err;
}


typedef enum { INPUT_FD, OUTPUT_FD, MESSAGE_FD } fd_type_t;

#define COMMANDLINELEN 40
static gpgme_error_t
uiserver_set_fd (engine_uiserver_t uiserver, fd_type_t fd_type, const char *opt)
{
  gpg_error_t err = 0;
  char line[COMMANDLINELEN];
  const char *which;
  iocb_data_t *iocb_data;
  int dir;

  switch (fd_type)
    {
    case INPUT_FD:
      which = "INPUT";
      iocb_data = &uiserver->input_cb;
      break;

    case OUTPUT_FD:
      which = "OUTPUT";
      iocb_data = &uiserver->output_cb;
      break;

    case MESSAGE_FD:
      which = "MESSAGE";
      iocb_data = &uiserver->message_cb;
      break;

    default:
      return gpg_error (GPG_ERR_INV_VALUE);
    }

  dir = iocb_data->dir;

  /* We try to short-cut the communication by giving UISERVER direct
     access to the file descriptor, rather than using a pipe.  */
  iocb_data->server_fd = _gpgme_data_get_fd (iocb_data->data);
  if (iocb_data->server_fd < 0)
    {
      int fds[2];

      if (_gpgme_io_pipe (fds, 0) < 0)
	return gpg_error_from_syserror ();

      iocb_data->fd = dir ? fds[0] : fds[1];
      iocb_data->server_fd = dir ? fds[1] : fds[0];

      if (_gpgme_io_set_close_notify (iocb_data->fd,
				      close_notify_handler, uiserver))
	{
	  err = gpg_error (GPG_ERR_GENERAL);
	  goto leave_set_fd;
	}
    }

  err = assuan_sendfd (uiserver->assuan_ctx, iocb_data->server_fd);
  if (err)
    goto leave_set_fd;

  _gpgme_io_close (iocb_data->server_fd);
  iocb_data->server_fd = -1;

  if (opt)
    snprintf (line, COMMANDLINELEN, "%s FD %s", which, opt);
  else
    snprintf (line, COMMANDLINELEN, "%s FD", which);

  err = uiserver_assuan_simple_command (uiserver, line, NULL, NULL);

 leave_set_fd:
  if (err)
    {
      _gpgme_io_close (iocb_data->fd);
      iocb_data->fd = -1;
      if (iocb_data->server_fd != -1)
        {
          _gpgme_io_close (iocb_data->server_fd);
          iocb_data->server_fd = -1;
        }
    }

  return err;
}


static const char *
map_data_enc (gpgme_data_t d)
{
  switch (gpgme_data_get_encoding (d))
    {
    case GPGME_DATA_ENCODING_NONE:
      break;
    case GPGME_DATA_ENCODING_BINARY:
      return "--binary";
    case GPGME_DATA_ENCODING_BASE64:
      return "--base64";
    case GPGME_DATA_ENCODING_ARMOR:
      return "--armor";
    default:
      break;
    }
  return NULL;
}


static gpgme_error_t
status_handler (void *opaque, int fd)
{
  struct io_cb_data *data = (struct io_cb_data *) opaque;
  engine_uiserver_t uiserver = (engine_uiserver_t) data->handler_value;
  gpgme_error_t err = 0;
  char *line;
  size_t linelen;

  do
    {
      err = assuan_read_line (uiserver->assuan_ctx, &line, &linelen);
      if (err)
	{
	  /* Try our best to terminate the connection friendly.  */
	  /*	  assuan_write_line (uiserver->assuan_ctx, "BYE"); */
          TRACE (DEBUG_CTX, "gpgme:status_handler", uiserver,
		  "fd 0x%x: error from assuan (%d) getting status line : %s",
                  fd, err, gpg_strerror (err));
	}
      else if (linelen >= 3
	       && line[0] == 'E' && line[1] == 'R' && line[2] == 'R'
	       && (line[3] == '\0' || line[3] == ' '))
	{
	  if (line[3] == ' ')
	    err = atoi (&line[4]);
	  if (! err)
	    err = gpg_error (GPG_ERR_GENERAL);
          TRACE (DEBUG_CTX, "gpgme:status_handler", uiserver,
		  "fd 0x%x: ERR line - mapped to: %s",
                  fd, err ? gpg_strerror (err) : "ok");
	  /* Try our best to terminate the connection friendly.  */
	  /*	  assuan_write_line (uiserver->assuan_ctx, "BYE"); */
	}
      else if (linelen >= 2
	       && line[0] == 'O' && line[1] == 'K'
	       && (line[2] == '\0' || line[2] == ' '))
	{
	  if (uiserver->status.fnc)
            {
              char emptystring[1] = {0};
              err = uiserver->status.fnc (uiserver->status.fnc_value,
                                          GPGME_STATUS_EOF, emptystring);
              if (gpg_err_code (err) == GPG_ERR_FALSE)
                err = 0; /* Drop special error code.  */
            }

	  if (!err && uiserver->colon.fnc && uiserver->colon.any)
            {
              /* We must tell a colon function about the EOF. We do
                 this only when we have seen any data lines.  Note
                 that this inlined use of colon data lines will
                 eventually be changed into using a regular data
                 channel. */
              uiserver->colon.any = 0;
              err = uiserver->colon.fnc (uiserver->colon.fnc_value, NULL);
            }
          TRACE (DEBUG_CTX, "gpgme:status_handler", uiserver,
		  "fd 0x%x: OK line - final status: %s",
                  fd, err ? gpg_strerror (err) : "ok");
	  _gpgme_io_close (uiserver->status_cb.fd);
	  return err;
	}
      else if (linelen > 2
	       && line[0] == 'D' && line[1] == ' '
	       && uiserver->colon.fnc)
        {
	  /* We are using the colon handler even for plain inline data
             - strange name for that function but for historic reasons
             we keep it.  */
          /* FIXME We can't use this for binary data because we
             assume this is a string.  For the current usage of colon
             output it is correct.  */
          char *src = line + 2;
	  char *end = line + linelen;
	  char *dst;
          char **aline = &uiserver->colon.attic.line;
	  int *alinelen = &uiserver->colon.attic.linelen;

	  if (uiserver->colon.attic.linesize < *alinelen + linelen + 1)
	    {
	      char *newline = realloc (*aline, *alinelen + linelen + 1);
	      if (!newline)
		err = gpg_error_from_syserror ();
	      else
		{
		  *aline = newline;
		  uiserver->colon.attic.linesize = *alinelen + linelen + 1;
		}
	    }
	  if (!err)
	    {
	      dst = *aline + *alinelen;

	      while (!err && src < end)
		{
		  if (*src == '%' && src + 2 < end)
		    {
		      /* Handle escaped characters.  */
		      ++src;
		      *dst = _gpgme_hextobyte (src);
		      (*alinelen)++;
		      src += 2;
		    }
		  else
		    {
		      *dst = *src++;
		      (*alinelen)++;
		    }

		  if (*dst == '\n')
		    {
		      /* Terminate the pending line, pass it to the colon
			 handler and reset it.  */

		      uiserver->colon.any = 1;
		      if (*alinelen > 1 && *(dst - 1) == '\r')
			dst--;
		      *dst = '\0';

		      /* FIXME How should we handle the return code?  */
		      err = uiserver->colon.fnc (uiserver->colon.fnc_value, *aline);
		      if (!err)
			{
			  dst = *aline;
			  *alinelen = 0;
			}
		    }
		  else
		    dst++;
		}
	    }
          TRACE (DEBUG_CTX, "gpgme:status_handler", uiserver,
		  "fd 0x%x: D line; final status: %s",
                  fd, err? gpg_strerror (err):"ok");
        }
      else if (linelen > 2
	       && line[0] == 'D' && line[1] == ' '
	       && uiserver->inline_data)
        {
          char *src = line + 2;
	  char *end = line + linelen;
	  char *dst = src;
          gpgme_ssize_t nwritten;

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
          while (linelen > 0)
            {
              nwritten = gpgme_data_write (uiserver->inline_data, src, linelen);
              if (!nwritten || (nwritten < 0 && errno != EINTR)
                  || nwritten > linelen)
                {
                  err = gpg_error_from_syserror ();
                  break;
                }
              src += nwritten;
              linelen -= nwritten;
            }

          TRACE (DEBUG_CTX, "gpgme:status_handler", uiserver,
		  "fd 0x%x: D inlinedata; final status: %s",
                  fd, err? gpg_strerror (err):"ok");
        }
      else if (linelen > 2
	       && line[0] == 'S' && line[1] == ' ')
	{
	  char *rest;
	  gpgme_status_code_t r;

	  rest = strchr (line + 2, ' ');
	  if (!rest)
	    rest = line + linelen; /* set to an empty string */
	  else
	    *(rest++) = 0;

	  r = _gpgme_parse_status (line + 2);

	  if (r >= 0)
	    {
	      if (uiserver->status.fnc)
                {
                  err = uiserver->status.fnc (uiserver->status.fnc_value,
                                              r, rest);
                  if (gpg_err_code (err) == GPG_ERR_FALSE)
                    err = 0; /* Drop special error code.  */
                }
	    }
	  else
	    fprintf (stderr, "[UNKNOWN STATUS]%s %s", line + 2, rest);
          TRACE (DEBUG_CTX, "gpgme:status_handler", uiserver,
		  "fd 0x%x: S line (%s) - final status: %s",
                  fd, line+2, err? gpg_strerror (err):"ok");
	}
      else if (linelen >= 7
               && line[0] == 'I' && line[1] == 'N' && line[2] == 'Q'
               && line[3] == 'U' && line[4] == 'I' && line[5] == 'R'
               && line[6] == 'E'
               && (line[7] == '\0' || line[7] == ' '))
        {
          char *keyword = line+7;

          while (*keyword == ' ')
            keyword++;;
          default_inq_cb (uiserver, keyword);
          assuan_write_line (uiserver->assuan_ctx, "END");
        }

    }
  while (!err && assuan_pending_line (uiserver->assuan_ctx));

  return err;
}


static gpgme_error_t
add_io_cb (engine_uiserver_t uiserver, iocb_data_t *iocbd, gpgme_io_cb_t handler)
{
  gpgme_error_t err;

  TRACE_BEG  (DEBUG_ENGINE, "engine-uiserver:add_io_cb", uiserver,
              "fd=%d, dir %d", iocbd->fd, iocbd->dir);
  err = (*uiserver->io_cbs.add) (uiserver->io_cbs.add_priv,
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
start (engine_uiserver_t uiserver, const char *command)
{
  gpgme_error_t err;
  int fdlist[5];
  int nfds;

  /* We need to know the fd used by assuan for reads.  We do this by
     using the assumption that the first returned fd from
     assuan_get_active_fds() is always this one.  */
  nfds = assuan_get_active_fds (uiserver->assuan_ctx, 0 /* read fds */,
                                fdlist, DIM (fdlist));
  if (nfds < 1)
    return gpg_error (GPG_ERR_GENERAL);	/* FIXME */

  /* We "duplicate" the file descriptor, so we can close it here (we
     can't close fdlist[0], as that is closed by libassuan, and
     closing it here might cause libassuan to close some unrelated FD
     later).  Alternatively, we could special case status_fd and
     register/unregister it manually as needed, but this increases
     code duplication and is more complicated as we can not use the
     close notifications etc.  A third alternative would be to let
     Assuan know that we closed the FD, but that complicates the
     Assuan interface.  */

  uiserver->status_cb.fd = _gpgme_io_dup (fdlist[0]);
  if (uiserver->status_cb.fd < 0)
    return gpg_error_from_syserror ();

  if (_gpgme_io_set_close_notify (uiserver->status_cb.fd,
				  close_notify_handler, uiserver))
    {
      _gpgme_io_close (uiserver->status_cb.fd);
      uiserver->status_cb.fd = -1;
      return gpg_error (GPG_ERR_GENERAL);
    }

  err = add_io_cb (uiserver, &uiserver->status_cb, status_handler);
  if (!err && uiserver->input_cb.fd != -1)
    err = add_io_cb (uiserver, &uiserver->input_cb, _gpgme_data_outbound_handler);
  if (!err && uiserver->output_cb.fd != -1)
    err = add_io_cb (uiserver, &uiserver->output_cb, _gpgme_data_inbound_handler);
  if (!err && uiserver->message_cb.fd != -1)
    err = add_io_cb (uiserver, &uiserver->message_cb, _gpgme_data_outbound_handler);

  if (!err)
    err = assuan_write_line (uiserver->assuan_ctx, command);

  if (!err)
    uiserver_io_event (uiserver, GPGME_EVENT_START, NULL);

  return err;
}


static gpgme_error_t
uiserver_reset (void *engine)
{
  engine_uiserver_t uiserver = engine;

  /* We must send a reset because we need to reset the list of
     signers.  Note that RESET does not reset OPTION commands. */
  return uiserver_assuan_simple_command (uiserver, "RESET", NULL, NULL);
}


static gpgme_error_t
uiserver_decrypt (void *engine,
                  gpgme_decrypt_flags_t flags,
                  gpgme_data_t ciph, gpgme_data_t plain,
                  int export_session_key, const char *override_session_key,
                  int auto_key_retrieve)
{
  engine_uiserver_t uiserver = engine;
  gpgme_error_t err;
  const char *protocol;
  char *cmd;
  int verify = !!(flags & GPGME_DECRYPT_VERIFY);

  (void)override_session_key; /* Fixme: We need to see now to add this
                               * to the UI server protocol  */
  (void)auto_key_retrieve;    /* Not yet supported.  */


  if (!uiserver)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (uiserver->protocol == GPGME_PROTOCOL_DEFAULT)
    protocol = "";
  else if (uiserver->protocol == GPGME_PROTOCOL_OpenPGP)
    protocol = " --protocol=OpenPGP";
  else if (uiserver->protocol == GPGME_PROTOCOL_CMS)
    protocol = " --protocol=CMS";
  else
    return gpgme_error (GPG_ERR_UNSUPPORTED_PROTOCOL);

  if (gpgrt_asprintf (&cmd, "DECRYPT%s%s%s", protocol,
		verify ? "" : " --no-verify",
                export_session_key ? " --export-session-key" : "") < 0)
    return gpg_error_from_syserror ();

  uiserver->input_cb.data = ciph;
  err = uiserver_set_fd (uiserver, INPUT_FD,
			 map_data_enc (uiserver->input_cb.data));
  if (err)
    {
      gpgrt_free (cmd);
      return gpg_error (GPG_ERR_GENERAL);	/* FIXME */
    }
  uiserver->output_cb.data = plain;
  err = uiserver_set_fd (uiserver, OUTPUT_FD, 0);
  if (err)
    {
      gpgrt_free (cmd);
      return gpg_error (GPG_ERR_GENERAL);	/* FIXME */
    }
  uiserver->inline_data = NULL;

  err = start (engine, cmd);
  gpgrt_free (cmd);
  return err;
}


static gpgme_error_t
set_recipients (engine_uiserver_t uiserver, gpgme_key_t recp[])
{
  gpgme_error_t err = 0;
  char *line;
  int linelen;
  int invalid_recipients = 0;
  int i;

  linelen = 10 + 40 + 1;	/* "RECIPIENT " + guess + '\0'.  */
  line = malloc (10 + 40 + 1);
  if (!line)
    return gpg_error_from_syserror ();
  strcpy (line, "RECIPIENT ");
  for (i=0; !err && recp[i]; i++)
    {
      char *uid;
      int newlen;

      /* We use only the first user ID of the key.  */
      if (!recp[i]->uids || !(uid=recp[i]->uids->uid) || !*uid)
	{
	  invalid_recipients++;
	  continue;
	}

      newlen = 11 + strlen (uid);
      if (linelen < newlen)
	{
	  char *newline = realloc (line, newlen);
	  if (! newline)
	    {
	      int saved_err = gpg_error_from_syserror ();
	      free (line);
	      return saved_err;
	    }
	  line = newline;
	  linelen = newlen;
	}
      /* FIXME: need to do proper escaping  */
      strcpy (&line[10], uid);

      err = uiserver_assuan_simple_command (uiserver, line,
                                            uiserver->status.fnc,
                                            uiserver->status.fnc_value);
      /* FIXME: This might requires more work.  */
      if (gpg_err_code (err) == GPG_ERR_NO_PUBKEY)
	invalid_recipients++;
      else if (err)
	{
	  free (line);
	  return err;
	}
    }
  free (line);
  return gpg_error (invalid_recipients
		    ? GPG_ERR_UNUSABLE_PUBKEY : GPG_ERR_NO_ERROR);
}


/* Take recipients from the LF delimited STRING and send RECIPIENT
 * commands to gpgsm.  */
static gpgme_error_t
set_recipients_from_string (engine_uiserver_t uiserver, const char *string)
{
  gpg_error_t err = 0;
  char *line = NULL;
  int no_pubkey = 0;
  const char *s;
  int n;

  for (;;)
    {
      while (*string == ' ' || *string == '\t')
        string++;
      if (!*string)
        break;

      s = strchr (string, '\n');
      if (s)
        n = s - string;
      else
        n = strlen (string);
      while (n && (string[n-1] == ' ' || string[n-1] == '\t'))
        n--;

      gpgrt_free (line);
      if (gpgrt_asprintf (&line, "RECIPIENT %.*s", n, string) < 0)
        {
          err = gpg_error_from_syserror ();
          break;
        }
      string += n + !!s;

      err = uiserver_assuan_simple_command (uiserver, line,
                                            uiserver->status.fnc,
                                            uiserver->status.fnc_value);

      /* Fixme: Improve error reporting.  */
      if (gpg_err_code (err) == GPG_ERR_NO_PUBKEY)
	no_pubkey++;
      else if (err)
        break;
    }
  gpgrt_free (line);
  return err? err : no_pubkey? gpg_error (GPG_ERR_NO_PUBKEY) : 0;
}


static gpgme_error_t
uiserver_encrypt (void *engine, gpgme_key_t recp[], const char *recpstring,
                  gpgme_encrypt_flags_t flags,
		  gpgme_data_t plain, gpgme_data_t ciph, int use_armor)
{
  engine_uiserver_t uiserver = engine;
  gpgme_error_t err;
  const char *protocol;
  char *cmd;

  if (!uiserver)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (uiserver->protocol == GPGME_PROTOCOL_DEFAULT)
    protocol = "";
  else if (uiserver->protocol == GPGME_PROTOCOL_OpenPGP)
    protocol = " --protocol=OpenPGP";
  else if (uiserver->protocol == GPGME_PROTOCOL_CMS)
    protocol = " --protocol=CMS";
  else
    return gpgme_error (GPG_ERR_UNSUPPORTED_PROTOCOL);

  if (flags & (GPGME_ENCRYPT_ARCHIVE | GPGME_ENCRYPT_FILE))
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  if (flags & GPGME_ENCRYPT_PREPARE)
    {
      if (!recp || plain || ciph)
	return gpg_error (GPG_ERR_INV_VALUE);

      if (gpgrt_asprintf (&cmd, "PREP_ENCRYPT%s%s", protocol,
		    (flags & GPGME_ENCRYPT_EXPECT_SIGN)
		    ? " --expect-sign" : "") < 0)
	return gpg_error_from_syserror ();
    }
  else
    {
      if (!plain || !ciph)
	return gpg_error (GPG_ERR_INV_VALUE);

      if (gpgrt_asprintf (&cmd, "ENCRYPT%s", protocol) < 0)
	return gpg_error_from_syserror ();
    }

  if (plain)
    {
      uiserver->input_cb.data = plain;
      err = uiserver_set_fd (uiserver, INPUT_FD,
			     map_data_enc (uiserver->input_cb.data));
      if (err)
	{
	  gpgrt_free (cmd);
	  return err;
	}
    }

  if (ciph)
    {
      uiserver->output_cb.data = ciph;
      err = uiserver_set_fd (uiserver, OUTPUT_FD, use_armor ? "--armor"
			     : map_data_enc (uiserver->output_cb.data));
      if (err)
	{
	  gpgrt_free (cmd);
	  return err;
	}
    }

  uiserver->inline_data = NULL;

  if (recp || recpstring)
    {
      if (recp)
        err = set_recipients (uiserver, recp);
      else
        err = set_recipients_from_string (uiserver, recpstring);
      if (err)
	{
	  gpgrt_free (cmd);
	  return err;
	}
    }

  err = start (uiserver, cmd);
  gpgrt_free (cmd);
  return err;
}


static gpgme_error_t
uiserver_sign (void *engine, gpgme_data_t in, gpgme_data_t out,
	       gpgme_sig_mode_t flags, int use_armor, int use_textmode,
	       int include_certs, gpgme_ctx_t ctx /* FIXME */)
{
  engine_uiserver_t uiserver = engine;
  gpgme_error_t err = 0;
  const char *protocol;
  char *cmd;
  gpgme_key_t key;

  (void)use_textmode;
  (void)include_certs;

  if (!uiserver || !in || !out)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (uiserver->protocol == GPGME_PROTOCOL_DEFAULT)
    protocol = "";
  else if (uiserver->protocol == GPGME_PROTOCOL_OpenPGP)
    protocol = " --protocol=OpenPGP";
  else if (uiserver->protocol == GPGME_PROTOCOL_CMS)
    protocol = " --protocol=CMS";
  else
    return gpgme_error (GPG_ERR_UNSUPPORTED_PROTOCOL);

  if (flags & (GPGME_SIG_MODE_CLEAR
               | GPGME_SIG_MODE_ARCHIVE
               | GPGME_SIG_MODE_FILE))
    return gpg_error (GPG_ERR_INV_VALUE);

  if (gpgrt_asprintf (&cmd, "SIGN%s%s", protocol,
		(flags & GPGME_SIG_MODE_DETACH) ? " --detached" : "") < 0)
    return gpg_error_from_syserror ();

  key = gpgme_signers_enum (ctx, 0);
  if (key)
    {
      const char *s = NULL;

      if (key && key->uids)
        s = key->uids->email;

      if (s && strlen (s) < 80)
        {
          char buf[100];

          strcpy (stpcpy (buf, "SENDER --info "), s);
          err = uiserver_assuan_simple_command (uiserver, buf,
                                                uiserver->status.fnc,
                                                uiserver->status.fnc_value);
        }
      else
        err = gpg_error (GPG_ERR_INV_VALUE);
      gpgme_key_unref (key);
      if (err)
        {
          gpgrt_free (cmd);
          return err;
        }
  }

  uiserver->input_cb.data = in;
  err = uiserver_set_fd (uiserver, INPUT_FD,
			 map_data_enc (uiserver->input_cb.data));
  if (err)
    {
      gpgrt_free (cmd);
      return err;
    }
  uiserver->output_cb.data = out;
  err = uiserver_set_fd (uiserver, OUTPUT_FD, use_armor ? "--armor"
			 : map_data_enc (uiserver->output_cb.data));
  if (err)
    {
      gpgrt_free (cmd);
      return err;
    }
  uiserver->inline_data = NULL;

  err = start (uiserver, cmd);
  gpgrt_free (cmd);
  return err;
}


/* FIXME: Missing a way to specify --silent.  */
static gpgme_error_t
uiserver_verify (void *engine, gpgme_verify_flags_t flags, gpgme_data_t sig,
                 gpgme_data_t signed_text, gpgme_data_t plaintext,
                 gpgme_ctx_t ctx)
{
  engine_uiserver_t uiserver = engine;
  gpgme_error_t err;
  const char *protocol;
  char *cmd;

  (void)ctx; /* FIXME: We should to add a --sender option to the
              * UISever protocol.  */

  if (!uiserver)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (uiserver->protocol == GPGME_PROTOCOL_DEFAULT)
    protocol = "";
  else if (uiserver->protocol == GPGME_PROTOCOL_OpenPGP)
    protocol = " --protocol=OpenPGP";
  else if (uiserver->protocol == GPGME_PROTOCOL_CMS)
    protocol = " --protocol=CMS";
  else
    return gpgme_error (GPG_ERR_UNSUPPORTED_PROTOCOL);

  if (flags & GPGME_VERIFY_ARCHIVE)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  if (gpgrt_asprintf (&cmd, "VERIFY%s", protocol) < 0)
    return gpg_error_from_syserror ();

  uiserver->input_cb.data = sig;
  err = uiserver_set_fd (uiserver, INPUT_FD,
			 map_data_enc (uiserver->input_cb.data));
  if (err)
    {
      gpgrt_free (cmd);
      return err;
    }
  if (plaintext)
    {
      /* Normal or cleartext signature.  */
      uiserver->output_cb.data = plaintext;
      err = uiserver_set_fd (uiserver, OUTPUT_FD, 0);
    }
  else
    {
      /* Detached signature.  */
      uiserver->message_cb.data = signed_text;
      err = uiserver_set_fd (uiserver, MESSAGE_FD, 0);
    }
  uiserver->inline_data = NULL;

  if (!err)
    err = start (uiserver, cmd);

  gpgrt_free (cmd);
  return err;
}


/* This sets a status callback for monitoring status lines before they
 * are passed to a caller set handler.  */
static void
uiserver_set_status_cb (void *engine, gpgme_status_cb_t cb, void *cb_value)
{
  engine_uiserver_t uiserver = engine;

  uiserver->status.mon_cb = cb;
  uiserver->status.mon_cb_value = cb_value;
}


static void
uiserver_set_status_handler (void *engine, engine_status_handler_t fnc,
			  void *fnc_value)
{
  engine_uiserver_t uiserver = engine;

  uiserver->status.fnc = fnc;
  uiserver->status.fnc_value = fnc_value;
}


static gpgme_error_t
uiserver_set_colon_line_handler (void *engine, engine_colon_line_handler_t fnc,
			      void *fnc_value)
{
  engine_uiserver_t uiserver = engine;

  uiserver->colon.fnc = fnc;
  uiserver->colon.fnc_value = fnc_value;
  uiserver->colon.any = 0;
  return 0;
}


static void
uiserver_set_io_cbs (void *engine, gpgme_io_cbs_t io_cbs)
{
  engine_uiserver_t uiserver = engine;
  uiserver->io_cbs = *io_cbs;
}


static void
uiserver_io_event (void *engine, gpgme_event_io_t type, void *type_data)
{
  engine_uiserver_t uiserver = engine;

  TRACE (DEBUG_ENGINE, "gpgme:uiserver_io_event", uiserver,
          "event %p, type %d, type_data %p",
          uiserver->io_cbs.event, type, type_data);
  if (uiserver->io_cbs.event)
    (*uiserver->io_cbs.event) (uiserver->io_cbs.event_priv, type, type_data);
}


struct engine_ops _gpgme_engine_ops_uiserver =
  {
    /* Static functions.  */
    _gpgme_get_default_uisrv_socket,
    NULL,
    uiserver_get_version,
    uiserver_get_req_version,
    uiserver_new,

    /* Member functions.  */
    uiserver_release,
    uiserver_reset,
    uiserver_set_status_cb,
    uiserver_set_status_handler,
    NULL,		/* set_command_handler */
    uiserver_set_colon_line_handler,
    uiserver_set_locale,
    uiserver_set_protocol,
    NULL,               /* set_engine_flags */
    uiserver_decrypt,
    NULL,		/* delete */
    NULL,		/* edit */
    uiserver_encrypt,
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
    uiserver_sign,
    uiserver_verify,
    NULL,		/* getauditlog */
    NULL,               /* setexpire */
    NULL,               /* setownertrust */
    NULL,               /* opassuan_transact */
    NULL,               /* getdirect */
    NULL,		/* conf_load */
    NULL,		/* conf_save */
    NULL,		/* conf_dir */
    NULL,               /* query_swdb */
    uiserver_set_io_cbs,
    uiserver_io_event,
    uiserver_cancel,
    NULL,		/* cancel_op */
    NULL,               /* passwd */
    NULL,               /* set_pinentry_mode */
    NULL                /* opspawn */
  };
