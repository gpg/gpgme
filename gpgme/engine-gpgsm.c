/* engine-gpgsm.c -  GpgSM engine
 *	Copyright (C) 2000 Werner Koch (dd9jn)
 *      Copyright (C) 2001 g10 Code GmbH
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

#if HAVE_CONFIG_H
#include <config.h>
#endif

/* FIXME: Correct check?  */
#ifdef GPGSM_PATH
#define ENABLE_GPGSM 1
#endif

#ifdef ENABLE_GPGSM

#include <sys/types.h>
#include <assert.h>

/* FIXME */
#include "../assuan/assuan-defs.h"
#undef xtrymalloc
#undef xtrycalloc
#undef xtryrealloc
#undef xfree

#include "gpgme.h"
#include "util.h"
#include "types.h"
#include "ops.h"
#include "wait.h"
#include "io.h"

#include "engine-gpgsm.h"

#include "assuan.h"

struct gpgsm_object_s
{
  ASSUAN_CONTEXT assuan_ctx;

  /* Input, output etc are from the servers perspective.  */
  int input_fd;
  int input_fd_server;
  GpgmeData input_data;
  int output_fd;
  int output_fd_server;
  GpgmeData output_data;
  int message_fd;
  int message_fd_server;
  GpgmeData message_data;

  char *command;

  struct
  {
    GpgStatusHandler fnc;
    void *fnc_value;
  } status;
  
};

const char *
_gpgme_gpgsm_get_version (void)
{
  static const char *gpgsm_version;

  /* FIXME: Locking.  */
  if (!gpgsm_version)
    gpgsm_version = _gpgme_get_program_version (_gpgme_get_gpgsm_path ());

  return gpgsm_version;
}

GpgmeError
_gpgme_gpgsm_check_version (void)
{
  return _gpgme_compare_versions (_gpgme_gpgsm_get_version (),
				  NEED_GPGSM_VERSION)
    ? 0 : mk_error (Invalid_Engine);
}

GpgmeError
_gpgme_gpgsm_new (GpgsmObject *r_gpgsm)
{
  GpgmeError err = 0;
  GpgsmObject gpgsm;
  char *argv[] = { "gpgsm", "--server", NULL };
  int ip[2] = { -1, -1 };
  int op[2] = { -1, -1 };
  int mp[2] = { -1, -1 };

  *r_gpgsm = NULL;
  gpgsm = xtrycalloc (1, sizeof *gpgsm);
  if (!gpgsm)
    {
      err = mk_error (Out_Of_Core);
      goto leave;
    }

  if (_gpgme_io_pipe (ip, 0) < 0)
    {
      err = mk_error (General_Error);
      goto leave;
    }
  gpgsm->input_fd = ip[1];
  gpgsm->input_fd_server = ip[0];
  if (_gpgme_io_pipe (op, 1) < 0)
    {
      err = mk_error (General_Error);
      goto leave;
    }
  gpgsm->output_fd = op[0];
  gpgsm->output_fd_server = op[1];
  if (_gpgme_io_pipe (mp, 0) < 0)
    {
      err = mk_error (General_Error);
      goto leave;
    }
  gpgsm->message_fd = mp[1];
  gpgsm->message_fd_server = mp[0];

  err = assuan_pipe_connect (&gpgsm->assuan_ctx,
			     _gpgme_get_gpgsm_path (), argv);

 leave:
  if (ip[0] != -1)
    _gpgme_io_close (ip[0]);
  if (op[1] != -1)
    _gpgme_io_close (op[1]);
  if (mp[0] != -1)
    _gpgme_io_close (mp[0]);

  if (err)
    _gpgme_gpgsm_release (gpgsm);
  else
    *r_gpgsm = gpgsm;

  return err;
}

void
_gpgme_gpgsm_release (GpgsmObject gpgsm)
{
  pid_t pid;

  if (!gpgsm)
    return;

  pid = assuan_get_pid (gpgsm->assuan_ctx);
  if (pid != -1)
    _gpgme_remove_proc_from_wait_queue (pid);

  if (gpgsm->input_fd != -1)
    _gpgme_io_close (gpgsm->input_fd);
  if (gpgsm->output_fd != -1)
    _gpgme_io_close (gpgsm->output_fd);
  if (gpgsm->message_fd != -1)
    _gpgme_io_close (gpgsm->message_fd);

  assuan_pipe_disconnect (gpgsm->assuan_ctx);
  xfree (gpgsm);
}

#define COMMANDLINELEN 40
static AssuanError
gpgsm_set_fd (ASSUAN_CONTEXT ctx, const char *which, int fd)
{
  AssuanError err;
  char line[COMMANDLINELEN];

  snprintf (line, COMMANDLINELEN, "%s FD=%i", which, fd);
  err = _assuan_write_line (ctx, line);
  if (err)
    return err;

  do
    {
      err = _assuan_read_line (ctx);
      if (err)
	return err;
    }
  while (*ctx->inbound.line == '#' || !ctx->inbound.linelen);
  
  if (ctx->inbound.linelen >= 2
      && ctx->inbound.line[0] == 'O' && ctx->inbound.line[1] == 'K'
      && (ctx->inbound.line[2] == '\0' || ctx->inbound.line[2] == ' '))
    return 0;
  else
    return ASSUAN_General_Error;
}

GpgmeError
_gpgme_gpgsm_op_verify (GpgsmObject gpgsm, GpgmeData sig, GpgmeData text)
{
  AssuanError err;

  if (!gpgsm)
    return mk_error (Invalid_Value);

  gpgsm->input_data = sig;
  err = gpgsm_set_fd (gpgsm->assuan_ctx, "INPUT", gpgsm->input_fd_server);
  if (err)
    return mk_error (General_Error);	/* FIXME */
  gpgsm->message_data = sig;
  err = gpgsm_set_fd (gpgsm->assuan_ctx, "MESSAGE", gpgsm->message_fd_server);
  if (err)
    return mk_error (General_Error);	/* FIXME */
  _gpgme_io_close (gpgsm->output_fd);
  gpgsm->output_fd = -1;

  gpgsm->command = "VERIFY";
  return 0;
}

static int
gpgsm_status_handler (void *opaque, int pid, int fd)
{
  int err;
  GpgsmObject gpgsm = opaque;
  ASSUAN_CONTEXT actx = gpgsm->assuan_ctx;

 assert (fd == gpgsm->assuan_ctx->inbound.fd);

  err = _assuan_read_line (gpgsm->assuan_ctx);

  if (actx->inbound.line[0] == '#' || !actx->inbound.linelen)
    return 0;  /* FIXME */

  if (actx->inbound.linelen >= 2
      && actx->inbound.line[0] == 'O' && actx->inbound.line[1] == 'K'
      && (actx->inbound.line[2] == '\0' || actx->inbound.line[2] == ' '))
    {
      if (gpgsm->status.fnc)
	gpgsm->status.fnc (gpgsm->status.fnc_value, STATUS_EOF, "");
      return 1;
    }
  /* FIXME: Parse the status and call the handler.  */

  fprintf (stderr, "[UNCAUGHT STATUS]%s", actx->inbound.line);
  return 0;
}

void
_gpgme_gpgsm_set_status_handler (GpgsmObject gpgsm,
				 GpgStatusHandler fnc, void *fnc_value) 
{
  assert (gpgsm);

  gpgsm->status.fnc = fnc;
  gpgsm->status.fnc_value = fnc_value;
}

GpgmeError
_gpgme_gpgsm_start (GpgsmObject gpgsm, void *opaque)
{
  GpgmeError err = 0;
  pid_t pid;

  if (!gpgsm)
    return mk_error (Invalid_Value);

  pid = assuan_get_pid (gpgsm->assuan_ctx);

  err = _gpgme_register_pipe_handler (opaque, gpgsm_status_handler, gpgsm, pid,
				      gpgsm->assuan_ctx->inbound.fd, 1);

  if (gpgsm->input_fd != -1)
    {
      err = _gpgme_register_pipe_handler (opaque, _gpgme_data_outbound_handler,
					  gpgsm->input_data, pid,
					  gpgsm->input_fd, 0);
      if (!err)	/* FIXME Kludge around poll() problem.  */
	err = _gpgme_io_set_nonblocking (gpgsm->input_fd);
    }
  if (!err && gpgsm->output_fd != -1)
    err = _gpgme_register_pipe_handler (opaque, _gpgme_data_inbound_handler,
					gpgsm->output_data, pid,
					gpgsm->output_fd, 1);
  if (!err && gpgsm->message_fd != -1)
    {
      err = _gpgme_register_pipe_handler (opaque, _gpgme_data_outbound_handler,
					  gpgsm->message_data, pid,
					  gpgsm->message_fd, 0);
      if (!err)	/* FIXME Kludge around poll() problem.  */
	err = _gpgme_io_set_nonblocking (gpgsm->message_fd);
    }

  if (!err)
    err = _assuan_write_line (gpgsm->assuan_ctx, gpgsm->command);

  return err;
}

#else	/* ENABLE_GPGSM */

#include <stddef.h>
#include "util.h"

#include "engine-gpgsm.h"

const char *
_gpgme_gpgsm_get_version (void)
{
  return NULL;
}

GpgmeError
_gpgme_gpgsm_check_version (void)
{
  return mk_error (Invalid_Engine);
}

GpgmeError
_gpgme_gpgsm_new (GpgsmObject *r_gpgsm)
{
  return mk_error (Invalid_Engine);
}

void
_gpgme_gpgsm_release (GpgsmObject gpgsm)
{
  return;
}

void
_gpgme_gpgsm_set_status_handler (GpgsmObject gpgsm,
				 GpgStatusHandler fnc, void *fnc_value) 
{
  return;
}

GpgmeError
 _gpgme_gpgsm_op_verify (GpgsmObject gpgsm, GpgmeData sig, GpgmeData text)
{
  return mk_error (Invalid_Engine);
}

GpgmeError
_gpgme_gpgsm_start (GpgsmObject gpgsm, void *opaque)
{
  return mk_error (Invalid_Engine);
}

#endif	/* ! ENABLE_GPGSM */
