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

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <assert.h>
#include <fcntl.h> /* FIXME */

#include "rungpg.h"
#include "status-table.h"

#include "gpgme.h"
#include "util.h"
#include "types.h"
#include "ops.h"
#include "wait.h"
#include "io.h"
#include "key.h"

#include "engine-gpgsm.h"

#include "assuan.h"

#define xtoi_1(p)   (*(p) <= '9'? (*(p)- '0'): \
                     *(p) <= 'F'? (*(p)-'A'+10):(*(p)-'a'+10))
#define xtoi_2(p)   ((xtoi_1(p) * 16) + xtoi_1((p)+1))


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

  struct
  {
    GpgColonLineHandler fnc;
    void *fnc_value;
    struct
    {
      unsigned char *line;
      int linesize;
      int linelen;
    } attic;
  } colon; 
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

static void
close_notify_handler (int fd, void *opaque)
{
  GpgsmObject gpgsm = opaque;

  assert (fd != -1);
  if (gpgsm->input_fd == fd)
    gpgsm->input_fd = -1;
  else if (gpgsm->output_fd == fd)
    gpgsm->output_fd = -1;
  else if (gpgsm->message_fd == fd)
    gpgsm->message_fd = -1;
}

GpgmeError
_gpgme_gpgsm_new (GpgsmObject *r_gpgsm)
{
  GpgmeError err = 0;
  GpgsmObject gpgsm;
  char *argv[] = { "gpgsm", "--server", NULL };
  int fds[2];

  *r_gpgsm = NULL;
  gpgsm = xtrycalloc (1, sizeof *gpgsm);
  if (!gpgsm)
    {
      err = mk_error (Out_Of_Core);
      return err;
    }

  gpgsm->input_fd = -1;
  gpgsm->input_fd_server = -1;
  gpgsm->output_fd = -1;
  gpgsm->output_fd_server = -1;
  gpgsm->message_fd = -1;
  gpgsm->message_fd_server = -1;

  gpgsm->status.fnc = 0;
  gpgsm->colon.fnc = 0;
  gpgsm->colon.attic.line = 0;
  gpgsm->colon.attic.linesize = 0;
  gpgsm->colon.attic.linelen = 0;

  if (_gpgme_io_pipe (fds, 0) < 0)
    {
      err = mk_error (General_Error);
      goto leave;
    }
  gpgsm->input_fd = fds[1];
  gpgsm->input_fd_server = fds[0];

  if (_gpgme_io_pipe (fds, 1) < 0)
    {
      err = mk_error (General_Error);
      goto leave;
    }
  gpgsm->output_fd = fds[0];
  gpgsm->output_fd_server = fds[1];

  if (_gpgme_io_pipe (fds, 0) < 0)
    {
      err = mk_error (General_Error);
      goto leave;
    }
  gpgsm->message_fd = fds[1];
  gpgsm->message_fd_server = fds[0];

  err = assuan_pipe_connect (&gpgsm->assuan_ctx,
			     _gpgme_get_gpgsm_path (), argv);

  if (!err &&
      (_gpgme_io_set_close_notify (gpgsm->input_fd,
				   close_notify_handler, gpgsm)
       || _gpgme_io_set_close_notify (gpgsm->output_fd,
				      close_notify_handler, gpgsm)
       || _gpgme_io_set_close_notify (gpgsm->message_fd,
				      close_notify_handler, gpgsm)))
    {
      err = mk_error (General_Error);
      goto leave;
    }
      
 leave:
  /* Close the server ends of the pipes.  Our ends are closed in
     _gpgme_gpgsm_release.  */
  if (gpgsm->input_fd_server != -1)
    _gpgme_io_close (gpgsm->input_fd_server);
  if (gpgsm->output_fd_server != -1)
    _gpgme_io_close (gpgsm->output_fd_server);
  if (gpgsm->message_fd_server != -1)
    _gpgme_io_close (gpgsm->message_fd_server);

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

  xfree (gpgsm->colon.attic.line);
  xfree (gpgsm->command);
  xfree (gpgsm);
}

static AssuanError
gpgsm_assuan_simple_command (ASSUAN_CONTEXT ctx, char *cmd)
{
  AssuanError err;
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
    }
  while (*line == '#' || !linelen);
  
  if (linelen >= 2
      && line[0] == 'O' && line[1] == 'K'
      && (line[2] == '\0' || line[2] == ' '))
    return 0;
  else
    return ASSUAN_General_Error;
}

#define COMMANDLINELEN 40
static AssuanError
gpgsm_set_fd (ASSUAN_CONTEXT ctx, const char *which, int fd, const char *opt)
{
  char line[COMMANDLINELEN];

  if (opt)
    snprintf (line, COMMANDLINELEN, "%s FD=%i %s", which, fd, opt);
  else
    snprintf (line, COMMANDLINELEN, "%s FD=%i", which, fd);

  return gpgsm_assuan_simple_command (ctx, line);
}

GpgmeError
_gpgme_gpgsm_op_decrypt (GpgsmObject gpgsm, GpgmeData ciph, GpgmeData plain)
{
  AssuanError err;

  if (!gpgsm)
    return mk_error (Invalid_Value);

  gpgsm->command = xtrystrdup ("DECRYPT");
  if (!gpgsm->command)
    return mk_error (Out_Of_Core);

  gpgsm->input_data = ciph;
  err = gpgsm_set_fd (gpgsm->assuan_ctx, "INPUT", gpgsm->input_fd_server, 0);
  if (err)
    return mk_error (General_Error);	/* FIXME */
  gpgsm->output_data = plain;
  err = gpgsm_set_fd (gpgsm->assuan_ctx, "OUTPUT", gpgsm->output_fd_server, 0);
  if (err)
    return mk_error (General_Error);	/* FIXME */
  _gpgme_io_close (gpgsm->message_fd);

  return 0;
}

GpgmeError
_gpgme_gpgsm_op_delete (GpgsmObject gpgsm, GpgmeKey key, int allow_secret)
{
  /* FIXME */
  return mk_error (Not_Implemented);
}

static AssuanError
gpgsm_set_recipients (ASSUAN_CONTEXT ctx, GpgmeRecipients recp)
{
  AssuanError err;
  char *line;
  int linelen;
  struct user_id_s *r;

  linelen = 10 + 40 + 1;	/* "RECIPIENT " + guess + '\0'.  */
  line = xtrymalloc (10 + 40 + 1);
  if (!line)
    return ASSUAN_Out_Of_Core;
  strcpy (line, "RECIPIENT ");
  for (r = recp->list; r; r = r->next)
    {
      int newlen = 11 + strlen (r->name);
      if (linelen < newlen)
	{
	  char *newline = xtryrealloc (line, newlen);
	  if (! newline)
	    {
	      xfree (line);
	      return ASSUAN_Out_Of_Core;
	    }
	  line = newline;
	  linelen = newlen;
	}
      strcpy (&line[10], r->name);
      
      err = gpgsm_assuan_simple_command (ctx, line);
      if (err)
	{
	  xfree (line);
	  return err;
	}
    }
  xfree (line);
  return 0;
}

GpgmeError
_gpgme_gpgsm_op_encrypt (GpgsmObject gpgsm, GpgmeRecipients recp,
			 GpgmeData plain, GpgmeData ciph, int use_armor)
{
  AssuanError err;

  if (!gpgsm)
    return mk_error (Invalid_Value);

  gpgsm->command = xtrystrdup ("ENCRYPT");
  if (!gpgsm->command)
    return mk_error (Out_Of_Core);

  gpgsm->input_data = plain;
  err = gpgsm_set_fd (gpgsm->assuan_ctx, "INPUT", gpgsm->input_fd_server, 0);
  if (err)
    return mk_error (General_Error);	/* FIXME */
  gpgsm->output_data = ciph;
  err = gpgsm_set_fd (gpgsm->assuan_ctx, "OUTPUT", gpgsm->output_fd_server,
		      use_armor ? "--armor" : 0);
  if (err)
    return mk_error (General_Error);	/* FIXME */
  _gpgme_io_close (gpgsm->message_fd);

  err = gpgsm_set_recipients (gpgsm->assuan_ctx, recp);
  if (err)
    return mk_error (General_Error);

  return 0;
}

GpgmeError
_gpgme_gpgsm_op_export (GpgsmObject gpgsm, GpgmeRecipients recp,
			GpgmeData keydata, int use_armor)
{
  /* FIXME */
  return mk_error (Not_Implemented);
}

GpgmeError
_gpgme_gpgsm_op_genkey (GpgsmObject gpgsm, GpgmeData help_data, int use_armor)
{
  /* FIXME */
  return mk_error (Not_Implemented);
}

GpgmeError
_gpgme_gpgsm_op_import (GpgsmObject gpgsm, GpgmeData keydata)
{
  AssuanError err;

  if (!gpgsm)
    return mk_error (Invalid_Value);

  gpgsm->command = xtrystrdup ("IMPORT");
  if (!gpgsm->command)
    return mk_error (Out_Of_Core);

  gpgsm->input_data = keydata;
  err = gpgsm_set_fd (gpgsm->assuan_ctx, "INPUT", gpgsm->input_fd_server, 0);
  if (err)
    return mk_error (General_Error);	/* FIXME */
  _gpgme_io_close (gpgsm->output_fd);
  _gpgme_io_close (gpgsm->message_fd);

  return 0;
}

GpgmeError
_gpgme_gpgsm_op_keylist (GpgsmObject gpgsm, const char *pattern,
			 int secret_only, int keylist_mode)
{
  char *line;

  if (!pattern)
    pattern = "";

  line = xtrymalloc (9 + strlen (pattern) + 1);	/* "LISTKEYS " + p + '\0'.  */
  if (!line)
    return mk_error (Out_Of_Core);
  strcpy (line, "LISTKEYS ");
  strcpy (&line[9], pattern);

  _gpgme_io_close (gpgsm->input_fd);
  _gpgme_io_close (gpgsm->output_fd);
  _gpgme_io_close (gpgsm->message_fd);

  gpgsm->command = line;
  return 0;
}

GpgmeError
_gpgme_gpgsm_op_sign (GpgsmObject gpgsm, GpgmeData in, GpgmeData out,
		      GpgmeSigMode mode, int use_armor,
		      int use_textmode, GpgmeCtx ctx /* FIXME */)
{
  AssuanError err;

  if (!gpgsm)
    return mk_error (Invalid_Value);

  gpgsm->command = xtrystrdup (mode == GPGME_SIG_MODE_DETACH
			       ? "SIGN --detached" : "SIGN");
  if (!gpgsm->command)
    return mk_error (Out_Of_Core);

  gpgsm->input_data = in;
  err = gpgsm_set_fd (gpgsm->assuan_ctx, "INPUT", gpgsm->input_fd_server, 0);
  if (err)
    return mk_error (General_Error);	/* FIXME */
  gpgsm->output_data = out;
  err = gpgsm_set_fd (gpgsm->assuan_ctx, "OUTPUT", gpgsm->output_fd_server,
		      use_armor ? "--armor" : 0);
  if (err)
    return mk_error (General_Error);	/* FIXME */
  _gpgme_io_close (gpgsm->message_fd);

  return 0;
}

GpgmeError
_gpgme_gpgsm_op_trustlist (GpgsmObject gpgsm, const char *pattern)
{
  /* FIXME */
  return mk_error (Not_Implemented);
}

GpgmeError
_gpgme_gpgsm_op_verify (GpgsmObject gpgsm, GpgmeData sig, GpgmeData text)
{
  AssuanError err;

  if (!gpgsm)
    return mk_error (Invalid_Value);

  gpgsm->command = xtrystrdup ("VERIFY");
  if (!gpgsm->command)
    return mk_error (Out_Of_Core);

  gpgsm->input_data = sig;
  err = gpgsm_set_fd (gpgsm->assuan_ctx, "INPUT", gpgsm->input_fd_server, 0);
  if (err)
    return mk_error (General_Error);	/* FIXME */
  gpgsm->message_data = text;
  err = gpgsm_set_fd (gpgsm->assuan_ctx, "MESSAGE", gpgsm->message_fd_server,
		      0);
  if (err)
    return mk_error (General_Error);	/* FIXME */
  _gpgme_io_close (gpgsm->output_fd);

  return 0;
}

static int
status_cmp (const void *ap, const void *bp)
{
  const struct status_table_s *a = ap;
  const struct status_table_s *b = bp;

  return strcmp (a->name, b->name);
}

static int
gpgsm_status_handler (void *opaque, int pid, int fd)
{
  int err;
  GpgsmObject gpgsm = opaque;
  char *line;
  size_t linelen;

  do
    {
      err = assuan_read_line (gpgsm->assuan_ctx, &line, &linelen);

      if (err
          || (linelen >= 2
              && line[0] == 'O' && line[1] == 'K'
              && (line[2] == '\0' || line[2] == ' '))
	  || (linelen >= 3
	      && line[0] == 'E' && line[1] == 'R' && line[2] == 'R'
	      && (line[3] == '\0' || line[3] == ' ')))
	{
	  /* FIXME Save error somewhere.  */
	  if (gpgsm->status.fnc)
	    gpgsm->status.fnc (gpgsm->status.fnc_value, STATUS_EOF, "");
	  return 1;
	}

      if (linelen > 2
	  && line[0] == 'D' && line[1] == ' '
          && gpgsm->colon.fnc)
        {
	  /* We are using the colon handler even for plain inline data
             - strange name for that function but for historic reasons
             we keep it.  */
          /* FIXME We can't use this for binary data because we
             assume this is a string.  For the current usage of colon
             output it is correct.  */
          unsigned char *src = line + 2;
	  unsigned char *end = line + linelen;
	  unsigned char *dst;
          unsigned char **aline = &gpgsm->colon.attic.line;
	  int *alinelen = &gpgsm->colon.attic.linelen;

	  if (gpgsm->colon.attic.linesize
	      < *alinelen + linelen + 1)
	    {
	      unsigned char *newline = xtryrealloc (*aline,
						    *alinelen + linelen + 1);
	      if (!newline)
		return mk_error (Out_Of_Core);
	      *aline = newline;
	      gpgsm->colon.attic.linesize += linelen + 1;
	    }

	  dst = *aline + *alinelen;

          while (src < end)
            {
              if (*src == '%' && src + 2 < end)
                {
		  /* Handle escaped characters.  */
		  ++src;
                  *dst = xtoi_2 (src);
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

		  if (*alinelen > 1 && *(dst - 1) == '\r')
		    dst--;
		  *dst = '\0';

		  /* FIXME How should we handle the return code? */
		  gpgsm->colon.fnc (gpgsm->colon.fnc_value, *aline);
		  dst = *aline;
		  *alinelen = 0;
		}
	      else
		dst++;
            }
        }
      else if (linelen > 2
	  && line[0] == 'S' && line[1] == ' ')
	{
	  struct status_table_s t, *r;
	  char *rest;
	  
	  rest = strchr (line + 2, ' ');
	  if (!rest)
	    rest = line + linelen; /* set to an empty string */
	  else
	    *rest++ = 0;

	  t.name = line + 2;
	  r = bsearch (&t, status_table, DIM(status_table) - 1,
		       sizeof t, status_cmp);

	  if (r)
	    {
	      if (gpgsm->status.fnc)
		gpgsm->status.fnc (gpgsm->status.fnc_value, r->code, rest);
	    }
	  else
	    fprintf (stderr, "[UNKNOWN STATUS]%s %s", t.name, rest);
	}
    }
  while (assuan_pending_line (gpgsm->assuan_ctx));
  
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

void
_gpgme_gpgsm_set_colon_line_handler (GpgsmObject gpgsm,
                                     GpgColonLineHandler fnc, void *fnc_value) 
{
  assert (gpgsm);

  gpgsm->colon.fnc = fnc;
  gpgsm->colon.fnc_value = fnc_value;
}

GpgmeError
_gpgme_gpgsm_start (GpgsmObject gpgsm, void *opaque)
{
  GpgmeError err = 0;
  pid_t pid;
  int fdlist[5];
  int nfds;

  if (!gpgsm)
    return mk_error (Invalid_Value);

  pid = assuan_get_pid (gpgsm->assuan_ctx);

  /* We need to know the fd used by assuan for reads.  We do this by
     using the assumption that the first returned fd from
     assuan_get_active_fds() is always this one. */
  nfds = assuan_get_active_fds (gpgsm->assuan_ctx, 0 /* read fds */,
                                fdlist, DIM (fdlist));
  if (nfds < 1)
    return mk_error (General_Error);
  err = _gpgme_register_pipe_handler (opaque, gpgsm_status_handler, gpgsm, pid,
                                      fdlist[0], 1);


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
    err = assuan_write_line (gpgsm->assuan_ctx, gpgsm->command);

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
_gpgme_gpgsm_op_decrypt (GpgsmObject gpgsm, GpgmeData ciph, GpgmeData plain)
{
  return mk_error (Invalid_Engine);
}

GpgmeError
_gpgme_gpgsm_op_delete (GpgsmObject gpgsm, GpgmeKey key, int allow_secret)
{
  return mk_error (Invalid_Engine);
}

GpgmeError
_gpgme_gpgsm_op_encrypt (GpgsmObject gpgsm, GpgmeRecipients recp,
			 GpgmeData plain, GpgmeData ciph, int use_armor)
{
  return mk_error (Invalid_Engine);
}

GpgmeError
_gpgme_gpgsm_op_export (GpgsmObject gpgsm, GpgmeRecipients recp,
			GpgmeData keydata, int use_armor)
{
  return mk_error (Invalid_Engine);
}

GpgmeError
_gpgme_gpgsm_op_genkey (GpgsmObject gpgsm, GpgmeData help_data, int use_armor)
{
  return mk_error (Invalid_Engine);
}
  
GpgmeError
_gpgme_gpgsm_op_import (GpgsmObject gpgsm, GpgmeData keydata)
{
  return mk_error (Invalid_Engine);
}

GpgmeError
_gpgme_gpgsm_op_keylist (GpgsmObject gpgsm, const char *pattern,
			 int secret_only, int keylist_mode)
{
  return mk_error (Invalid_Engine);
}

GpgmeError
_gpgme_gpgsm_op_sign (GpgsmObject gpgsm, GpgmeData in, GpgmeData out,
		      GpgmeSigMode mode, int use_armor,
		      int use_textmode, GpgmeCtx ctx /* FIXME */)
{
  return mk_error (Invalid_Engine);
}

GpgmeError
_gpgme_gpgsm_op_trustlist (GpgsmObject gpgsm, const char *pattern)
{
  return mk_error (Invalid_Engine);
}

GpgmeError
_gpgme_gpgsm_op_verify (GpgsmObject gpgsm, GpgmeData sig, GpgmeData text)
{
  return mk_error (Invalid_Engine);
}

void
_gpgme_gpgsm_set_colon_line_handler (GpgsmObject gpgsm,
                                     GpgColonLineHandler fnc, void *fnc_value) 
{
}

GpgmeError
_gpgme_gpgsm_start (GpgsmObject gpgsm, void *opaque)
{
  return mk_error (Invalid_Engine);
}

#endif	/* ! ENABLE_GPGSM */
