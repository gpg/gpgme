/* engine-gpgsm.c - GpgSM engine.
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

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <assert.h>
#include <unistd.h>
#include <locale.h>
#include <fcntl.h> /* FIXME */
#include <errno.h>

#include "gpgme.h"
#include "util.h"
#include "ops.h"
#include "wait.h"
#include "io.h"
#include "sema.h"

#include "assuan.h"
#include "status-table.h"

#include "engine-backend.h"


typedef struct
{
  int fd;	/* FD we talk about.  */
  int dir;	/* Inbound/Outbound, maybe given implicit?  */
  void *data;	/* Handler-specific data.  */
  void *tag;	/* ID from the user for gpgme_remove_io_callback.  */
} iocb_data_t;


struct engine_gpgsm
{
  ASSUAN_CONTEXT assuan_ctx;

  iocb_data_t status_cb;

  /* Input, output etc are from the servers perspective.  */
  iocb_data_t input_cb;
  int input_fd_server;

  iocb_data_t output_cb;
  int output_fd_server;

  iocb_data_t message_cb;
  int message_fd_server;

  struct
  {
    engine_status_handler_t fnc;
    void *fnc_value;
  } status;

  struct
  {
    engine_colon_line_handler_t fnc;
    void *fnc_value;
    struct
    {
      unsigned char *line;
      int linesize;
      int linelen;
    } attic;
    int any; /* any data line seen */
  } colon; 

  struct gpgme_io_cbs io_cbs;
};

typedef struct engine_gpgsm *engine_gpgsm_t;


static const char *
gpgsm_get_version (void)
{
  static const char *gpgsm_version;
  DEFINE_STATIC_LOCK (gpgsm_version_lock);

  LOCK (gpgsm_version_lock);
  if (!gpgsm_version)
    gpgsm_version = _gpgme_get_program_version (_gpgme_get_gpgsm_path ());
  UNLOCK (gpgsm_version_lock);

  return gpgsm_version;
}


static const char *
gpgsm_get_req_version (void)
{
  return NEED_GPGSM_VERSION;
}


static void
close_notify_handler (int fd, void *opaque)
{
  engine_gpgsm_t gpgsm = opaque;

  assert (fd != -1);
  if (gpgsm->status_cb.fd == fd)
    {
      if (gpgsm->status_cb.tag)
	(*gpgsm->io_cbs.remove) (gpgsm->status_cb.tag);
      gpgsm->status_cb.fd = -1;
    }
  else if (gpgsm->input_cb.fd == fd)
    {
      if (gpgsm->input_cb.tag)
	(*gpgsm->io_cbs.remove) (gpgsm->input_cb.tag);
      gpgsm->input_cb.fd = -1;
    }
  else if (gpgsm->output_cb.fd == fd)
    {
      if (gpgsm->output_cb.tag)
	(*gpgsm->io_cbs.remove) (gpgsm->output_cb.tag);
      gpgsm->output_cb.fd = -1;
    }
  else if (gpgsm->message_cb.fd == fd)
    {
      if (gpgsm->message_cb.tag)
	(*gpgsm->io_cbs.remove) (gpgsm->message_cb.tag);
      gpgsm->message_cb.fd = -1;
    }
}


static gpgme_error_t
map_assuan_error (AssuanError err)
{
  if (err == -1)
    return gpg_error (GPG_ERR_INV_ENGINE);

  /* New code will use gpg_error_t values.  */
  if (gpg_err_source (err))
    return (gpgme_error_t) err;

  /* Legacy code will use old values.  */
  switch (err)
    {
    case ASSUAN_No_Error:
      return gpg_error (GPG_ERR_NO_ERROR);
    case ASSUAN_General_Error:
      return gpg_error (GPG_ERR_GENERAL);
    case ASSUAN_Out_Of_Core:
      return gpg_error (GPG_ERR_ENOMEM);
    case ASSUAN_Invalid_Value:
      return gpg_error (GPG_ERR_INV_VALUE);
    case ASSUAN_Timeout:
      return gpg_error (GPG_ERR_ETIMEDOUT);
    case ASSUAN_Read_Error:
      return gpg_error (GPG_ERR_GENERAL);
    case ASSUAN_Write_Error:
      return gpg_error (GPG_ERR_GENERAL);

    case ASSUAN_Problem_Starting_Server:
    case ASSUAN_Not_A_Server:
    case ASSUAN_Not_A_Client:
    case ASSUAN_Nested_Commands:
    case ASSUAN_No_Data_Callback:
    case ASSUAN_No_Inquire_Callback:
    case ASSUAN_Connect_Failed:
    case ASSUAN_Accept_Failed:
    case ASSUAN_Invalid_Command:
    case ASSUAN_Unknown_Command:
    case ASSUAN_Syntax_Error:
    case ASSUAN_Parameter_Error:
    case ASSUAN_Parameter_Conflict:
    case ASSUAN_No_Input:
    case ASSUAN_No_Output:
    case ASSUAN_No_Data_Available:
    case ASSUAN_Too_Much_Data:
    case ASSUAN_Inquire_Unknown:
    case ASSUAN_Inquire_Error:
    case ASSUAN_Invalid_Option:
    case ASSUAN_Unexpected_Status:
    case ASSUAN_Unexpected_Data:
    case ASSUAN_Invalid_Status:
      return gpg_error (GPG_ERR_ASSUAN);

    case ASSUAN_Invalid_Response:
      return gpg_error (GPG_ERR_INV_RESPONSE);

    case ASSUAN_Not_Implemented:
      return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
    case ASSUAN_Line_Too_Long:
      return gpg_error (GPG_ERR_LINE_TOO_LONG);
    case ASSUAN_Line_Not_Terminated:
      return gpg_error (GPG_ERR_INCOMPLETE_LINE);
    case ASSUAN_Canceled:
      return gpg_error (GPG_ERR_CANCELED);

    case ASSUAN_Unsupported_Algorithm:
      return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);
    case ASSUAN_Server_Resource_Problem:
      return gpg_error (GPG_ERR_RESOURCE_LIMIT);
    case ASSUAN_Server_IO_Error:
      return gpg_error (GPG_ERR_GENERAL);
    case ASSUAN_Server_Bug:
      return gpg_error (GPG_ERR_BUG);
    case ASSUAN_Invalid_Data:
      return gpg_error (GPG_ERR_INV_DATA);
    case ASSUAN_Invalid_Index:
      return gpg_error (GPG_ERR_INV_INDEX);
    case ASSUAN_Not_Confirmed:
      return gpg_error (GPG_ERR_NOT_CONFIRMED);
    case ASSUAN_Bad_Certificate:
      return gpg_error (GPG_ERR_BAD_CERT);
    case ASSUAN_Bad_Certificate_Chain:
      return gpg_error (GPG_ERR_BAD_CERT_CHAIN);
    case ASSUAN_Missing_Certificate:
      return gpg_error (GPG_ERR_MISSING_CERT);
    case ASSUAN_Bad_Signature:
      return gpg_error (GPG_ERR_BAD_SIGNATURE);
    case ASSUAN_No_Agent:
      return gpg_error (GPG_ERR_NO_AGENT);
    case ASSUAN_Agent_Error:
      return gpg_error (GPG_ERR_AGENT);
    case ASSUAN_No_Public_Key:
      return gpg_error (GPG_ERR_NO_PUBKEY);
    case ASSUAN_No_Secret_Key:
      return gpg_error (GPG_ERR_NO_SECKEY);
    case ASSUAN_Invalid_Name:
      return gpg_error (GPG_ERR_INV_NAME);
      
    case ASSUAN_Cert_Revoked:
      return gpg_error (GPG_ERR_CERT_REVOKED);
    case ASSUAN_No_CRL_For_Cert:
      return gpg_error (GPG_ERR_NO_CRL_KNOWN);
    case ASSUAN_CRL_Too_Old:
      return gpg_error (GPG_ERR_CRL_TOO_OLD);
    case ASSUAN_Not_Trusted:
      return gpg_error (GPG_ERR_NOT_TRUSTED);

    case ASSUAN_Card_Error:
      return gpg_error (GPG_ERR_CARD);
    case ASSUAN_Invalid_Card:
      return gpg_error (GPG_ERR_INV_CARD);
    case ASSUAN_No_PKCS15_App:
      return gpg_error (GPG_ERR_NO_PKCS15_APP);
    case ASSUAN_Card_Not_Present:
      return gpg_error (GPG_ERR_CARD_NOT_PRESENT);
    case ASSUAN_Invalid_Id:
      return gpg_error (GPG_ERR_INV_ID);
    default:
      return gpg_error (GPG_ERR_GENERAL);
    }
}


static void
gpgsm_release (void *engine)
{
  engine_gpgsm_t gpgsm = engine;

  if (!gpgsm)
    return;

  if (gpgsm->status_cb.fd != -1)
    _gpgme_io_close (gpgsm->status_cb.fd);
  if (gpgsm->input_cb.fd != -1)
    _gpgme_io_close (gpgsm->input_cb.fd);
  if (gpgsm->output_cb.fd != -1)
    _gpgme_io_close (gpgsm->output_cb.fd);
  if (gpgsm->message_cb.fd != -1)
    _gpgme_io_close (gpgsm->message_cb.fd);

  assuan_disconnect (gpgsm->assuan_ctx);

  free (gpgsm->colon.attic.line);
  free (gpgsm);
}


static gpgme_error_t
gpgsm_new (void **engine, const char *lc_ctype, const char *lc_messages)
{
  gpgme_error_t err = 0;
  engine_gpgsm_t gpgsm;
  char *argv[3];
  int fds[2];
  int child_fds[4];
  char *dft_display = NULL;
  char dft_ttyname[64];
  char *dft_ttytype = NULL;
  char *optstr;
  int fdlist[5];
  int nfds;

  gpgsm = calloc (1, sizeof *gpgsm);
  if (!gpgsm)
    return gpg_error_from_errno (errno);

  gpgsm->status_cb.fd = -1;
  gpgsm->status_cb.tag = 0;

  gpgsm->input_cb.fd = -1;
  gpgsm->input_cb.tag = 0;
  gpgsm->input_fd_server = -1;
  gpgsm->output_cb.fd = -1;
  gpgsm->output_cb.tag = 0;
  gpgsm->output_fd_server = -1;
  gpgsm->message_cb.fd = -1;
  gpgsm->message_cb.tag = 0;
  gpgsm->message_fd_server = -1;

  gpgsm->status.fnc = 0;
  gpgsm->colon.fnc = 0;
  gpgsm->colon.attic.line = 0;
  gpgsm->colon.attic.linesize = 0;
  gpgsm->colon.attic.linelen = 0;
  gpgsm->colon.any = 0;

  gpgsm->io_cbs.add = NULL;
  gpgsm->io_cbs.add_priv = NULL;
  gpgsm->io_cbs.remove = NULL;
  gpgsm->io_cbs.event = NULL;
  gpgsm->io_cbs.event_priv = NULL;

  if (_gpgme_io_pipe (fds, 0) < 0)
    {
      err = gpg_error_from_errno (errno);
      goto leave;
    }
  gpgsm->input_cb.fd = fds[1];
  gpgsm->input_cb.dir = 0;
  gpgsm->input_fd_server = fds[0];

  if (_gpgme_io_pipe (fds, 1) < 0)
    {
      err = gpg_error_from_errno (errno);
      goto leave;
    }
  gpgsm->output_cb.fd = fds[0];
  gpgsm->output_cb.dir = 1;
  gpgsm->output_fd_server = fds[1];

  if (_gpgme_io_pipe (fds, 0) < 0)
    {
      err = gpg_error_from_errno (errno);
      goto leave;
    }
  gpgsm->message_cb.fd = fds[1];
  gpgsm->message_cb.dir = 0;
  gpgsm->message_fd_server = fds[0];

  child_fds[0] = gpgsm->input_fd_server;
  child_fds[1] = gpgsm->output_fd_server;
  child_fds[2] = gpgsm->message_fd_server;
  child_fds[3] = -1;

  argv[0] = "gpgsm";
  argv[1] = "--server";
  argv[2] = NULL;

  err = assuan_pipe_connect (&gpgsm->assuan_ctx,
			     _gpgme_get_gpgsm_path (), argv, child_fds);

  /* We need to know the fd used by assuan for reads.  We do this by
     using the assumption that the first returned fd from
     assuan_get_active_fds() is always this one.  */
  nfds = assuan_get_active_fds (gpgsm->assuan_ctx, 0 /* read fds */,
                                fdlist, DIM (fdlist));
  if (nfds < 1)
    {
      err = gpg_error (GPG_ERR_GENERAL);	/* FIXME */
      goto leave;
    }
  /* We duplicate the file descriptor, so we can close it without
     disturbing assuan.  Alternatively, we could special case
     status_fd and register/unregister it manually as needed, but this
     increases code duplication and is more complicated as we can not
     use the close notifications etc.  */
  gpgsm->status_cb.fd = dup (fdlist[0]);
  if (gpgsm->status_cb.fd < 0)
    {
      err = gpg_error (GPG_ERR_GENERAL);	/* FIXME */
      goto leave;
    }
  gpgsm->status_cb.dir = 1;
  gpgsm->status_cb.data = gpgsm;

  err = _gpgme_getenv ("DISPLAY", &dft_display);
  if (err)
    goto leave;
  if (dft_display)
    {
      if (asprintf (&optstr, "OPTION display=%s", dft_display) < 0)
        {
	  free (dft_display);
	  err = gpg_error_from_errno (errno);
	  goto leave;
	}
      free (dft_display);

      err = assuan_transact (gpgsm->assuan_ctx, optstr, NULL, NULL, NULL,
			     NULL, NULL, NULL);
      free (optstr);
      if (err)
	{
	  err = map_assuan_error (err);
	  goto leave;
	}
    }

  if (ttyname_r (1, dft_ttyname, sizeof (dft_ttyname)))
    {
      err = gpg_error_from_errno (errno);
      goto leave;
    }
  else
    {
      if (asprintf (&optstr, "OPTION ttyname=%s", dft_ttyname) < 0)
        {
	  err = gpg_error_from_errno (errno);
	  goto leave;
	}
      err = assuan_transact (gpgsm->assuan_ctx, optstr, NULL, NULL, NULL,
			     NULL, NULL, NULL);
      free (optstr);
      if (err)
	{
	  err = map_assuan_error (err);
	  goto leave;
	}

      err = _gpgme_getenv ("TERM", &dft_ttytype);
      if (err)
	goto leave;
      if (dft_ttytype)
	{
	  if (asprintf (&optstr, "OPTION ttytype=%s", dft_ttytype) < 0)
	    {
	      free (dft_ttytype);
	      err = gpg_error_from_errno (errno);
	      goto leave;
	    }
	  free (dft_ttytype);

	  err = assuan_transact (gpgsm->assuan_ctx, optstr, NULL, NULL, NULL,
				 NULL, NULL, NULL);
	  free (optstr);
	  if (err)
	    {
	      err = map_assuan_error (err);
	      goto leave;
	    }
	}

      if (lc_ctype)
	{
	  if (asprintf (&optstr, "OPTION lc-ctype=%s", lc_ctype) < 0)
	    err = gpg_error_from_errno (errno);
	  else
	    {
	      err = assuan_transact (gpgsm->assuan_ctx, optstr, NULL, NULL,
				     NULL, NULL, NULL, NULL);
	      free (optstr);
	      if (err)
		err = map_assuan_error (err);
	    }
	}
      if (err)
	goto leave;

      if (lc_messages)
	{
	  if (asprintf (&optstr, "OPTION lc-messages=%s", lc_messages) < 0)
	    err = gpg_error_from_errno (errno);
	  else
	    {
	      err = assuan_transact (gpgsm->assuan_ctx, optstr, NULL, NULL,
				     NULL, NULL, NULL, NULL);
	      free (optstr);
	      if (err)
		err = map_assuan_error (err);
	    }
	}
      if (err)
	goto leave;
    }

  if (!err
      && (_gpgme_io_set_close_notify (gpgsm->status_cb.fd,
				      close_notify_handler, gpgsm)
	  || _gpgme_io_set_close_notify (gpgsm->input_cb.fd,
					 close_notify_handler, gpgsm)
	  || _gpgme_io_set_close_notify (gpgsm->output_cb.fd,
					 close_notify_handler, gpgsm)
	  || _gpgme_io_set_close_notify (gpgsm->message_cb.fd,
					 close_notify_handler, gpgsm)))
    {
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }
      
 leave:
  /* Close the server ends of the pipes.  Our ends are closed in
     gpgsm_release().  */
  if (gpgsm->input_fd_server != -1)
    _gpgme_io_close (gpgsm->input_fd_server);
  if (gpgsm->output_fd_server != -1)
    _gpgme_io_close (gpgsm->output_fd_server);
  if (gpgsm->message_fd_server != -1)
    _gpgme_io_close (gpgsm->message_fd_server);

  if (err)
    gpgsm_release (gpgsm);
  else
    *engine = gpgsm;

  return err;
}


/* Forward declaration.  */
static gpgme_status_code_t parse_status (const char *name);

static gpgme_error_t
gpgsm_assuan_simple_command (ASSUAN_CONTEXT ctx, char *cmd,
			     engine_status_handler_t status_fnc,
			     void *status_fnc_value)
{
  AssuanError err;
  char *line;
  size_t linelen;

  err = assuan_write_line (ctx, cmd);
  if (err)
    return map_assuan_error (err);

  do
    {
      err = assuan_read_line (ctx, &line, &linelen);
      if (err)
	return map_assuan_error (err);

      if (*line == '#' || !linelen)
	continue;

      if (linelen >= 2
	  && line[0] == 'O' && line[1] == 'K'
	  && (line[2] == '\0' || line[2] == ' '))
	return 0;
      else if (linelen >= 4
	  && line[0] == 'E' && line[1] == 'R' && line[2] == 'R'
	  && line[3] == ' ')
	err = map_assuan_error (atoi (&line[4]));
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

	  r = parse_status (line + 2);

	  if (r >= 0 && status_fnc)
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


#define COMMANDLINELEN 40
static gpgme_error_t
gpgsm_set_fd (ASSUAN_CONTEXT ctx, const char *which, int fd, const char *opt)
{
  char line[COMMANDLINELEN];

  if (opt)
    snprintf (line, COMMANDLINELEN, "%s FD=%i %s", which, fd, opt);
  else
    snprintf (line, COMMANDLINELEN, "%s FD=%i", which, fd);

  return gpgsm_assuan_simple_command (ctx, line, NULL, NULL);
}


static const char *
map_input_enc (gpgme_data_t d)
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


static int
status_cmp (const void *ap, const void *bp)
{
  const struct status_table_s *a = ap;
  const struct status_table_s *b = bp;

  return strcmp (a->name, b->name);
}


static gpgme_status_code_t
parse_status (const char *name)
{
  struct status_table_s t, *r;
  t.name = name;
  r = bsearch (&t, status_table, DIM(status_table) - 1,
	       sizeof t, status_cmp);
  return r ? r->code : -1;
}


static gpgme_error_t
status_handler (void *opaque, int fd)
{
  AssuanError assuan_err;
  gpgme_error_t err = 0;
  engine_gpgsm_t gpgsm = opaque;
  char *line;
  size_t linelen;

  do
    {
      assuan_err = assuan_read_line (gpgsm->assuan_ctx, &line, &linelen);
      if (assuan_err)
	{
	  /* Try our best to terminate the connection friendly.  */
	  /*	  assuan_write_line (gpgsm->assuan_ctx, "BYE"); */
	  err = map_assuan_error (assuan_err);
	}
      else if (linelen >= 3
	       && line[0] == 'E' && line[1] == 'R' && line[2] == 'R'
	       && (line[3] == '\0' || line[3] == ' '))
	{
	  if (line[3] == ' ')
	    err = map_assuan_error (atoi (&line[4]));
	  else
	    err = gpg_error (GPG_ERR_GENERAL);
	}
      else if (linelen >= 2
	       && line[0] == 'O' && line[1] == 'K'
	       && (line[2] == '\0' || line[2] == ' '))
	{
	  if (gpgsm->status.fnc)
	    err = gpgsm->status.fnc (gpgsm->status.fnc_value,
				     GPGME_STATUS_EOF, "");
	  
	  if (!err && gpgsm->colon.fnc && gpgsm->colon.any )
            {
              /* We must tell a colon function about the EOF. We do
                 this only when we have seen any data lines.  Note
                 that this inlined use of colon data lines will
                 eventually be changed into using a regular data
                 channel. */
              gpgsm->colon.any = 0;
              err = gpgsm->colon.fnc (gpgsm->colon.fnc_value, NULL);
            }
	  _gpgme_io_close (gpgsm->status_cb.fd);
	  return err;
	}
      else if (linelen > 2
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
	      unsigned char *newline = realloc (*aline,
						*alinelen + linelen + 1);
	      if (!newline)
		err = gpg_error_from_errno (errno);
	      else
		{
		  *aline = newline;
		  gpgsm->colon.attic.linesize += linelen + 1;
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
		      *dst = (unsigned char) _gpgme_hextobyte (src);
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
		      
		      gpgsm->colon.any = 1;
		      if (*alinelen > 1 && *(dst - 1) == '\r')
			dst--;
		      *dst = '\0';

		      /* FIXME How should we handle the return code?  */
		      err = gpgsm->colon.fnc (gpgsm->colon.fnc_value, *aline);
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

	  r = parse_status (line + 2);

	  if (r >= 0)
	    {
	      if (gpgsm->status.fnc)
		err = gpgsm->status.fnc (gpgsm->status.fnc_value, r, rest);
	    }
	  else
	    fprintf (stderr, "[UNKNOWN STATUS]%s %s", line + 2, rest);
	}
    }
  while (!err && assuan_pending_line (gpgsm->assuan_ctx));
	  
  return err;
}


static gpgme_error_t
add_io_cb (engine_gpgsm_t gpgsm, iocb_data_t *iocbd, gpgme_io_cb_t handler)
{
  gpgme_error_t err;

  err = (*gpgsm->io_cbs.add) (gpgsm->io_cbs.add_priv,
			      iocbd->fd, iocbd->dir,
			      handler, iocbd->data, &iocbd->tag);
  if (err)
    return err;
  if (!iocbd->dir)
    /* FIXME Kludge around poll() problem.  */
    err = _gpgme_io_set_nonblocking (iocbd->fd);
  return err;
}


static gpgme_error_t
start (engine_gpgsm_t gpgsm, const char *command)
{
  gpgme_error_t err;

  err = add_io_cb (gpgsm, &gpgsm->status_cb, status_handler);
  if (!err && gpgsm->input_cb.fd != -1)
    err = add_io_cb (gpgsm, &gpgsm->input_cb, _gpgme_data_outbound_handler);
  if (!err && gpgsm->output_cb.fd != -1)
    err = add_io_cb (gpgsm, &gpgsm->output_cb, _gpgme_data_inbound_handler);
  if (!err && gpgsm->message_cb.fd != -1)
    err = add_io_cb (gpgsm, &gpgsm->message_cb, _gpgme_data_outbound_handler);

  if (!err)
    err = assuan_write_line (gpgsm->assuan_ctx, command);

  if (!err)
    (*gpgsm->io_cbs.event) (gpgsm->io_cbs.event_priv, GPGME_EVENT_START, NULL);

  return err;
}


static gpgme_error_t
gpgsm_decrypt (void *engine, gpgme_data_t ciph, gpgme_data_t plain)
{
  engine_gpgsm_t gpgsm = engine;
  gpgme_error_t err;

  if (!gpgsm)
    return gpg_error (GPG_ERR_INV_VALUE);

  gpgsm->input_cb.data = ciph;
  err = gpgsm_set_fd (gpgsm->assuan_ctx, "INPUT", gpgsm->input_fd_server, 
                      map_input_enc (gpgsm->input_cb.data));
  if (err)
    return gpg_error (GPG_ERR_GENERAL);	/* FIXME */
  gpgsm->output_cb.data = plain;
  err = gpgsm_set_fd (gpgsm->assuan_ctx, "OUTPUT", gpgsm->output_fd_server, 0);
  if (err)
    return gpg_error (GPG_ERR_GENERAL);	/* FIXME */
  _gpgme_io_close (gpgsm->message_cb.fd);

  err = start (engine, "DECRYPT");
  return err;
}


static gpgme_error_t
gpgsm_delete (void *engine, gpgme_key_t key, int allow_secret)
{
  engine_gpgsm_t gpgsm = engine;
  gpgme_error_t err;
  char *fpr = key->subkeys ? key->subkeys->fpr : NULL;
  char *linep = fpr;
  char *line;
  int length = 8;	/* "DELKEYS " */

  if (!fpr)
    return gpg_error (GPG_ERR_INV_VALUE);

  while (*linep)
    {
      length++;
      if (*linep == '%' || *linep == ' ' || *linep == '+')
	length += 2;
      linep++;
    }
  length++;

  line = malloc (length);
  if (!line)
    return gpg_error_from_errno (errno);

  strcpy (line, "DELKEYS ");
  linep = &line[8];

  while (*fpr)
    {
      switch (*fpr)
	{
	case '%':
	  *(linep++) = '%';
	  *(linep++) = '2';
	  *(linep++) = '5';
	  break;
	case ' ':
	  *(linep++) = '%';
	  *(linep++) = '2';
	  *(linep++) = '0';
	  break;
	case '+':
	  *(linep++) = '%';
	  *(linep++) = '2';
	  *(linep++) = 'B';
	  break;
	default:
	  *(linep++) = *fpr;
	  break;
	}
      fpr++;
    }
  *linep = '\0';

  _gpgme_io_close (gpgsm->output_cb.fd);
  _gpgme_io_close (gpgsm->input_cb.fd);
  _gpgme_io_close (gpgsm->message_cb.fd);

  err = start (gpgsm, line);
  free (line);

  return err;
}


static gpgme_error_t
set_recipients (engine_gpgsm_t gpgsm, gpgme_key_t recp[])
{
  gpgme_error_t err = 0;
  ASSUAN_CONTEXT ctx = gpgsm->assuan_ctx;
  char *line;
  int linelen;
  int invalid_recipients = 0;
  int i = 0;

  linelen = 10 + 40 + 1;	/* "RECIPIENT " + guess + '\0'.  */
  line = malloc (10 + 40 + 1);
  if (!line)
    return gpg_error_from_errno (errno);
  strcpy (line, "RECIPIENT ");
  while (!err && recp[i])
    {
      char *fpr;
      int newlen;

      if (!recp[i]->subkeys || !recp[i]->subkeys->fpr)
	{
	  invalid_recipients++;
	  continue;
	}
      fpr = recp[i]->subkeys->fpr;

      newlen = 11 + strlen (fpr);
      if (linelen < newlen)
	{
	  char *newline = realloc (line, newlen);
	  if (! newline)
	    {
	      int saved_errno = errno;
	      free (line);
	      return gpg_error_from_errno (saved_errno);
	    }
	  line = newline;
	  linelen = newlen;
	}
      strcpy (&line[10], fpr);

      err = gpgsm_assuan_simple_command (ctx, line, gpgsm->status.fnc,
					 gpgsm->status.fnc_value);
      /* FIXME: This requires more work.  */
      if (gpg_err_code (err) == GPG_ERR_NO_PUBKEY)
	invalid_recipients++;
      else if (err)
	{
	  free (line);
	  return err;
	}
      i++;
    }
  free (line);
  return gpg_error (invalid_recipients
		    ? GPG_ERR_UNUSABLE_PUBKEY : GPG_ERR_NO_ERROR);
}


static gpgme_error_t
gpgsm_encrypt (void *engine, gpgme_key_t recp[], gpgme_encrypt_flags_t flags,
	       gpgme_data_t plain, gpgme_data_t ciph, int use_armor)
{
  engine_gpgsm_t gpgsm = engine;
  gpgme_error_t err;

  if (!gpgsm)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!recp)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  gpgsm->input_cb.data = plain;
  err = gpgsm_set_fd (gpgsm->assuan_ctx, "INPUT", gpgsm->input_fd_server,
                      map_input_enc (gpgsm->input_cb.data));
  if (err)
    return err;
  gpgsm->output_cb.data = ciph;
  err = gpgsm_set_fd (gpgsm->assuan_ctx, "OUTPUT", gpgsm->output_fd_server,
		      use_armor ? "--armor" : 0);
  if (err)
    return err;
  _gpgme_io_close (gpgsm->message_cb.fd);

  err = set_recipients (gpgsm, recp);

  if (!err)
    err = start (gpgsm, "ENCRYPT");

  return err;
}


static gpgme_error_t
gpgsm_export (void *engine, const char *pattern, unsigned int reserved,
	      gpgme_data_t keydata, int use_armor)
{
  engine_gpgsm_t gpgsm = engine;
  gpgme_error_t err = 0;
  char *cmd;

  if (!gpgsm || reserved)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!pattern)
    pattern = "";

  cmd = malloc (7 + strlen (pattern) + 1);
  if (!cmd)
    return gpg_error_from_errno (errno);
  strcpy (cmd, "EXPORT ");
  strcpy (&cmd[7], pattern);

  gpgsm->output_cb.data = keydata;
  err = gpgsm_set_fd (gpgsm->assuan_ctx, "OUTPUT", gpgsm->output_fd_server,
		      use_armor ? "--armor" : 0);
  if (err)
    return err;
  _gpgme_io_close (gpgsm->input_cb.fd);
  _gpgme_io_close (gpgsm->message_cb.fd);

  err = start (gpgsm, cmd);
  free (cmd);
  return err;
}


static gpgme_error_t
gpgsm_export_ext (void *engine, const char *pattern[], unsigned int reserved,
		  gpgme_data_t keydata, int use_armor)
{
  engine_gpgsm_t gpgsm = engine;
  gpgme_error_t err = 0;
  char *line;
  /* Length is "EXPORT " + p + '\0'.  */
  int length = 7 + 1;
  char *linep;

  if (!gpgsm || reserved)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (pattern && *pattern)
    {
      const char **pat = pattern;

      while (*pat)
	{
	  const char *patlet = *pat;

	  while (*patlet)
	    {
	      length++;
	      if (*patlet == '%' || *patlet == ' ' || *patlet == '+')
		length += 2;
	      patlet++;
	    }
	  pat++;
	  /* This will allocate one byte more than necessary.  */
	  length++;
	}
    }
  line = malloc (length);
  if (!line)
    return gpg_error_from_errno (errno);

  strcpy (line, "EXPORT ");
  linep = &line[7];

  if (pattern && *pattern)
    {
      while (*pattern)
	{
	  const char *patlet = *pattern;

	  while (*patlet)
	    {
	      switch (*patlet)
		{
		case '%':
		  *(linep++) = '%';
		  *(linep++) = '2';
		  *(linep++) = '5';
		  break;
		case ' ':
		  *(linep++) = '%';
		  *(linep++) = '2';
		  *(linep++) = '0';
		  break;
		case '+':
		  *(linep++) = '%';
		  *(linep++) = '2';
		  *(linep++) = 'B';
		  break;
		default:
		  *(linep++) = *patlet;
		  break;
		}
	      patlet++;
	    }
	  pattern++;
	}
    }
  *linep = '\0';

  gpgsm->output_cb.data = keydata;
  err = gpgsm_set_fd (gpgsm->assuan_ctx, "OUTPUT", gpgsm->output_fd_server,
		      use_armor ? "--armor" : 0);
  if (err)
    return err;
  _gpgme_io_close (gpgsm->input_cb.fd);
  _gpgme_io_close (gpgsm->message_cb.fd);

  err = start (gpgsm, line);
  free (line);
  return err;
}


static gpgme_error_t
gpgsm_genkey (void *engine, gpgme_data_t help_data, int use_armor,
	      gpgme_data_t pubkey, gpgme_data_t seckey)
{
  engine_gpgsm_t gpgsm = engine;
  gpgme_error_t err;

  if (!gpgsm || !pubkey || seckey)
    return gpg_error (GPG_ERR_INV_VALUE);

  gpgsm->input_cb.data = help_data;
  err = gpgsm_set_fd (gpgsm->assuan_ctx, "INPUT", gpgsm->input_fd_server,
                      map_input_enc (gpgsm->input_cb.data));
  if (err)
    return err;
  gpgsm->output_cb.data = pubkey;
  err = gpgsm_set_fd (gpgsm->assuan_ctx, "OUTPUT", gpgsm->output_fd_server,
		      use_armor ? "--armor" : 0);
  if (err)
    return err;
  _gpgme_io_close (gpgsm->message_cb.fd);

  err = start (gpgsm, "GENKEY");
  return err;
}


static gpgme_error_t
gpgsm_import (void *engine, gpgme_data_t keydata)
{
  engine_gpgsm_t gpgsm = engine;
  gpgme_error_t err;

  if (!gpgsm)
    return gpg_error (GPG_ERR_INV_VALUE);

  gpgsm->input_cb.data = keydata;
  err = gpgsm_set_fd (gpgsm->assuan_ctx, "INPUT", gpgsm->input_fd_server,
                      map_input_enc (gpgsm->input_cb.data));
  if (err)
    return err;
  _gpgme_io_close (gpgsm->output_cb.fd);
  _gpgme_io_close (gpgsm->message_cb.fd);

  err = start (gpgsm, "IMPORT");
  return err;
}


static gpgme_error_t
gpgsm_keylist (void *engine, const char *pattern, int secret_only,
	       gpgme_keylist_mode_t mode)
{
  engine_gpgsm_t gpgsm = engine;
  char *line;
  gpgme_error_t err;
  int list_mode = 0;

  if (mode & GPGME_KEYLIST_MODE_LOCAL)
    list_mode |= 1;
  if (mode & GPGME_KEYLIST_MODE_EXTERN)
    list_mode |= 2;

  if (!pattern)
    pattern = "";

  if (asprintf (&line, "OPTION list-mode=%d", (list_mode & 3)) < 0)
    return gpg_error_from_errno (errno);
  err = gpgsm_assuan_simple_command (gpgsm->assuan_ctx, line, NULL, NULL);
  free (line);
  if (err)
    return err;

  /* Length is "LISTSECRETKEYS " + p + '\0'.  */
  line = malloc (15 + strlen (pattern) + 1);
  if (!line)
    return gpg_error_from_errno (errno);
  if (secret_only)
    {
      strcpy (line, "LISTSECRETKEYS ");
      strcpy (&line[15], pattern);
    }
  else
    {
      strcpy (line, "LISTKEYS ");
      strcpy (&line[9], pattern);
    }

  _gpgme_io_close (gpgsm->input_cb.fd);
  _gpgme_io_close (gpgsm->output_cb.fd);
  _gpgme_io_close (gpgsm->message_cb.fd);

  err = start (gpgsm, line);
  free (line);
  return err;
}


static gpgme_error_t
gpgsm_keylist_ext (void *engine, const char *pattern[], int secret_only,
		   int reserved, gpgme_keylist_mode_t mode)
{
  engine_gpgsm_t gpgsm = engine;
  char *line;
  gpgme_error_t err;
  /* Length is "LISTSECRETKEYS " + p + '\0'.  */
  int length = 15 + 1;
  char *linep;
  int list_mode = 0;

  if (reserved)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (mode & GPGME_KEYLIST_MODE_LOCAL)
    list_mode |= 1;
  if (mode & GPGME_KEYLIST_MODE_EXTERN)
    list_mode |= 2;

  if (asprintf (&line, "OPTION list-mode=%d", (list_mode & 3)) < 0)
    return gpg_error_from_errno (errno);
  err = gpgsm_assuan_simple_command (gpgsm->assuan_ctx, line, NULL, NULL);
  free (line);
  if (err)
    return err;

  if (pattern && *pattern)
    {
      const char **pat = pattern;

      while (*pat)
	{
	  const char *patlet = *pat;

	  while (*patlet)
	    {
	      length++;
	      if (*patlet == '%' || *patlet == ' ' || *patlet == '+')
		length += 2;
	      patlet++;
	    }
	  pat++;
	  /* This will allocate one byte more than necessary.  */
	  length++;
	}
    }
  line = malloc (length);
  if (!line)
    return gpg_error_from_errno (errno);
  if (secret_only)
    {
      strcpy (line, "LISTSECRETKEYS ");
      linep = &line[15];
    }
  else
    {
      strcpy (line, "LISTKEYS ");
      linep = &line[9];
    }

  if (pattern && *pattern)
    {
      while (*pattern)
	{
	  const char *patlet = *pattern;

	  while (*patlet)
	    {
	      switch (*patlet)
		{
		case '%':
		  *(linep++) = '%';
		  *(linep++) = '2';
		  *(linep++) = '5';
		  break;
		case ' ':
		  *(linep++) = '%';
		  *(linep++) = '2';
		  *(linep++) = '0';
		  break;
		case '+':
		  *(linep++) = '%';
		  *(linep++) = '2';
		  *(linep++) = 'B';
		  break;
		default:
		  *(linep++) = *patlet;
		  break;
		}
	      patlet++;
	    }
	  pattern++;
	}
    }
  *linep = '\0';

  _gpgme_io_close (gpgsm->input_cb.fd);
  _gpgme_io_close (gpgsm->output_cb.fd);
  _gpgme_io_close (gpgsm->message_cb.fd);

  err = start (gpgsm, line);
  free (line);
  return err;
}


static gpgme_error_t
gpgsm_sign (void *engine, gpgme_data_t in, gpgme_data_t out,
	    gpgme_sig_mode_t mode, int use_armor, int use_textmode,
	    int include_certs, gpgme_ctx_t ctx /* FIXME */)
{
  engine_gpgsm_t gpgsm = engine;
  gpgme_error_t err;
  char *assuan_cmd;
  int i;
  gpgme_key_t key;

  if (!gpgsm)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (asprintf (&assuan_cmd, "OPTION include-certs %i", include_certs) < 0)
    return gpg_error_from_errno (errno);
  err = gpgsm_assuan_simple_command (gpgsm->assuan_ctx, assuan_cmd, NULL,NULL);
  free (assuan_cmd);
  if (err)
    return err;

  /* We must do a reset becuase we need to reset the list of signers.  Note
     that RESET does not reset OPTION commands. */
  err = gpgsm_assuan_simple_command (gpgsm->assuan_ctx, "RESET", NULL, NULL);
  if (err)
    return err;

  for (i = 0; (key = gpgme_signers_enum (ctx, i)); i++)
    {
      const char *s = key->subkeys ? key->subkeys->fpr : NULL;
      if (s && strlen (s) < 80)
	{
          char buf[100];

          strcpy (stpcpy (buf, "SIGNER "), s);
          err = gpgsm_assuan_simple_command (gpgsm->assuan_ctx, buf,
                                             NULL, NULL);
	}
      else
        err = gpg_error (GPG_ERR_INV_VALUE);
      gpgme_key_unref (key);
      if (err) 
        return err;
    }

  gpgsm->input_cb.data = in;
  err = gpgsm_set_fd (gpgsm->assuan_ctx, "INPUT", gpgsm->input_fd_server,
                      map_input_enc (gpgsm->input_cb.data));
  if (err)
    return err;
  gpgsm->output_cb.data = out;
  err = gpgsm_set_fd (gpgsm->assuan_ctx, "OUTPUT", gpgsm->output_fd_server,
		      use_armor ? "--armor" : 0);
  if (err)
    return err;
  _gpgme_io_close (gpgsm->message_cb.fd);

  err = start (gpgsm, mode == GPGME_SIG_MODE_DETACH
	       ? "SIGN --detached" : "SIGN");
  return err;
}


static gpgme_error_t
gpgsm_verify (void *engine, gpgme_data_t sig, gpgme_data_t signed_text,
	      gpgme_data_t plaintext)
{
  engine_gpgsm_t gpgsm = engine;
  gpgme_error_t err;

  if (!gpgsm)
    return gpg_error (GPG_ERR_INV_VALUE);

  gpgsm->input_cb.data = sig;
  err = gpgsm_set_fd (gpgsm->assuan_ctx, "INPUT", gpgsm->input_fd_server,
                      map_input_enc (gpgsm->input_cb.data));
  if (err)
    return err;
  if (plaintext)
    {
      /* Normal or cleartext signature.  */
      gpgsm->output_cb.data = plaintext;
      err = gpgsm_set_fd (gpgsm->assuan_ctx, "OUTPUT", gpgsm->output_fd_server,
			  0);
      _gpgme_io_close (gpgsm->message_cb.fd);
    }
  else
    {
      /* Detached signature.  */
      gpgsm->message_cb.data = signed_text;
      err = gpgsm_set_fd (gpgsm->assuan_ctx, "MESSAGE",
			  gpgsm->message_fd_server, 0);
      _gpgme_io_close (gpgsm->output_cb.fd);
    }

  if (!err)
    err = start (gpgsm, "VERIFY");

  return err;
}


static void
gpgsm_set_status_handler (void *engine, engine_status_handler_t fnc,
			  void *fnc_value) 
{
  engine_gpgsm_t gpgsm = engine;

  gpgsm->status.fnc = fnc;
  gpgsm->status.fnc_value = fnc_value;
}


static gpgme_error_t
gpgsm_set_colon_line_handler (void *engine, engine_colon_line_handler_t fnc,
			      void *fnc_value) 
{
  engine_gpgsm_t gpgsm = engine;

  gpgsm->colon.fnc = fnc;
  gpgsm->colon.fnc_value = fnc_value;
  gpgsm->colon.any = 0;
  return 0;
}


static void
gpgsm_set_io_cbs (void *engine, gpgme_io_cbs_t io_cbs)
{
  engine_gpgsm_t gpgsm = engine;
  gpgsm->io_cbs = *io_cbs;
}


static void
gpgsm_io_event (void *engine, gpgme_event_io_t type, void *type_data)
{
  engine_gpgsm_t gpgsm = engine;

  if (gpgsm->io_cbs.event)
    (*gpgsm->io_cbs.event) (gpgsm->io_cbs.event_priv, type, type_data);
}


struct engine_ops _gpgme_engine_ops_gpgsm =
  {
    /* Static functions.  */
    _gpgme_get_gpgsm_path,
    gpgsm_get_version,
    gpgsm_get_req_version,
    gpgsm_new,

    /* Member functions.  */
    gpgsm_release,
    gpgsm_set_status_handler,
    NULL,		/* set_command_handler */
    gpgsm_set_colon_line_handler,
    gpgsm_decrypt,
    gpgsm_delete,
    NULL,		/* edit */
    gpgsm_encrypt,
    NULL,		/* encrypt_sign */
    gpgsm_export,
    gpgsm_export_ext,
    gpgsm_genkey,
    gpgsm_import,
    gpgsm_keylist,
    gpgsm_keylist_ext,
    gpgsm_sign,
    NULL,		/* trustlist */
    gpgsm_verify,
    gpgsm_set_io_cbs,
    gpgsm_io_event
  };
