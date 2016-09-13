/* vfs-create.c - vfs create support in GPGME
   Copyright (C) 2009 g10 Code GmbH

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
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include "gpgme.h"
#include "debug.h"
#include "context.h"
#include "ops.h"
#include "util.h"

static gpgme_error_t
vfs_start (gpgme_ctx_t ctx, int synchronous,
	   const char *command,
	   gpgme_assuan_data_cb_t data_cb,
	   void *data_cb_value,
	   gpgme_assuan_inquire_cb_t inq_cb,
	   void *inq_cb_value,
	   gpgme_assuan_status_cb_t status_cb,
	   void *status_cb_value)
{
  gpgme_error_t err;

  if (!command || !*command)
    return gpg_error (GPG_ERR_INV_VALUE);

  /* The flag value 256 is used to suppress an engine reset.  This is
     required to keep the connection running.  */
  err = _gpgme_op_reset (ctx, ((synchronous & 255) | 256));
  if (err)
    return err;

  return _gpgme_engine_op_assuan_transact (ctx->engine, command,
					   data_cb, data_cb_value,
					   inq_cb, inq_cb_value,
					   status_cb, status_cb_value);
}


#if 0
/* XXXX.  This is the asynchronous variant. */
static gpgme_error_t
gpgme_op_vfs_transact_start (gpgme_ctx_t ctx,
			     const char *command,
			     gpgme_assuan_data_cb_t data_cb,
			     void *data_cb_value,
			     gpgme_assuan_inquire_cb_t inq_cb,
			     void *inq_cb_value,
			     gpgme_assuan_status_cb_t status_cb,
			     void *status_cb_value)
{
  return vfs_start (ctx, 0, command, data_cb, data_cb_value,
		    inq_cb, inq_cb_value, status_cb, status_cb_value);
}
#endif


/* XXXX.  This is the synchronous variant. */
static gpgme_error_t
gpgme_op_vfs_transact (gpgme_ctx_t ctx,
		       const char *command,
		       gpgme_assuan_data_cb_t data_cb,
		       void *data_cb_value,
		       gpgme_assuan_inquire_cb_t inq_cb,
		       void *inq_cb_value,
		       gpgme_assuan_status_cb_t status_cb,
		       void *status_cb_value,
		       gpgme_error_t *op_err)
{
  gpgme_error_t err;

  if (!ctx)
    return gpg_error (GPG_ERR_INV_VALUE);

  err = vfs_start (ctx, 1, command, data_cb, data_cb_value,
		   inq_cb, inq_cb_value, status_cb, status_cb_value);
  if (!err)
    err = _gpgme_wait_one_ext (ctx, op_err);
  return err;
}


/* The actual exported interface follows.  */

/* The container is automatically uncreateed when the context is reset
   or destroyed.  This is a synchronous convenience interface, which
   automatically returns an operation error if there is no
   transmission error.  */
static gpgme_error_t
_gpgme_op_vfs_create (gpgme_ctx_t ctx, gpgme_key_t recp[],
		      const char *container_file, unsigned int flags,
		      gpgme_error_t *op_err)
{
  gpg_error_t err;
  char *cmd;
  char *container_file_esc = NULL;
  int i;

  (void)flags;

  /* We want to encourage people to check error values, so not getting
     them is discouraged here.  Also makes our code easier.  */
  if (! op_err)
    return gpg_error (GPG_ERR_INV_VALUE);

  err = _gpgme_encode_percent_string (container_file, &container_file_esc, 0);
  if (err)
    return err;

  i = 0;
  while (!err && recp[i])
    {
      if (!recp[i]->subkeys || !recp[i]->subkeys->fpr)
	{
	  free (container_file_esc);
	  return gpg_error (GPG_ERR_UNUSABLE_PUBKEY);
	}

      if (asprintf (&cmd, "RECIPIENT %s", recp[i]->subkeys->fpr) < 0)
	{
	  err = gpg_error_from_syserror ();
	  free (container_file_esc);
	  return err;
	}

      err = gpgme_op_vfs_transact (ctx, cmd, NULL, NULL, NULL, NULL,
				   NULL, NULL, op_err);
      free (cmd);
      if (err || *op_err)
	{
	  free (container_file_esc);
	  return err;
	}
      recp++;
    }

  if (asprintf (&cmd, "CREATE -- %s", container_file_esc) < 0)
    {
      err = gpg_error_from_syserror ();
      free (container_file_esc);
      return err;
    }
  free (container_file_esc);

  err = gpgme_op_vfs_transact (ctx, cmd, NULL, NULL, NULL, NULL,
			       NULL, NULL, op_err);
  free (cmd);

  return err;
}


gpgme_error_t
gpgme_op_vfs_create (gpgme_ctx_t ctx, gpgme_key_t recp[],
		      const char *container_file, unsigned int flags,
		      gpgme_error_t *op_err)
{
  gpg_error_t err;

  TRACE_BEG3 (DEBUG_CTX, "gpgme_op_vfs_create", ctx,
	      "container_file=%s, flags=0x%x, op_err=%p",
	      container_file, flags, op_err);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  if (_gpgme_debug_trace () && recp)
    {
      int i = 0;

      while (recp[i])
	{
	  TRACE_LOG3 ("recipient[%i] = %p (%s)", i, recp[i],
		      (recp[i]->subkeys && recp[i]->subkeys->fpr) ?
		      recp[i]->subkeys->fpr : "invalid");
	  i++;
	}
    }

  err = _gpgme_op_vfs_create (ctx, recp, container_file, flags, op_err);
  return TRACE_ERR (err);
}

