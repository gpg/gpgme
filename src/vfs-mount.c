/* vfs-mount.c - vfs mount support in GPGME
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

#include "gpgme.h"
#include "debug.h"
#include "context.h"
#include "ops.h"
#include "util.h"

typedef struct
{
  struct _gpgme_op_vfs_mount_result result;
} *op_data_t;



gpgme_vfs_mount_result_t
gpgme_op_vfs_mount_result (gpgme_ctx_t ctx)
{
  gpgme_error_t err;
  void *hook;
  op_data_t opd;

  err = _gpgme_op_data_lookup (ctx, OPDATA_VFS_MOUNT, &hook, -1, NULL);
  opd = hook;
  /* Check in case this function is used without having run a command
     before.  */
  if (err || !opd)
    return NULL;

  return &opd->result;
}


static gpgme_error_t
_gpgme_vfs_mount_status_handler (void *priv, const char *code, const char *args)
{
  gpgme_ctx_t ctx = (gpgme_ctx_t) priv;
  gpgme_error_t err;
  void *hook;
  op_data_t opd;

  err = _gpgme_op_data_lookup (ctx, OPDATA_VFS_MOUNT, &hook, -1, NULL);
  opd = hook;
  if (err)
    return err;

  if (! strcasecmp ("MOUNTPOINT", code))
    {
      if (opd->result.mount_dir)
	free (opd->result.mount_dir);
      opd->result.mount_dir = strdup (args);
    }

  return 0;
}


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
  void *hook;
  op_data_t opd;

  if (!command || !*command)
    return gpg_error (GPG_ERR_INV_VALUE);

  /* The flag value 256 is used to suppress an engine reset.  This is
     required to keep the connection running.  */
  err = _gpgme_op_reset (ctx, ((synchronous & 255) | 256));
  if (err)
    return err;

  err = _gpgme_op_data_lookup (ctx, OPDATA_VFS_MOUNT, &hook, sizeof (*opd),
			       NULL);
  opd = hook;
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

/* The container is automatically unmounted when the context is reset
   or destroyed.  This is a synchronous convenience interface, which
   automatically returns an operation error if there is no
   transmission error.  */
static gpgme_error_t
_gpgme_op_vfs_mount (gpgme_ctx_t ctx, const char *container_file,
		     const char *mount_dir, int flags, gpgme_error_t *op_err)
{
  gpg_error_t err;
  char *cmd;
  char *container_file_esc = NULL;

  (void)flags;

  /* We want to encourage people to check error values, so not getting
     them is discouraged here.  Also makes our code easier.  */
  if (! op_err)
    return gpg_error (GPG_ERR_INV_VALUE);

  err = _gpgme_encode_percent_string (container_file, &container_file_esc, 0);
  if (err)
    return err;

  if (asprintf (&cmd, "OPEN -- %s", container_file_esc) < 0)
    {
      err = gpg_error_from_syserror ();
      free (container_file_esc);
      return err;
    }
  free (container_file_esc);

  err = gpgme_op_vfs_transact (ctx, cmd, NULL, NULL, NULL, NULL,
			       NULL, NULL, op_err);
  free (cmd);
  if (err || *op_err)
    return err;

  if (mount_dir)
    {
      char *mount_dir_esc = NULL;

      err = _gpgme_encode_percent_string (mount_dir, &mount_dir_esc, 0);
      if (err)
	return err;

      if (asprintf (&cmd, "MOUNT -- %s", mount_dir_esc) < 0)
	{
	  err = gpg_error_from_syserror ();
	  free (mount_dir_esc);
	  return err;
	}
      free (mount_dir_esc);
    }
  else
    {
      if (asprintf (&cmd, "MOUNT") < 0)
	return gpg_error_from_syserror ();
    }

  err = gpgme_op_vfs_transact (ctx, cmd, NULL, NULL, NULL, NULL,
			       _gpgme_vfs_mount_status_handler, ctx, op_err);
  free (cmd);

  return err;
}

gpgme_error_t
gpgme_op_vfs_mount (gpgme_ctx_t ctx, const char *container_file,
		    const char *mount_dir, unsigned int flags,
		    gpgme_error_t *op_err)
{
  gpg_error_t err;

  TRACE_BEG4 (DEBUG_CTX, "gpgme_op_vfs_mount", ctx,
	      "container=%s, mount_dir=%s, flags=0x%x, op_err=%p",
	      container_file, mount_dir, flags, op_err);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = _gpgme_op_vfs_mount (ctx, container_file, mount_dir, flags, op_err);
  return TRACE_ERR (err);
}

