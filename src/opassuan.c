/* opassuan.c - Low-level Assuan operations.
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
   License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

/* Suppress warning for accessing deprecated member "err".  */
#define _GPGME_IN_GPGME 1
#include "gpgme.h"
#include "context.h"
#include "ops.h"
#include "util.h"
#include "debug.h"

/* LEGACY: Remove this when removing the deprecated result
   structure.  */
typedef struct
{
  struct _gpgme_op_assuan_result result;
} *op_data_t;


static gpgme_error_t
opassuan_start (gpgme_ctx_t ctx, int synchronous,
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
  err = _gpgme_op_reset (ctx, ((synchronous&255) | 256));
  if (err)
    return err;

  {
    /* LEGACY: Remove this when removing the deprecated result
       structure.  */
    void *hook;
    op_data_t opd;
    err = _gpgme_op_data_lookup (ctx, OPDATA_ASSUAN, &hook,
				 sizeof (*opd), NULL);
    if (err)
      return err;
  }

  return _gpgme_engine_op_assuan_transact (ctx->engine, command,
                                           data_cb, data_cb_value,
                                           inq_cb, inq_cb_value,
                                           status_cb, status_cb_value);
}



/* XXXX.  This is the asynchronous variant. */
gpgme_error_t
gpgme_op_assuan_transact_start (gpgme_ctx_t ctx,
				const char *command,
				gpgme_assuan_data_cb_t data_cb,
				void *data_cb_value,
				gpgme_assuan_inquire_cb_t inq_cb,
				void *inq_cb_value,
				gpgme_assuan_status_cb_t status_cb,
				void *status_cb_value)
{
  gpg_error_t err;

  TRACE_BEG7 (DEBUG_CTX, "gpgme_op_assuan_transact_start", ctx,
	      "command=%s, data_cb=%p/%p, inq_cb=%p/%p, status_cb=%p/%p",
	      command, data_cb, data_cb_value, inq_cb, inq_cb_value,
	      status_cb, status_cb_value);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = opassuan_start (ctx, 0, command, data_cb, data_cb_value,
			inq_cb, inq_cb_value, status_cb, status_cb_value);
  return TRACE_ERR (err);
}


/* XXXX.  This is the synchronous variant. */
gpgme_error_t
gpgme_op_assuan_transact_ext (gpgme_ctx_t ctx,
			      const char *command,
			      gpgme_assuan_data_cb_t data_cb,
			      void *data_cb_value,
			      gpgme_assuan_inquire_cb_t inq_cb,
			      void *inq_cb_value,
			      gpgme_assuan_status_cb_t status_cb,
			      void *status_cb_value,
			      gpgme_error_t *op_err_p)
{
  gpgme_error_t err;
  gpgme_error_t op_err;

  TRACE_BEG8 (DEBUG_CTX, "gpgme_op_assuan_transact", ctx,
	      "command=%s, data_cb=%p/%p, inq_cb=%p/%p, status_cb=%p/%p, "
	      "op_err=%p",
	      command, data_cb, data_cb_value, inq_cb, inq_cb_value,
	      status_cb, status_cb_value, op_err_p);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = opassuan_start (ctx, 1, command,
                        data_cb, data_cb_value,
                        inq_cb, inq_cb_value,
                        status_cb, status_cb_value);
  if (err)
    goto out;

  err = _gpgme_wait_one_ext (ctx, &op_err);
  if (op_err)
    {
      TRACE_LOG2 ("op_err = %s <%s>", gpgme_strerror (op_err),
		  gpgme_strsource (op_err));
      if (! op_err_p)
	{
	  TRACE_LOG ("warning: operational error ignored by user");
	}
    }
  if (op_err_p)
    *op_err_p = op_err;

 out:
  return TRACE_ERR (err);
}




/* Compatibility code for old interface.  */

/* Evil hack breaking abstractions for the purpose of localizing our
   other hack.  This is copied from engine.c.  */
struct engine
{
  struct engine_ops *ops;
  void *engine;
};

gpg_error_t _gpgme_engine_assuan_last_op_err (void *engine);

gpgme_assuan_result_t
gpgme_op_assuan_result (gpgme_ctx_t ctx)
{
  gpgme_error_t err;
  void *hook;
  op_data_t opd;

  TRACE_BEG (DEBUG_CTX, "gpgme_op_assuan_result", ctx);

  err = _gpgme_op_data_lookup (ctx, OPDATA_ASSUAN, &hook, -1, NULL);
  opd = hook;
  /* Check in case this function is used without having run a command
     before.  */
  if (err || !opd)
    {
      TRACE_SUC0 ("result=(null)");
      return NULL;
    }

  /* All of this is a hack for the old style interface.  The new style
     interface returns op errors directly.  */
  opd->result.err = _gpgme_engine_assuan_last_op_err (ctx->engine->engine);
  if (opd->result.err)
    {
      TRACE_LOG1 ("err = %s", gpg_strerror (0));
    }
  else
    {
      TRACE_LOG2 ("err = %s <%s>", gpg_strerror (opd->result.err),
		  gpg_strsource (opd->result.err));
    }

  TRACE_SUC1 ("result=%p", &opd->result);
  return &opd->result;
}


gpgme_error_t
gpgme_op_assuan_transact (gpgme_ctx_t ctx,
			  const char *command,
			  gpgme_assuan_data_cb_t data_cb,
			  void *data_cb_value,
			  gpgme_assuan_inquire_cb_t inq_cb,
			  void *inq_cb_value,
			  gpgme_assuan_status_cb_t status_cb,
			  void *status_cb_value)
{
  gpgme_error_t err;

  TRACE (DEBUG_CTX, "gpgme_op_assuan_transact", ctx);

  if (!ctx)
    return gpg_error (GPG_ERR_INV_VALUE);

  /* Users of the old-style session based interfaces need to look at
     the result structure.  */
  err = gpgme_op_assuan_transact_ext (ctx, command, data_cb, data_cb_value,
				      inq_cb, inq_cb_value,
				      status_cb, status_cb_value, NULL);
  return err;
}
