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

#include "gpgme.h"
#include "context.h"
#include "ops.h"
#include "util.h"

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
  return opassuan_start (ctx, 0, command, 
                         data_cb, data_cb_value,
                         inq_cb, inq_cb_value,
                         status_cb, status_cb_value);
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
			      gpgme_error_t *op_err)
{
  gpgme_error_t err;

  err = opassuan_start (ctx, 1, command, 
                        data_cb, data_cb_value,
                        inq_cb, inq_cb_value,
                        status_cb, status_cb_value);
  if (!err)
    err = _gpgme_wait_one_ext (ctx, op_err);
  return err;
}




/* Compatibility code for old interface.  */

/* Evil hack breaking abstractions for the purpose of localizing our
   other hack.  This is copied from engine.c.  */
struct engine
{
  struct engine_ops *ops;
  void *engine;
};

typedef struct
{
  struct _gpgme_op_assuan_result result;
} *op_data_t;

gpg_error_t _gpgme_engine_assuan_last_op_err (void *engine);

gpgme_assuan_result_t
gpgme_op_assuan_result (gpgme_ctx_t ctx)
{
  gpgme_error_t err;
  void *hook;
  op_data_t opd;

  err = _gpgme_op_data_lookup (ctx, OPDATA_ASSUAN, &hook, -1, NULL);
  opd = hook;
  /* Check in case this function is used without having run a command
     before.  */
  if (err || !opd)
    return NULL;

  /* All of this is a hack for the old style interface.  The new style
     interface returns op errors directly.  */
  opd->result.err = _gpgme_engine_assuan_last_op_err (ctx->engine->engine);

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
  gpgme_error_t op_err;
  gpgme_error_t err;

  /* Users of the old-style session based interfaces need to look at
     the result structure.  */
  gpgme_op_assuan_transact_ext (ctx, command, data_cb, data_cb_value,
				inq_cb, inq_cb_value,
				status_cb, status_cb_value, &op_err);

  return err;
}
