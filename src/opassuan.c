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


typedef struct
{
  struct _gpgme_op_assuan_result result;

} *op_data_t;




/* This callback is used to return the status of the assuan command
   back.  Note that this is different from the error code returned
   from gpgme_op_assuan_transact because the later only reflects error
   with the connection.  */
static gpgme_error_t
result_cb (void *priv, gpgme_error_t result)
{
  gpgme_ctx_t ctx = (gpgme_ctx_t)priv;
  gpgme_error_t err;
  void *hook;
  op_data_t opd;

  err = _gpgme_op_data_lookup (ctx, OPDATA_ASSUAN, &hook, -1, NULL);
  opd = hook;
  if (err)
    return err;
  if (!opd)
    return gpg_error (GPG_ERR_INTERNAL);

  opd->result.err = result;
  return 0;
}


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

  return &opd->result;
}


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
  void *hook;
  op_data_t opd;

  if (!command || !*command)
    return gpg_error (GPG_ERR_INV_VALUE);

  /* The flag value 256 is used to suppress an engine reset.  This is
     required to keep the connection running.  */
  err = _gpgme_op_reset (ctx, ((synchronous&255) | 256));
  if (err)
    return err;

  err = _gpgme_op_data_lookup (ctx, OPDATA_ASSUAN, &hook, sizeof (*opd), NULL);
  opd = hook;
  if (err)
    return err;
  opd->result.err = gpg_error (GPG_ERR_UNFINISHED);

  return _gpgme_engine_op_assuan_transact (ctx->engine, command,
                                           result_cb, ctx,
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

  err = opassuan_start (ctx, 1, command, 
                        data_cb, data_cb_value,
                        inq_cb, inq_cb_value,
                        status_cb, status_cb_value);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return err;
}

