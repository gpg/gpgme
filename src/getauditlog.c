
/* getauditlog.c - Retrieve the audit log.
   Copyright (C) 2007 g10 Code GmbH

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
#include "debug.h"
#include "context.h"
#include "ops.h"


static gpgme_error_t
getauditlog_status_handler (void *priv, gpgme_status_code_t code, char *args)
{
  (void)priv;
  (void)code;
  (void)args;
  return 0;
}


static gpgme_error_t
getauditlog_start (gpgme_ctx_t ctx, int synchronous,
                   gpgme_data_t output, unsigned int flags)
{
  gpgme_error_t err;

  if (!output)
    return gpg_error (GPG_ERR_INV_VALUE);

  err = _gpgme_op_reset (ctx, ((synchronous&255) | 256) );
  if (err)
    return err;

  _gpgme_engine_set_status_handler (ctx->engine,
                                    getauditlog_status_handler, ctx);

  return _gpgme_engine_op_getauditlog (ctx->engine, output, flags);
}



/* Return the auditlog for the current session.  This may be called
   after a successful or failed operation.  If no audit log is
   available GPG_ERR_NO_DATA is returned.  This is the asynchronous
   variant. */
gpgme_error_t
gpgme_op_getauditlog_start (gpgme_ctx_t ctx,
                            gpgme_data_t output, unsigned int flags)
{
  gpg_error_t err;
  TRACE_BEG2 (DEBUG_CTX, "gpgme_op_getauditlog_start", ctx,
	      "output=%p, flags=0x%x", output, flags);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = getauditlog_start (ctx, 0, output, flags);
  return TRACE_ERR (err);
}


/* Return the auditlog for the current session.  This may be called
   after a successful or failed operation.  If no audit log is
   available GPG_ERR_NO_DATA is returned.  This is the synchronous
   variant. */
gpgme_error_t
gpgme_op_getauditlog (gpgme_ctx_t ctx, gpgme_data_t output, unsigned int flags)
{
  gpgme_error_t err;

  TRACE_BEG2 (DEBUG_CTX, "gpgme_op_getauditlog", ctx,
	      "output=%p, flags=0x%x", output, flags);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = getauditlog_start (ctx, 1, output, flags);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return TRACE_ERR (err);
}

