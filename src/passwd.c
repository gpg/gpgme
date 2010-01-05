/* passwd.c - Passphrase changing function
   Copyright (C) 2010 g10 Code GmbH

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
passwd_status_handler (void *priv, gpgme_status_code_t code, char *args)
{
  (void)priv;
  (void)code;
  (void)args;
  return 0;
}


static gpgme_error_t
passwd_start (gpgme_ctx_t ctx, int synchronous, gpgme_key_t key,
              unsigned int flags)
{
  gpgme_error_t err;

  if (!key)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (flags)
    return gpg_error (GPG_ERR_INV_FLAG);

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    return err;

  _gpgme_engine_set_status_handler (ctx->engine, passwd_status_handler, ctx);

  return _gpgme_engine_op_passwd (ctx->engine, key, flags);
}



/* Change the passphrase for KEY.  FLAGS is reserved for future use
   and must be passed as 0.  The engine is expected to present a user
   interface to enter the old and the new passphrase.  This is the
   asynchronous variant. 

   Note that if ever the need arises to supply a passphrase we can do
   this with a flag value and the passphrase callback feature.  */
gpgme_error_t
gpgme_op_passwd_start (gpgme_ctx_t ctx, gpgme_key_t key, unsigned int flags)
{
  gpg_error_t err;
  TRACE_BEG2 (DEBUG_CTX, "gpgme_op_passwd_start", ctx,
	      "key=%p, flags=0x%x", key, flags);
  err = passwd_start (ctx, 0, key, flags);
  return TRACE_ERR (err);
}


/* Change the passphrase for KEY.  FLAGS is reserved for future use
   and must be passed as 0.  This is the synchronous variant.  */
gpgme_error_t
gpgme_op_passwd (gpgme_ctx_t ctx, gpgme_key_t key, unsigned int flags)
{
  gpgme_error_t err;

  TRACE_BEG2 (DEBUG_CTX, "gpgme_op_passwd", ctx,
	      "key=%p, flags=0x%x", key, flags);

  err = passwd_start (ctx, 1, key, flags);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return TRACE_ERR (err);
}

