/* export.c - Export a key.
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

#include "gpgme.h"
#include "context.h"
#include "ops.h"


static gpgme_error_t
export_status_handler (void *priv, gpgme_status_code_t code, char *args)
{
  return 0;
}


static gpgme_error_t
export_start (gpgme_ctx_t ctx, int synchronous,
	      gpgme_recipients_t recp, gpgme_data_t keydata)
{
  gpgme_error_t err;

  if (!keydata || !recp)
    return GPGME_Invalid_Value;

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    return err;

  _gpgme_engine_set_status_handler (ctx->engine, export_status_handler, ctx);

  return _gpgme_engine_op_export (ctx->engine, recp, keydata, ctx->use_armor);
}


/* Export the keys listed in RECP into KEYDATA.  */
gpgme_error_t
gpgme_op_export_start (gpgme_ctx_t ctx, gpgme_recipients_t recp, gpgme_data_t keydata)
{
  return export_start (ctx, 0, recp, keydata);
}


/* Export the keys listed in RECP into KEYDATA.  */
gpgme_error_t
gpgme_op_export (gpgme_ctx_t ctx, gpgme_recipients_t recipients, gpgme_data_t keydata)
{
  gpgme_error_t err = export_start (ctx, 1, recipients, keydata);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return err;
}
