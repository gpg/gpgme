/* spawn.c - Run an arbitrary command with callbacks.
   Copyright (C) 2014 Code GmbH

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
#include "util.h"
#include "ops.h"


static gpgme_error_t
spawn_start (gpgme_ctx_t ctx, int synchronous,
             const char *file, const char *argv[],
             gpgme_data_t datain,
             gpgme_data_t dataout, gpgme_data_t dataerr,
             unsigned int flags)
{
  gpgme_error_t err;
  const char *tmp_argv[2];

  if (ctx->protocol != GPGME_PROTOCOL_SPAWN)
    return gpg_error (GPG_ERR_UNSUPPORTED_PROTOCOL);

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    return err;

  if (!argv)
    {
      tmp_argv[0] = _gpgme_get_basename (file);
      tmp_argv[1] = NULL;
      argv = tmp_argv;
    }

  return _gpgme_engine_op_spawn (ctx->engine, file, argv,
                                 datain, dataout, dataerr, flags);
}


/* Run the command FILE with the arguments in ARGV.  Connect stdin to
   DATAIN, stdout to DATAOUT, and STDERR to DATAERR.  If one the data
   streams is NULL, connect to /dev/null instead.  */
gpgme_error_t
gpgme_op_spawn_start (gpgme_ctx_t ctx, const char *file, const char *argv[],
                      gpgme_data_t datain,
                      gpgme_data_t dataout, gpgme_data_t dataerr,
                      unsigned int flags)
{
  gpgme_error_t err;

  TRACE_BEG2 (DEBUG_CTX, "gpgme_op_spawn_start", ctx, "file=(%s) flaggs=%x",
              file, flags);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = spawn_start (ctx, 0, file, argv, datain, dataout, dataerr, flags);
  return err;
}


/* Run the command FILE with the arguments in ARGV.  Connect stdin to
   DATAIN, stdout to DATAOUT, and STDERR to DATAERR.  If one the data
   streams is NULL, connect to /dev/null instead.  Synchronous
   variant. */
gpgme_error_t
gpgme_op_spawn (gpgme_ctx_t ctx, const char *file, const char *argv[],
	        gpgme_data_t datain,
                gpgme_data_t dataout, gpgme_data_t dataerr,
                unsigned int flags)
{
  gpgme_error_t err;

  TRACE_BEG2 (DEBUG_CTX, "gpgme_op_spawn", ctx, "file=(%s) flags=%x",
              file, flags);
  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = spawn_start (ctx, 1, file, argv, datain, dataout, dataerr, flags);

  if (!err)
    err = _gpgme_wait_one (ctx);
  return TRACE_ERR (err);
}
