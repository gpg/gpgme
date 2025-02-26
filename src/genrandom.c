/* genrandom.c - Wrapper around gpg --gen-random
 * Copyright (C) 2025 g10 Code GmbH
 *
 * This file is part of GPGME.
 *
 * GPGME is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * GPGME is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <https://gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <assert.h>

#include "gpgme.h"
#include "debug.h"
#include "context.h"
#include "ops.h"


static gpgme_error_t
do_genrandom (gpgme_ctx_t ctx, gpgme_data_t dataout, size_t length, int zbase)
{
  gpgme_error_t err;
  const char *argv[4];
  char countbuf[35];

  if (ctx->protocol != GPGME_PROTOCOL_OPENPGP)
    return gpg_error (GPG_ERR_UNSUPPORTED_PROTOCOL);

  err = _gpgme_op_reset (ctx, 1/*synchronous*/);
  if (err)
    return err;

  snprintf (countbuf, sizeof countbuf, "%zu", length);
  argv[0] = "--gen-random";
  argv[1] = zbase? "30" : "2";
  argv[2] = countbuf;
  argv[3] = NULL;

  err = _gpgme_engine_op_getdirect (ctx->engine, argv, dataout, 0);
  if (!err)
    err = _gpgme_wait_one (ctx);

  return err;
}


/* Fill BUFFER of size BUFSIZE with random bytes retrieved from gpg.
 * If GPGME_RANDOM_MODE_ZBASE32 is used BUFSIZE needs to be at least
 * 31 and will be filled with a string of 30 ascii characters followed
 * by a Nul; the remainder of the buffer is not changed.  In all other
 * modes the entire buffer will be filled with binary data.  The
 * function has a limit of 1024 bytes to avoid accidental overuse of
 * the random generator. */
gpgme_error_t
gpgme_op_random_bytes (gpgme_ctx_t ctx, gpgme_random_mode_t mode,
                       char *buffer, size_t bufsize)
{
  gpgme_error_t err = 0;
  gpgme_data_t data = NULL;
  char *datap = NULL;
  size_t datalen;

  TRACE_BEG  (DEBUG_CTX, "gpgme_op_random_bytes", ctx, "mode=%d size=%zu",
              mode, bufsize);

  if (!ctx || !buffer || !bufsize)
    err = gpg_error (GPG_ERR_INV_VALUE);
  else if (mode == GPGME_RANDOM_MODE_ZBASE32)
    {
      /* The output is expected to be 30 ascii characters followed by
       * a trailing Nul. */
      if (bufsize < 31)
        err = gpg_error (GPG_ERR_BUFFER_TOO_SHORT);
    }
  else if (mode)
    err = gpg_error (GPG_ERR_INV_VALUE);
  else if (bufsize > 1024) /* More or an less arbitrary limit.  */
    err = gpg_error (GPG_ERR_TOO_LARGE);

  if (err)
    goto leave;

  err = gpgme_data_new (&data);
  if (err)
    goto leave;

  err = do_genrandom (ctx, data, bufsize, (mode == GPGME_RANDOM_MODE_ZBASE32));
  if (!err)
    err = _gpgme_wait_one (ctx);
  if (err)
    goto leave;

  datap = gpgme_data_release_and_get_mem (data, &datalen);
  data = NULL;
  if (!datap)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  if (datalen > bufsize)
    {
      err = gpg_error (GPG_ERR_INTERNAL);
      goto leave;
    }
  if (mode == GPGME_RANDOM_MODE_ZBASE32)
    {
      /* Strip trailing LF.  */
      while (datalen
             && (datap[datalen-1] == '\n' || datap[datalen-1] == '\r'))
        datalen--;

      if (datalen != 30)
        {
          /* 30 is the holy count, not 29, not 31 and never 32. */
          err = gpg_error (GPG_ERR_INTERNAL);
          goto leave;
        }
      memcpy (buffer, datap, datalen);
      buffer[datalen] = 0;
    }
  else
    {
      if (datalen != bufsize)
        {
          err = gpg_error (GPG_ERR_INTERNAL);
          goto leave;
        }
      memcpy (buffer, datap, datalen);
    }

 leave:
  free (datap);
  gpgme_data_release (data);
  return TRACE_ERR (err);
}
