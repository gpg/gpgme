/* queryswdb.c - Access to the SWDB file
 * Copyright (C) 2016 g10 Code GmbH
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


typedef struct
{
  struct _gpgme_op_query_swdb_result result;

} *op_data_t;



static void
release_op_data (void *hook)
{
  op_data_t opd = (op_data_t) hook;
  gpgme_query_swdb_result_t result = &opd->result;

  assert (!result->next);
  free (result->name);
  free (result->iversion);
  free (result->version);
}


gpgme_query_swdb_result_t
gpgme_op_query_swdb_result (gpgme_ctx_t ctx)
{
  void *hook;
  op_data_t opd;
  gpgme_error_t err;

  TRACE_BEG (DEBUG_CTX, "gpgme_op_query_swdb_result", ctx, "");

  err = _gpgme_op_data_lookup (ctx, OPDATA_QUERY_SWDB, &hook, -1, NULL);
  opd = hook;

  if (err || !opd)
    {
      TRACE_SUC ("result=(null)");
      return NULL;
    }

  TRACE_SUC ("result=%p", &opd->result);
  return &opd->result;
}



/* Query the swdb for software package NAME and check against the
 * installed version given by IVERSION.  If IVERSION is NULL a check
 * is only done if GPGME can figure out the version by itself
 * (e.g. for "gpgme" or "gnupg").  RESERVED should be 0.
 *
 * Note that we only implemented the synchronous variant of this
 * function but the API is prepared for an asynchronous variant.
 */
gpgme_error_t
gpgme_op_query_swdb (gpgme_ctx_t ctx, const char *name, const char *iversion,
                     unsigned int reserved)
{
  gpgme_error_t err;
  void *hook;
  op_data_t opd;

  TRACE_BEG  (DEBUG_CTX, "gpgme_op_query_swdb", ctx,
	      "name=%s, iversion=%s", name, iversion);

  if (!ctx || reserved)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  if (ctx->protocol != GPGME_PROTOCOL_GPGCONF)
    return TRACE_ERR (gpg_error (GPG_ERR_UNSUPPORTED_PROTOCOL));

  if (!name)
    name = "gpgme";

  if (!iversion && !strcmp (name, "gpgme"))
    iversion = VERSION;

  err = _gpgme_op_reset (ctx, 1);
  if (err)
    return err;

  err = _gpgme_op_data_lookup (ctx, OPDATA_QUERY_SWDB, &hook,
                               sizeof (*opd), release_op_data);
  opd = hook;
  if (err)
    return TRACE_ERR (err);

  err = _gpgme_engine_op_query_swdb (ctx->engine, name, iversion,
                                     &opd->result);
  return TRACE_ERR (err);
}
