/* delete.c -  delete a key 
 *      Copyright (C) 2001, 2002 g10 Code GmbH
 *
 * This file is part of GPGME.
 *
 * GPGME is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GPGME is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include "util.h"
#include "context.h"
#include "ops.h"
#include "key.h"


enum delete_problem
  {
    DELETE_No_Problem = 0,
    DELETE_No_Such_Key = 1,
    DELETE_Must_Delete_Secret_Key = 2
  };


struct delete_result_s
{
  enum delete_problem problem;
};


void
_gpgme_release_delete_result (DeleteResult result)
{
  if (!result)
    return;
  xfree (result);
}


static void
delete_status_handler (GpgmeCtx ctx, GpgStatusCode code, char *args)
{
  if (ctx->error)
    return;
  test_and_allocate_result (ctx, delete);

  switch (code)
    {
    case STATUS_EOF:
      switch (ctx->result.delete->problem)
	{
	case DELETE_No_Problem:
	  break;
	case DELETE_No_Such_Key:
	  ctx->error = mk_error(Invalid_Key);
	  break;
	case DELETE_Must_Delete_Secret_Key:
	  ctx->error = mk_error(Conflict);
	  break;
	default:
	  ctx->error = mk_error(General_Error);
	  break;
	}
      break;

    case STATUS_DELETE_PROBLEM:
      ctx->result.delete->problem = atoi (args);
      break;

    default:
      /* Ignore all other codes.  */
      break;
    }
}


GpgmeError
gpgme_op_delete_start (GpgmeCtx ctx, const GpgmeKey key, int allow_secret)
{
  GpgmeError err = 0;

  fail_on_pending_request (ctx);
  ctx->pending = 1;

  if (!key)
    {
      err = mk_error (Invalid_Value);
      goto leave;
    }

  if (ctx->engine)
    {
      _gpgme_engine_release (ctx->engine); 
      ctx->engine = NULL;
    }

  _gpgme_release_result (ctx);
    
  err = _gpgme_engine_new (ctx->use_cms ? GPGME_PROTOCOL_CMS
			   : GPGME_PROTOCOL_OpenPGP, &ctx->engine);
  if (err)
    goto leave;

  _gpgme_engine_set_status_handler (ctx->engine, delete_status_handler, ctx);
  _gpgme_engine_set_verbosity (ctx->engine, ctx->verbosity);

  err = _gpgme_engine_op_delete (ctx->engine, key, allow_secret);
  if (!err)
    err = _gpgme_engine_start (ctx->engine, ctx);

 leave:
  if (err)
    {
      ctx->pending = 0; 
      _gpgme_engine_release (ctx->engine);
      ctx->engine = NULL;
    }
  return err;
}


/**
 * gpgme_op_delete:
 * @c: Context 
 * @key: A Key Object
 * @allow_secret: Allow secret key delete
 * 
 * Delete the give @key from the key database.  To delete a secret
 * along with the public key, @allow_secret must be true.
 * 
 * Return value: 0 on success or an error code.
 **/
GpgmeError
gpgme_op_delete (GpgmeCtx ctx, const GpgmeKey key, int allow_secret)
{
  GpgmeError err = gpgme_op_delete_start (ctx, key, allow_secret);
  if (!err)
    gpgme_wait (ctx, &err, 1);
  return err;
}
