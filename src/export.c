/* export.c - Export a key.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003, 2004, 2010 g10 Code GmbH

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
#include <stdlib.h>
#include <string.h>

#include "gpgme.h"
#include "util.h"
#include "debug.h"
#include "context.h"
#include "ops.h"


static gpgme_error_t
export_status_handler (void *priv, gpgme_status_code_t code, char *args)
{
  return 0;
}


static gpgme_error_t
export_start (gpgme_ctx_t ctx, int synchronous, const char *pattern,
	      gpgme_export_mode_t mode, gpgme_data_t keydata)
{
  gpgme_error_t err;

  if ((mode & ~(GPGME_EXPORT_MODE_EXTERN
                |GPGME_EXPORT_MODE_MINIMAL)))
    return gpg_error (GPG_ERR_INV_VALUE); /* Invalid flags in MODE.  */

  
  if ((mode & GPGME_EXPORT_MODE_EXTERN))
    {
      if (keydata)
        return gpg_error (GPG_ERR_INV_VALUE);
    }
  else
    {
      if (!keydata)
        return gpg_error (GPG_ERR_INV_VALUE);
    }

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    return err;

  _gpgme_engine_set_status_handler (ctx->engine, export_status_handler, ctx);

  return _gpgme_engine_op_export (ctx->engine, pattern, mode, keydata,
				  ctx->use_armor);
}


/* Export the keys listed in PATTERN into KEYDATA.  */
gpgme_error_t
gpgme_op_export_start (gpgme_ctx_t ctx, const char *pattern,
		       gpgme_export_mode_t mode, gpgme_data_t keydata)
{
  gpgme_error_t err;

  TRACE_BEG3 (DEBUG_CTX, "gpgme_op_export_start", ctx,
	      "pattern=%s, mode=0x%x, keydata=%p", pattern, mode, keydata);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = export_start (ctx, 0, pattern, mode, keydata);
  return TRACE_ERR (err);
}


/* Export the keys listed in PATTERN into KEYDATA.  */
gpgme_error_t
gpgme_op_export (gpgme_ctx_t ctx, const char *pattern,
		 gpgme_export_mode_t mode, gpgme_data_t keydata)
{
  gpgme_error_t err;

  TRACE_BEG3 (DEBUG_CTX, "gpgme_op_export", ctx,
	      "pattern=%s, mode=0x%x, keydata=%p", pattern, mode, keydata);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = export_start (ctx, 1, pattern, mode, keydata);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return err;
}


static gpgme_error_t
export_ext_start (gpgme_ctx_t ctx, int synchronous, const char *pattern[],
		  gpgme_export_mode_t mode, gpgme_data_t keydata)
{
  gpgme_error_t err;

  if ((mode & ~(GPGME_EXPORT_MODE_EXTERN
                |GPGME_EXPORT_MODE_MINIMAL)))
    return gpg_error (GPG_ERR_INV_VALUE); /* Invalid flags in MODE.  */

  if ((mode & GPGME_EXPORT_MODE_EXTERN))
    {
      if (keydata)
        return gpg_error (GPG_ERR_INV_VALUE);
    }
  else
    {
      if (!keydata)
        return gpg_error (GPG_ERR_INV_VALUE);
    }

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    return err;

  _gpgme_engine_set_status_handler (ctx->engine, export_status_handler, ctx);

  return _gpgme_engine_op_export_ext (ctx->engine, pattern, mode, keydata,
				      ctx->use_armor);
}


/* Export the keys listed in PATTERN into KEYDATA.  */
gpgme_error_t
gpgme_op_export_ext_start (gpgme_ctx_t ctx, const char *pattern[],
			   gpgme_export_mode_t mode, gpgme_data_t keydata)
{
  gpgme_error_t err;

  TRACE_BEG2 (DEBUG_CTX, "gpgme_op_export_ext_start", ctx,
	      "mode=0x%x, keydata=%p", mode, keydata);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  if (_gpgme_debug_trace () && pattern)
    {
      int i = 0;

      while (pattern[i])
	{
	  TRACE_LOG2 ("pattern[%i] = %s", i, pattern[i]);
	  i++;
	}
    }

  err = export_ext_start (ctx, 0, pattern, mode, keydata);
  return TRACE_ERR (err);
}


/* Export the keys listed in PATTERN into KEYDATA.  */
gpgme_error_t
gpgme_op_export_ext (gpgme_ctx_t ctx, const char *pattern[],
		     gpgme_export_mode_t mode, gpgme_data_t keydata)
{
  gpgme_error_t err;

  TRACE_BEG2 (DEBUG_CTX, "gpgme_op_export_ext_start", ctx,
	      "mode=0x%x, keydata=%p", mode, keydata);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  if (_gpgme_debug_trace () && pattern)
    {
      int i = 0;

      while (pattern[i])
	{
	  TRACE_LOG2 ("pattern[%i] = %s", i, pattern[i]);
	  i++;
	}
    }

  err = export_ext_start (ctx, 1, pattern, mode, keydata);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return TRACE_ERR (err);
}





static gpgme_error_t
export_keys_start (gpgme_ctx_t ctx, int synchronous, gpgme_key_t keys[],
                   gpgme_export_mode_t mode, gpgme_data_t keydata)
{
  gpgme_error_t err;
  int nkeys, idx;
  char **pattern;

  if (!keys)
    return gpg_error (GPG_ERR_INV_VALUE);

  /* Create a list of pattern from the keys.  */
  for (idx=nkeys=0; keys[idx]; idx++)
    if (keys[idx]->protocol == ctx->protocol)
      nkeys++;
  if (!nkeys)
    return gpg_error (GPG_ERR_NO_DATA);
  
  pattern = calloc (nkeys+1, sizeof *pattern);
  if (!pattern)
    return gpg_error_from_syserror ();

  for (idx=nkeys=0; keys[idx]; idx++)
    if (keys[idx]->protocol == ctx->protocol
        && keys[idx]->subkeys
        && keys[idx]->subkeys->fpr
        && *keys[idx]->subkeys->fpr)
      {
        pattern[nkeys] = strdup (keys[idx]->subkeys->fpr);
        if (!pattern[nkeys])
          {
            err = gpg_error_from_syserror ();
            goto leave;
          }
        nkeys++;
      }


  /* Pass on to the regular function.  */
  err = export_ext_start (ctx, synchronous, (const char**)pattern,
                          mode, keydata);

 leave:
  for (idx=0; pattern[idx]; idx++)
    free (pattern[idx]);
  free (pattern);

  return err;
}


/* Export the keys from the array KEYS into KEYDATA.  Only keys of the
   current protocol are exported and only those which have a
   fingerprint set; that is keys received with some external search
   methods are silently skipped.  */
gpgme_error_t
gpgme_op_export_keys_start (gpgme_ctx_t ctx,
                            gpgme_key_t keys[],
                            gpgme_export_mode_t mode,
                            gpgme_data_t keydata)
{
  gpg_error_t err;

  TRACE_BEG2 (DEBUG_CTX, "gpgme_op_export_keys_start", ctx,
	      "mode=0x%x, keydata=%p", mode, keydata);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));
  
  if (_gpgme_debug_trace () && keys)
    {
      int i = 0;

      while (keys[i])
	{
	  TRACE_LOG3 ("keys[%i] = %p (%s)", i, keys[i],
		      (keys[i]->subkeys && keys[i]->subkeys->fpr) ? 
		      keys[i]->subkeys->fpr : "invalid");
	  i++;
	}
    }

  err = export_keys_start (ctx, 0, keys, mode, keydata);
  return TRACE_ERR (err);
}

gpgme_error_t
gpgme_op_export_keys (gpgme_ctx_t ctx,
                      gpgme_key_t keys[],
                      gpgme_export_mode_t mode,
                      gpgme_data_t keydata)
{
  gpgme_error_t err;

  TRACE_BEG2 (DEBUG_CTX, "gpgme_op_export_keys", ctx,
	      "mode=0x%x, keydata=%p", mode, keydata);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));
  
  if (_gpgme_debug_trace () && keys)
    {
      int i = 0;

      while (keys[i])
	{
	  TRACE_LOG3 ("keys[%i] = %p (%s)", i, keys[i],
		      (keys[i]->subkeys && keys[i]->subkeys->fpr) ? 
		      keys[i]->subkeys->fpr : "invalid");
	  i++;
	}
    }

  err = export_keys_start (ctx, 1, keys, mode, keydata);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return TRACE_ERR (err);
}

