/* signers.c - maintain signer sets
   Copyright (C) 2001 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002 g10 Code GmbH
 
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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "util.h"
#include "context.h"

/* The signers are directly stored in the context.  So this is quite
   different to a recipient set.  */


/**
 * gpgme_signers_clear:
 * @c: context to clear from signers
 *
 * Remove the list of signers from the context and release the
 * references to the signers keys.
 *
 * Return value: The version string or NULL
 **/
void
gpgme_signers_clear (GpgmeCtx ctx)
{
  int i;

  return_if_fail (ctx);

  if (!ctx->signers)
    return;
  for (i = 0; i < ctx->signers_len; i++)
    {
      assert (ctx->signers[i]);
      gpgme_key_unref (ctx->signers[i]);
      ctx->signers[i] = NULL;
    }
  ctx->signers_len = 0;
}

/**
 * gpgme_signers_add:
 * @c: context to add signer to
 * @key: key to add
 *
 * Add the key as a signer to the context.  Acquires a reference to
 * the key.
 *
 * Return value: NULL on success, or an error code.
 **/
GpgmeError
gpgme_signers_add (GpgmeCtx ctx, const GpgmeKey key)
{
  if (!ctx || !key)
    return mk_error (Invalid_Value);

  if (ctx->signers_len == ctx->signers_size)
    {
      GpgmeKey *newarr;
      int n = ctx->signers_size + 5;
      int j;

      newarr = realloc (ctx->signers, n * sizeof (*newarr));
      if (!newarr)
	return mk_error (Out_Of_Core);
      for (j = ctx->signers_size; j < n; j++)
	newarr[j] = NULL;
      ctx->signers = newarr;
      ctx->signers_size = n;
    }

  gpgme_key_ref (key);
  ctx->signers[ctx->signers_len++] = key;
  return 0;
}

/**
 * gpgme_signers_enum:
 * @c: context to retrieve signer from
 * @seq: index of key to retrieve
 *
 * Acquire a reference to the signers key with the specified index
 * number in the context and return it to the caller.
 *
 * Return value: A GpgmeKey or NULL on failure.
 **/
GpgmeKey
gpgme_signers_enum (const GpgmeCtx ctx, int seq)
{
  return_null_if_fail (ctx);
  return_null_if_fail (seq >= 0);

  if (seq >= ctx->signers_len)
    return NULL;

  gpgme_key_ref (ctx->signers[seq]);
  return ctx->signers[seq];
}
