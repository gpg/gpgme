/* signers.c - Maintain signer sets.
   Copyright (C) 2001 Werner Koch (dd9jn)
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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#include "util.h"
#include "context.h"


/* Delete all signers from CTX.  */
void
gpgme_signers_clear (gpgme_ctx_t ctx)
{
  unsigned int i;

  if (!ctx || !ctx->signers)
    return;

  for (i = 0; i < ctx->signers_len; i++)
    {
      assert (ctx->signers[i]);
      gpgme_key_unref (ctx->signers[i]);
      ctx->signers[i] = NULL;
    }
  ctx->signers_len = 0;
}

/* Add KEY to list of signers in CTX.  */
gpgme_error_t
gpgme_signers_add (gpgme_ctx_t ctx, const gpgme_key_t key)
{
  if (!ctx || !key)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (ctx->signers_len == ctx->signers_size)
    {
      gpgme_key_t *newarr;
      int n = ctx->signers_size + 5;
      int j;

      newarr = realloc (ctx->signers, n * sizeof (*newarr));
      if (!newarr)
	return gpg_error_from_errno (errno);
      for (j = ctx->signers_size; j < n; j++)
	newarr[j] = NULL;
      ctx->signers = newarr;
      ctx->signers_size = n;
    }

  gpgme_key_ref (key);
  ctx->signers[ctx->signers_len++] = key;
  return 0;
}


/* Return the SEQth signer's key in CTX with one reference.  */
gpgme_key_t
gpgme_signers_enum (const gpgme_ctx_t ctx, int seq)
{
  unsigned int seqno;

  if (!ctx || seq < 0)
    return NULL;

  seqno = (unsigned int) seq;
  if (seqno >= ctx->signers_len)
    return NULL;
  gpgme_key_ref (ctx->signers[seqno]);
  return ctx->signers[seqno];
}
