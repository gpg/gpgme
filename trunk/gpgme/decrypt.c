/* decrypt.c - Decrypt function.
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
#include <stdlib.h>

#include "util.h"
#include "context.h"
#include "ops.h"


struct decrypt_result_s
{
  int okay;
  int failed;
};


void
_gpgme_release_decrypt_result (DecryptResult result)
{
  if (!result)
    return;
  free (result);
}

/* Check whether STRING starts with TOKEN and return true in this
   case.  This is case insensitive.  If NEXT is not NULL return the
   number of bytes to be added to STRING to get to the next token; a
   returned value of 0 indicates end of line. 
   Fixme: Duplicated from verify.c.  */
static int 
is_token (const char *string, const char *token, size_t *next)
{
  size_t n = 0;

  for (;*string && *token && *string == *token; string++, token++, n++)
    ;
  if (*token || (*string != ' ' && !*string))
    return 0;
  if (next)
    {
      for (; *string == ' '; string++, n++)
        ;
      *next = n;
    }
  return 1;
}


static int
skip_token (const char *string, size_t *next)
{
  size_t n = 0;

  for (;*string && *string != ' '; string++, n++)
    ;
  for (;*string == ' '; string++, n++)
    ;
  if (!*string)
    return 0;
  if (next)
    *next = n;
  return 1;
}


GpgmeError
_gpgme_decrypt_status_handler (GpgmeCtx ctx, GpgmeStatusCode code, char *args)
{
  GpgmeError err;
  size_t n;

  err = _gpgme_passphrase_status_handler (ctx, code, args);
  if (err)
    return err;

  test_and_allocate_result (ctx, decrypt);

  switch (code)
    {
    case GPGME_STATUS_EOF:
      if (ctx->result.decrypt->failed)
	return GPGME_Decryption_Failed;
      else if (!ctx->result.decrypt->okay)
	return GPGME_No_Data;
      break;

    case GPGME_STATUS_DECRYPTION_OKAY:
      ctx->result.decrypt->okay = 1;
      break;

    case GPGME_STATUS_DECRYPTION_FAILED:
      ctx->result.decrypt->failed = 1;
      break;

    case GPGME_STATUS_ERROR:
      if (is_token (args, "decrypt.algorithm", &n) && n)
        {
          args += n;
          if (is_token (args, "Unsupported_Algorithm", &n))
            {
              GpgmeData dh;

              args += n;
              /* Fixme: This won't work when used with decrypt+verify */
              if (!gpgme_data_new (&dh))
                {
                  _gpgme_data_append_string (dh,
                                             "<GnupgOperationInfo>\n"
                                             " <decryption>\n"
                                             "  <error>\n"
                                             "   <unsupportedAlgorithm>");
                  if (skip_token (args, &n))
                    {
                      int c = args[n];
                      args[n] = 0;
                      _gpgme_data_append_percentstring_for_xml (dh, args);
                      args[n] = c;
                    }
                  else
                    _gpgme_data_append_percentstring_for_xml (dh, args);
                  
                  _gpgme_data_append_string (dh,
                                             "</unsupportedAlgorithm>\n"
                                             "  </error>\n"
                                             " </decryption>\n"
                                             "</GnupgOperationInfo>\n");
                  _gpgme_set_op_info (ctx, dh);
                }
            }
        }
      break;
        
    default:
      break;
    }

  return 0;
}


GpgmeError
_gpgme_decrypt_start (GpgmeCtx ctx, int synchronous,
		      GpgmeData ciph, GpgmeData plain, void *status_handler)
{
  GpgmeError err = 0;

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    goto leave;

  /* Check the supplied data.  */
  if (!ciph)
    {
      err = GPGME_No_Data;
      goto leave;
    }
  if (!plain)
    {
      err = GPGME_Invalid_Value;
      goto leave;
    }

  err = _gpgme_passphrase_start (ctx);
  if (err)
    goto leave;

  _gpgme_engine_set_status_handler (ctx->engine, status_handler, ctx);
  _gpgme_engine_set_verbosity (ctx->engine, ctx->verbosity);

  err = _gpgme_engine_op_decrypt (ctx->engine, ciph, plain);

 leave:
  if (err)
    {
      ctx->pending = 0; 
      _gpgme_engine_release (ctx->engine);
      ctx->engine = NULL;
    }
  return err;
}


GpgmeError
gpgme_op_decrypt_start (GpgmeCtx ctx, GpgmeData ciph, GpgmeData plain)
{
  return _gpgme_decrypt_start (ctx, 0, ciph, plain,
			       _gpgme_decrypt_status_handler);
}


/**
 * gpgme_op_decrypt:
 * @ctx: The context
 * @in: ciphertext input
 * @out: plaintext output
 * 
 * This function decrypts @in to @out.
 * Other parameters are take from the context @ctx.
 * The function does wait for the result.
 * 
 * Return value:  0 on success or an errorcode. 
 **/
GpgmeError
gpgme_op_decrypt (GpgmeCtx ctx, GpgmeData in, GpgmeData out)
{
  GpgmeError err = _gpgme_decrypt_start (ctx, 1, in, out,
					 _gpgme_decrypt_status_handler);
  if (!err)
      err = _gpgme_wait_one (ctx);
  return err;
}
