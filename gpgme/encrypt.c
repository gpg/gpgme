/* encrypt.c - Encrypt functions.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "util.h"
#include "context.h"
#include "ops.h"
#include "wait.h"

#define SKIP_TOKEN_OR_RETURN(a) do { \
    while (*(a) && *(a) != ' ') (a)++; \
    while (*(a) == ' ') (a)++; \
    if (!*(a)) \
        return; /* oops */ \
} while (0)

struct encrypt_result
{
  int no_valid_recipients;
  int invalid_recipients;
  GpgmeData xmlinfo;
};
typedef struct encrypt_result *EncryptResult;

static void
release_encrypt_result (void *hook)
{
  EncryptResult result = (EncryptResult) hook;

  gpgme_data_release (result->xmlinfo);
}


/* Parse the args and save the information in an XML structure.  With
   args of NULL the xml structure is closed.  */
static void
append_xml_encinfo (GpgmeData *rdh, char *args)
{
  GpgmeData dh;
  char helpbuf[100];

  if (!*rdh)
    {
      if (gpgme_data_new (rdh))
	return; /* FIXME: We are ignoring out-of-core.  */
      dh = *rdh;
      _gpgme_data_append_string (dh, "<GnupgOperationInfo>\n");
    }
  else
    {
      dh = *rdh;
      _gpgme_data_append_string (dh, "  </encryption>\n");
    }

  if (!args)
    {
      /* Just close the XML containter.  */
      _gpgme_data_append_string (dh, "</GnupgOperationInfo>\n");
      return;
    }

  _gpgme_data_append_string (dh, "  <encryption>\n"
			     "    <error>\n"
			     "      <invalidRecipient/>\n");
    
  sprintf (helpbuf, "      <reason>%d</reason>\n", atoi (args));
  _gpgme_data_append_string (dh, helpbuf);
  SKIP_TOKEN_OR_RETURN (args);

  _gpgme_data_append_string (dh, "      <name>");
  _gpgme_data_append_percentstring_for_xml (dh, args);
  _gpgme_data_append_string (dh, "</name>\n"
			     "    </error>\n");
}


GpgmeError
_gpgme_encrypt_status_handler (GpgmeCtx ctx, GpgmeStatusCode code, char *args)
{
  GpgmeError err = 0;
  EncryptResult result;

  switch (code)
    {
    case GPGME_STATUS_EOF:
      err = _gpgme_op_data_lookup (ctx, OPDATA_ENCRYPT, (void **) &result,
				   -1, NULL);
      if (!err)
	{
	  if (result && result->xmlinfo)
	    {
	      append_xml_encinfo (&result->xmlinfo, NULL);
	      _gpgme_set_op_info (ctx, result->xmlinfo);
	      result->xmlinfo = NULL;
	    }
	  if (result && result->no_valid_recipients) 
	    return GPGME_No_UserID;
	  if (result && result->invalid_recipients) 
	    return GPGME_Invalid_UserID;
	}
      break;

    case GPGME_STATUS_INV_RECP:
      err = _gpgme_op_data_lookup (ctx, OPDATA_ENCRYPT, (void **) &result,
				   sizeof (*result), release_encrypt_result);
      if (!err)
	{
	  result->invalid_recipients++;
	  append_xml_encinfo (&result->xmlinfo, args);
	}
      break;

    case GPGME_STATUS_NO_RECP:
      err = _gpgme_op_data_lookup (ctx, OPDATA_ENCRYPT, (void **) &result,
				   sizeof (*result), release_encrypt_result);
      if (!err)
	result->no_valid_recipients = 1;
      break;

    default:
      break;
    }
  return err;
}


GpgmeError
_gpgme_encrypt_sym_status_handler (GpgmeCtx ctx, GpgmeStatusCode code,
				   char *args)
{
  return _gpgme_passphrase_status_handler (ctx, code, args);
}


static GpgmeError
_gpgme_op_encrypt_start (GpgmeCtx ctx, int synchronous,
			 GpgmeRecipients recp, GpgmeData plain, GpgmeData cipher)
{
  GpgmeError err;
  int symmetric = 0;

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    return err;

  if (!recp)
    symmetric = 1;
  else if (gpgme_recipients_count (recp) == 0)
    return GPGME_No_UserID;

  if (!plain)
    return GPGME_No_Data;
  if (!cipher)
    return GPGME_Invalid_Value;

  if (symmetric && ctx->passphrase_cb)
    {
      /* Symmetric encryption requires a passphrase.  */
      err = _gpgme_engine_set_command_handler (ctx->engine,
					       _gpgme_passphrase_command_handler,
					       ctx, NULL);
      if (err)
	return err;
    }

  _gpgme_engine_set_status_handler (ctx->engine,
				    symmetric
				    ? _gpgme_encrypt_sym_status_handler
				    : _gpgme_encrypt_status_handler,
				    ctx);

  return _gpgme_engine_op_encrypt (ctx->engine, recp, plain, cipher,
				   ctx->use_armor);
}


GpgmeError
gpgme_op_encrypt_start (GpgmeCtx ctx, GpgmeRecipients recp, GpgmeData plain,
			GpgmeData ciph)
{
  return _gpgme_op_encrypt_start (ctx, 0, recp, plain, ciph);
}


/**
 * gpgme_op_encrypt:
 * @c: The context
 * @recp: A set of recipients 
 * @in: plaintext input
 * @out: ciphertext output
 * 
 * This function encrypts @in to @out for all recipients from
 * @recp.  Other parameters are take from the context @c.
 * The function does wait for the result.
 * 
 * Return value:  0 on success or an errorcode. 
 **/
GpgmeError
gpgme_op_encrypt (GpgmeCtx ctx, GpgmeRecipients recp,
		  GpgmeData plain, GpgmeData cipher)
{
  int err = _gpgme_op_encrypt_start (ctx, 1, recp, plain, cipher);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return err;
}
