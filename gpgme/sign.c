/* sign.c -  signing functions
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

#define SKIP_TOKEN_OR_RETURN(a) do { \
    while (*(a) && *(a) != ' ') (a)++; \
    while (*(a) == ' ') (a)++; \
    if (!*(a)) \
        return; /* oops */ \
} while (0)

struct sign_result
{
  int okay;
  GpgmeData xmlinfo;
};
typedef struct sign_result *SignResult;


static void
release_sign_result (void *hook)
{
  SignResult result = (SignResult) hook;

  gpgme_data_release (result->xmlinfo);
}

/* Parse the args and save the information 
   <type> <pubkey algo> <hash algo> <class> <timestamp> <key fpr>
   in an XML structure.  With args of NULL the xml structure is
   closed.  */
static void
append_xml_siginfo (GpgmeData *rdh, char *args)
{
  GpgmeData dh;
  char helpbuf[100];
  int i;
  char *s;
  unsigned long ul;

  if (!*rdh)
    {
      if (gpgme_data_new (rdh))
	{
	  return; /* fixme: We are ignoring out-of-core */
        }
      dh = *rdh;
      _gpgme_data_append_string (dh, "<GnupgOperationInfo>\n");
    }
  else
    {
      dh = *rdh;
      _gpgme_data_append_string (dh, "  </signature>\n");
    }

  if (!args)
    {
      /* Just close the XML containter.  */
      _gpgme_data_append_string (dh, "</GnupgOperationInfo>\n");
      return;
    }

  _gpgme_data_append_string (dh, "  <signature>\n");
    
  _gpgme_data_append_string (dh,
			     *args == 'D' ? "    <detached/>\n" :
			     *args == 'C' ? "    <cleartext/>\n" :
			     *args == 'S' ? "    <standard/>\n" : "");
  SKIP_TOKEN_OR_RETURN (args);

  sprintf (helpbuf, "    <algo>%d</algo>\n", atoi (args));
  _gpgme_data_append_string (dh, helpbuf);
  SKIP_TOKEN_OR_RETURN (args);

  i = atoi (args);
  sprintf (helpbuf, "    <hashalgo>%d</hashalgo>\n", atoi (args));
  _gpgme_data_append_string (dh, helpbuf);
  switch (i)
    {
    case  1: s = "pgp-md5"; break;
    case  2: s = "pgp-sha1"; break;
    case  3: s = "pgp-ripemd160"; break;
    case  5: s = "pgp-md2"; break;
    case  6: s = "pgp-tiger192"; break;
    case  7: s = "pgp-haval-5-160"; break;
    case  8: s = "pgp-sha256"; break;
    case  9: s = "pgp-sha384"; break;
    case 10: s = "pgp-sha512"; break;
    default: s = "pgp-unknown"; break;
    }
  sprintf (helpbuf, "    <micalg>%s</micalg>\n", s);
  _gpgme_data_append_string (dh,helpbuf);
  SKIP_TOKEN_OR_RETURN (args);
    
  sprintf (helpbuf, "    <sigclass>%.2s</sigclass>\n", args);
  _gpgme_data_append_string (dh, helpbuf);
  SKIP_TOKEN_OR_RETURN (args);

  ul = strtoul (args, NULL, 10);
  sprintf (helpbuf, "    <created>%lu</created>\n", ul);
  _gpgme_data_append_string (dh, helpbuf);
  SKIP_TOKEN_OR_RETURN (args);

  /* Count the length of the finperprint.  */
  for (i = 0; args[i] && args[i] != ' '; i++)
    ;
  _gpgme_data_append_string (dh, "    <fpr>");
  _gpgme_data_append (dh, args, i);
  _gpgme_data_append_string (dh, "</fpr>\n");
}

GpgmeError
_gpgme_sign_status_handler (GpgmeCtx ctx, GpgmeStatusCode code, char *args)
{
  SignResult result;
  GpgmeError err;

  err = _gpgme_passphrase_status_handler (ctx, code, args);
  if (err)
    return err;

  switch (code)
    {
    case GPGME_STATUS_EOF:
      err = _gpgme_op_data_lookup (ctx, OPDATA_SIGN, (void **) &result,
				   -1, NULL);
      if (!err)
	{
	  if (result && result->okay)
	    {
	      append_xml_siginfo (&result->xmlinfo, NULL);
	      _gpgme_set_op_info (ctx, result->xmlinfo);
	      result->xmlinfo = NULL;
	    }
	  else if (!result || !result->okay)
	    /* FIXME: choose a better error code?  */
	    err = GPGME_No_Data;
	}
      break;

    case GPGME_STATUS_SIG_CREATED: 
      /* FIXME: We have no error return for multiple signatures.  */
      err = _gpgme_op_data_lookup (ctx, OPDATA_SIGN, (void **) &result,
				   sizeof (*result), release_sign_result);
      append_xml_siginfo (&result->xmlinfo, args);
      result->okay = 1;
      break;

    default:
      break;
    }
  return err;
}

static GpgmeError
_gpgme_op_sign_start (GpgmeCtx ctx, int synchronous,
		      GpgmeData in, GpgmeData out,
		      GpgmeSigMode mode)
{
  GpgmeError err = 0;

  if (mode != GPGME_SIG_MODE_NORMAL
      && mode != GPGME_SIG_MODE_DETACH
      && mode != GPGME_SIG_MODE_CLEAR)
    return GPGME_Invalid_Value;

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    goto leave;

  /* Check the supplied data.  */
  if (!in)
    {
      err = GPGME_No_Data;
      goto leave;
    }
  if (!out)
    {
      err = GPGME_Invalid_Value;
      goto leave;
    }

  err = _gpgme_passphrase_start (ctx);
  if (err)
    goto leave;

  _gpgme_engine_set_status_handler (ctx->engine, _gpgme_sign_status_handler,
				    ctx);
  _gpgme_engine_set_verbosity (ctx->engine, ctx->verbosity);

  err = _gpgme_engine_op_sign (ctx->engine, in, out, mode, ctx->use_armor,
			       ctx->use_textmode, ctx->include_certs,
			       ctx /* FIXME */);

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
gpgme_op_sign_start (GpgmeCtx ctx, GpgmeData in, GpgmeData out,
		     GpgmeSigMode mode)
{
  return _gpgme_op_sign_start (ctx, 0, in, out, mode);
}

/**
 * gpgme_op_sign:
 * @ctx: The context
 * @in: Data to be signed
 * @out: Detached signature
 * @mode: Signature creation mode
 * 
 * Create a detached signature for @in and write it to @out.
 * The data will be signed using either the default key or the ones
 * defined through @ctx.
 * The defined modes for signature create are:
 * <literal>
 * GPGME_SIG_MODE_NORMAL (or 0) 
 * GPGME_SIG_MODE_DETACH
 * GPGME_SIG_MODE_CLEAR
 * </literal>
 * Note that the settings done by gpgme_set_armor() and gpgme_set_textmode()
 * are ignore for @mode GPGME_SIG_MODE_CLEAR.
 * 
 * Return value: 0 on success or an error code.
 **/
GpgmeError
gpgme_op_sign (GpgmeCtx ctx, GpgmeData in, GpgmeData out, GpgmeSigMode mode)
{
  GpgmeError err = _gpgme_op_sign_start (ctx, 1, in, out, mode);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return err;
}
