/* verify.c - Signature verification.
 * Copyright (C) 2000 Werner Koch (dd9jn)
 * Copyright (C) 2001, 2002, 2003, 2004, 2005 g10 Code GmbH
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
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>

#include "gpgme.h"
#include "debug.h"
#include "util.h"
#include "context.h"
#include "ops.h"


typedef struct
{
  struct _gpgme_op_verify_result result;

  /* The error code from a FAILURE status line or 0.  */
  gpg_error_t failure_code;

  gpgme_signature_t current_sig;
  int did_prepare_new_sig;
  int only_newsig_seen;
  int plaintext_seen;
  int conflict_user_seen;
} *op_data_t;


static void
release_op_data (void *hook)
{
  op_data_t opd = (op_data_t) hook;
  gpgme_signature_t sig = opd->result.signatures;

  while (sig)
    {
      gpgme_signature_t next = sig->next;
      gpgme_sig_notation_t notation = sig->notations;

      while (notation)
	{
	  gpgme_sig_notation_t next_nota = notation->next;

	  _gpgme_sig_notation_free (notation);
	  notation = next_nota;
	}

      if (sig->fpr)
	free (sig->fpr);
      if (sig->pka_address)
	free (sig->pka_address);
      if (sig->key)
        gpgme_key_unref (sig->key);
      free (sig);
      sig = next;
    }

  if (opd->result.file_name)
    free (opd->result.file_name);
}


gpgme_verify_result_t
gpgme_op_verify_result (gpgme_ctx_t ctx)
{
  void *hook;
  op_data_t opd;
  gpgme_error_t err;
  gpgme_signature_t sig;

  TRACE_BEG (DEBUG_CTX, "gpgme_op_verify_result", ctx, "");
  err = _gpgme_op_data_lookup (ctx, OPDATA_VERIFY, &hook, -1, NULL);
  opd = hook;
  if (err || !opd)
    {
      TRACE_SUC ("result=(null)");
      return NULL;
    }

  /* It is possible that we saw a new signature only followed by an
     ERROR line for that.  In particular a missing X.509 key triggers
     this.  In this case it is surprising that the summary field has
     not been updated.  We fix it here by explicitly looking for this
     case.  The real fix would be to have GPGME emit ERRSIG.  */
  for (sig = opd->result.signatures; sig; sig = sig->next)
    {
      if (!sig->summary)
        {
          switch (gpg_err_code (sig->status))
            {
            case GPG_ERR_KEY_EXPIRED:
              sig->summary |= GPGME_SIGSUM_KEY_EXPIRED;
              break;

            case GPG_ERR_NO_PUBKEY:
              sig->summary |= GPGME_SIGSUM_KEY_MISSING;
              break;

            default:
              break;
            }
        }
    }

  /* Now for some tracing stuff. */
  if (_gpgme_debug_trace ())
    {
      int i;

      for (sig = opd->result.signatures, i = 0; sig; sig = sig->next, i++)
	{
	  TRACE_LOG  ("sig[%i] = fpr %s, summary 0x%x, status %s",
		      i, sig->fpr, sig->summary, gpg_strerror (sig->status));
	  TRACE_LOG  ("sig[%i] = timestamps 0x%lx/0x%lx flags:%s%s%s",
		      i, sig->timestamp, sig->exp_timestamp,
		      sig->wrong_key_usage ? "wrong key usage" : "",
		      sig->pka_trust == 1 ? "pka bad"
		      : (sig->pka_trust == 2 ? "pka_okay" : "pka RFU"),
		      sig->chain_model ? "chain model" : "");
	  TRACE_LOG  ("sig[%i] = validity 0x%x (%s), algos %s/%s",
		      i, sig->validity, gpg_strerror (sig->validity_reason),
		      gpgme_pubkey_algo_name (sig->pubkey_algo),
		      gpgme_hash_algo_name (sig->hash_algo));
	  if (sig->pka_address)
	    {
	      TRACE_LOG  ("sig[%i] = PKA address %s", i, sig->pka_address);
	    }
	  if (sig->notations)
	    {
	      TRACE_LOG  ("sig[%i] = has notations (not shown)", i);
	    }
	}
    }

  TRACE_SUC ("result=%p", &opd->result);
  return &opd->result;
}


/* Build a summary vector from RESULT. */
static void
calc_sig_summary (gpgme_signature_t sig)
{
  unsigned long sum = 0;

  /* Calculate the red/green flag.  */
  if (sig->validity == GPGME_VALIDITY_FULL
      || sig->validity == GPGME_VALIDITY_ULTIMATE)
    {
      if (gpg_err_code (sig->status) == GPG_ERR_NO_ERROR
	  || gpg_err_code (sig->status) == GPG_ERR_SIG_EXPIRED
	  || gpg_err_code (sig->status) == GPG_ERR_KEY_EXPIRED)
	sum |= GPGME_SIGSUM_GREEN;
    }
  else if (sig->validity == GPGME_VALIDITY_NEVER)
    {
      if (gpg_err_code (sig->status) == GPG_ERR_NO_ERROR
	  || gpg_err_code (sig->status) == GPG_ERR_SIG_EXPIRED
	  || gpg_err_code (sig->status) == GPG_ERR_KEY_EXPIRED)
	sum |= GPGME_SIGSUM_RED;
    }
  else if (gpg_err_code (sig->status) == GPG_ERR_BAD_SIGNATURE)
    sum |= GPGME_SIGSUM_RED;


  /* FIXME: handle the case when key and message are expired. */
  switch (gpg_err_code (sig->status))
    {
    case GPG_ERR_SIG_EXPIRED:
      sum |= GPGME_SIGSUM_SIG_EXPIRED;
      break;

    case GPG_ERR_KEY_EXPIRED:
      sum |= GPGME_SIGSUM_KEY_EXPIRED;
      break;

    case GPG_ERR_NO_PUBKEY:
      sum |= GPGME_SIGSUM_KEY_MISSING;
      break;

    case GPG_ERR_CERT_REVOKED:
      sum |= GPGME_SIGSUM_KEY_REVOKED;
      break;

    case GPG_ERR_BAD_SIGNATURE:
    case GPG_ERR_NO_ERROR:
      break;

    default:
      sum |= GPGME_SIGSUM_SYS_ERROR;
      break;
    }

  /* Now look at the certain reason codes.  */
  switch (gpg_err_code (sig->validity_reason))
    {
    case GPG_ERR_CRL_TOO_OLD:
      if (sig->validity == GPGME_VALIDITY_UNKNOWN)
        sum |= GPGME_SIGSUM_CRL_TOO_OLD;
      break;

    case GPG_ERR_CERT_REVOKED:
      /* Note that this is a second way to set this flag.  It may also
         have been set due to a sig->status of STATUS_REVKEYSIG from
         parse_new_sig.  */
      sum |= GPGME_SIGSUM_KEY_REVOKED;
      break;

    default:
      break;
    }

  /* Check other flags. */
  if (sig->wrong_key_usage)
    sum |= GPGME_SIGSUM_BAD_POLICY;

  /* Set the valid flag when the signature is unquestionable
     valid.  (The test is identical to if(sum == GPGME_SIGSUM_GREEN)). */
  if ((sum & GPGME_SIGSUM_GREEN) && !(sum & ~GPGME_SIGSUM_GREEN))
    sum |= GPGME_SIGSUM_VALID;

  sig->summary = sum;
}


static gpgme_error_t
prepare_new_sig (op_data_t opd)
{
  gpgme_signature_t sig;

  if (opd->only_newsig_seen && opd->current_sig)
    {
      /* We have only seen the NEWSIG status and nothing else - we
         better skip this signature therefore and reuse it for the
         next possible signature. */
      sig = opd->current_sig;
      memset (sig, 0, sizeof *sig);
      assert (opd->result.signatures == sig);
    }
  else
    {
      sig = calloc (1, sizeof (*sig));
      if (!sig)
        return gpg_error_from_syserror ();
      if (!opd->result.signatures)
        opd->result.signatures = sig;
      if (opd->current_sig)
        opd->current_sig->next = sig;
      opd->current_sig = sig;
    }
  opd->did_prepare_new_sig = 1;
  opd->only_newsig_seen = 0;
  return 0;
}

static gpgme_error_t
parse_new_sig (op_data_t opd, gpgme_status_code_t code, char *args,
               gpgme_protocol_t protocol)
{
  gpgme_signature_t sig;
  char *end = strchr (args, ' ');
  char *tail;
  int got_fpr = 0;

  if (end)
    {
      *end = '\0';
      end++;
    }

  if (!opd->did_prepare_new_sig)
    {
      gpg_error_t err;

      err = prepare_new_sig (opd);
      if (err)
        return err;
    }
  assert (opd->did_prepare_new_sig);
  opd->did_prepare_new_sig = 0;

  assert (opd->current_sig);
  sig = opd->current_sig;

  /* FIXME: We should set the source of the state.  */
  switch (code)
    {
    case GPGME_STATUS_GOODSIG:
      sig->status = gpg_error (GPG_ERR_NO_ERROR);
      break;

    case GPGME_STATUS_EXPSIG:
      sig->status = gpg_error (GPG_ERR_SIG_EXPIRED);
      break;

    case GPGME_STATUS_EXPKEYSIG:
      sig->status = gpg_error (GPG_ERR_KEY_EXPIRED);
      break;

    case GPGME_STATUS_BADSIG:
      sig->status = gpg_error (GPG_ERR_BAD_SIGNATURE);
      break;

    case GPGME_STATUS_REVKEYSIG:
      sig->status = gpg_error (GPG_ERR_CERT_REVOKED);
      break;

    case GPGME_STATUS_ERRSIG:
      /* Parse the pubkey algo.  */
      if (!end)
	goto parse_err_sig_fail;
      gpg_err_set_errno (0);
      sig->pubkey_algo = _gpgme_map_pk_algo (strtol (end, &tail, 0), protocol);
      if (errno || end == tail || *tail != ' ')
	goto parse_err_sig_fail;
      end = tail;
      while (*end == ' ')
	end++;

      /* Parse the hash algo.  */
      if (!*end)
	goto parse_err_sig_fail;
      gpg_err_set_errno (0);
      sig->hash_algo = strtol (end, &tail, 0);
      if (errno || end == tail || *tail != ' ')
	goto parse_err_sig_fail;
      end = tail;
      while (*end == ' ')
	end++;

      /* Skip the sig class.  */
      end = strchr (end, ' ');
      if (!end)
	goto parse_err_sig_fail;
      while (*end == ' ')
	end++;

      /* Parse the timestamp.  */
      sig->timestamp = _gpgme_parse_timestamp (end, &tail);
      if (sig->timestamp == -1 || end == tail || (*tail && *tail != ' '))
	return trace_gpg_error (GPG_ERR_INV_ENGINE);
      end = tail;
      while (*end == ' ')
	end++;

      /* Parse the return code.  */
      if (!*end)
	goto parse_err_sig_fail;

      gpg_err_set_errno (0);
      sig->status = strtoul (end, &tail, 10);
      if (errno || end == tail || (*tail && *tail != ' '))
	goto parse_err_sig_fail;
      if (!*tail)
        goto parse_err_sig_ok;
      end = tail;
      while (*end == ' ')
	end++;

      /* Parse the new fingerprint (from the ISSUER_FPR subpacket).  */
      if (!*end || (*end == '-' && (end[1] == ' ' || !end[1])))
        goto parse_err_sig_ok;  /* Okay (just trailing spaces).  */
      sig->fpr = strdup (end);
      if (!sig->fpr)
	return gpg_error_from_syserror ();
      got_fpr = 1;
      goto parse_err_sig_ok;

    parse_err_sig_fail:
      sig->status = gpg_error (GPG_ERR_GENERAL);
    parse_err_sig_ok:
      break;

    default:
      return gpg_error (GPG_ERR_GENERAL);
    }

  if (*args && !got_fpr)
    {
      sig->fpr = strdup (args);
      if (!sig->fpr)
	return gpg_error_from_syserror ();
    }
  return 0;
}


static gpgme_error_t
parse_valid_sig (gpgme_signature_t sig, char *args, gpgme_protocol_t protocol)
{
  char *end = strchr (args, ' ');
  if (end)
    {
      *end = '\0';
      end++;
    }

  if (!*args)
    /* We require at least the fingerprint.  */
    return gpg_error (GPG_ERR_GENERAL);

  if (sig->fpr)
    free (sig->fpr);
  sig->fpr = strdup (args);
  if (!sig->fpr)
    return gpg_error_from_syserror ();

  /* Skip the creation date.  */
  end = strchr (end, ' ');
  if (end)
    {
      char *tail;

      sig->timestamp = _gpgme_parse_timestamp (end, &tail);
      if (sig->timestamp == -1 || end == tail || (*tail && *tail != ' '))
	return trace_gpg_error (GPG_ERR_INV_ENGINE);
      end = tail;

      sig->exp_timestamp = _gpgme_parse_timestamp (end, &tail);
      if (sig->exp_timestamp == -1 || end == tail || (*tail && *tail != ' '))
	return trace_gpg_error (GPG_ERR_INV_ENGINE);
      end = tail;

      while (*end == ' ')
	end++;
      /* Skip the signature version.  */
      end = strchr (end, ' ');
      if (end)
	{
	  while (*end == ' ')
	    end++;

	  /* Skip the reserved field.  */
	  end = strchr (end, ' ');
	  if (end)
	    {
	      /* Parse the pubkey algo.  */
	      gpg_err_set_errno (0);
	      sig->pubkey_algo = _gpgme_map_pk_algo (strtol (end, &tail, 0),
                                                     protocol);
	      if (errno || end == tail || *tail != ' ')
		return trace_gpg_error (GPG_ERR_INV_ENGINE);
	      end = tail;

	      while (*end == ' ')
		end++;

	      if (*end)
		{
		  /* Parse the hash algo.  */

		  gpg_err_set_errno (0);
		  sig->hash_algo = strtol (end, &tail, 0);
		  if (errno || end == tail || *tail != ' ')
		    return trace_gpg_error (GPG_ERR_INV_ENGINE);
		  end = tail;
		}
	    }
	}
    }
  return 0;
}


static gpgme_error_t
parse_notation (gpgme_signature_t sig, gpgme_status_code_t code, char *args)
{
  gpgme_error_t err;
  gpgme_sig_notation_t *lastp = &sig->notations;
  gpgme_sig_notation_t notation = sig->notations;
  char *p;

  if (code == GPGME_STATUS_NOTATION_NAME || code == GPGME_STATUS_POLICY_URL)
    {
      p = strchr (args, ' ');
      if (p)
        *p = '\0';

      /* FIXME: We could keep a pointer to the last notation in the list.  */
      while (notation && notation->value)
	{
	  lastp = &notation->next;
	  notation = notation->next;
	}

      if (notation)
	/* There is another notation name without data for the
	   previous one.  The crypto backend misbehaves.  */
	return trace_gpg_error (GPG_ERR_INV_ENGINE);

      err = _gpgme_sig_notation_create (&notation, NULL, 0, NULL, 0, 0);
      if (err)
	return err;

      if (code == GPGME_STATUS_NOTATION_NAME)
	{
	  err = _gpgme_decode_percent_string (args, &notation->name, 0, 0);
	  if (err)
	    {
	      _gpgme_sig_notation_free (notation);
	      return err;
	    }

	  notation->name_len = strlen (notation->name);

	  /* Set default flags for use with older gpg versions which
           * do not emit a NOTATIONS_FLAG line.  */
	  notation->flags = GPGME_SIG_NOTATION_HUMAN_READABLE;
	  notation->human_readable = 1;
	}
      else
	{
	  /* This is a policy URL.  */

	  err = _gpgme_decode_percent_string (args, &notation->value, 0, 0);
	  if (err)
	    {
	      _gpgme_sig_notation_free (notation);
	      return err;
	    }

	  notation->value_len = strlen (notation->value);
	}
      *lastp = notation;
    }
  else if (code == GPGME_STATUS_NOTATION_FLAGS)
    {
      char *field[2];

      while (notation && notation->next)
	{
	  lastp = &notation->next;
	  notation = notation->next;
	}

      if (!notation || !notation->name)
        { /* There are notation flags without a previous notation name.
           * The crypto backend misbehaves.  */
          return trace_gpg_error (GPG_ERR_INV_ENGINE);
        }
      if (_gpgme_split_fields (args, field, DIM (field)) < 2)
        { /* Required args missing.  */
          return trace_gpg_error (GPG_ERR_INV_ENGINE);
        }
      notation->flags = 0;
      if (atoi (field[0]))
        {
          notation->flags |= GPGME_SIG_NOTATION_CRITICAL;
          notation->critical = 1;
        }
      if (atoi (field[1]))
        {
          notation->flags |= GPGME_SIG_NOTATION_HUMAN_READABLE;
          notation->human_readable = 1;
        }
    }
  else if (code == GPGME_STATUS_NOTATION_DATA)
    {
      int len = strlen (args) + 1;
      char *dest;

      /* FIXME: We could keep a pointer to the last notation in the list.  */
      while (notation && notation->next)
	{
	  lastp = &notation->next;
	  notation = notation->next;
	}

      if (!notation || !notation->name)
	/* There is notation data without a previous notation
	   name.  The crypto backend misbehaves.  */
	return trace_gpg_error (GPG_ERR_INV_ENGINE);

      if (!notation->value)
	{
	  dest = notation->value = malloc (len);
	  if (!dest)
	    return gpg_error_from_syserror ();
	}
      else
	{
	  int cur_len = strlen (notation->value);
	  dest = realloc (notation->value, len + strlen (notation->value));
	  if (!dest)
	    return gpg_error_from_syserror ();
	  notation->value = dest;
	  dest += cur_len;
	}

      err = _gpgme_decode_percent_string (args, &dest, len, 0);
      if (err)
	return err;

      notation->value_len += strlen (dest);
    }
  else
    return trace_gpg_error (GPG_ERR_INV_ENGINE);
  return 0;
}


static gpgme_error_t
parse_trust (gpgme_signature_t sig, gpgme_status_code_t code, char *args)
{
  char *end = strchr (args, ' ');

  if (end)
    *end = '\0';

  switch (code)
    {
    case GPGME_STATUS_TRUST_UNDEFINED:
    default:
      sig->validity = GPGME_VALIDITY_UNKNOWN;
      break;

    case GPGME_STATUS_TRUST_NEVER:
      sig->validity = GPGME_VALIDITY_NEVER;
      break;

    case GPGME_STATUS_TRUST_MARGINAL:
      sig->validity = GPGME_VALIDITY_MARGINAL;
      break;

    case GPGME_STATUS_TRUST_FULLY:
    case GPGME_STATUS_TRUST_ULTIMATE:
      sig->validity = GPGME_VALIDITY_FULL;
      break;
    }

  sig->validity_reason = 0;
  sig->chain_model = 0;
  if (*args)
    {
      sig->validity_reason = atoi (args);
      while (*args && *args != ' ')
        args++;
      if (*args)
        {
          while (*args == ' ')
            args++;
          if (!strncmp (args, "chain", 5) && (args[5] == ' ' || !args[5]))
            sig->chain_model = 1;
        }
    }

  return 0;
}


/* Parse a TOFU_USER line and put the info into SIG.  */
static gpgme_error_t
parse_tofu_user (gpgme_signature_t sig, char *args, gpgme_protocol_t protocol)
{
  gpg_error_t err;
  char *tail;
  gpgme_user_id_t uid;
  gpgme_tofu_info_t ti;
  char *fpr = NULL;
  char *address = NULL;

  tail = strchr (args, ' ');
  if (!tail || tail == args)
    {
      err = trace_gpg_error (GPG_ERR_INV_ENGINE);  /* No fingerprint.  */
      goto leave;
    }
  *tail++ = 0;

  fpr = strdup (args);
  if (!fpr)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  if (sig->key && sig->key->fpr && strcmp (sig->key->fpr, fpr))
    {
      /* GnuPG since 2.1.17 emits multiple TOFU_USER lines with
         different fingerprints in case of conflicts for a signature. */
      err = gpg_error (GPG_ERR_DUP_VALUE);
      goto leave;
    }

  args = tail;
  tail = strchr (args, ' ');
  if (tail == args)
    {
      err = trace_gpg_error (GPG_ERR_INV_ENGINE);  /* No addr-spec.  */
      goto leave;
    }
  if (tail)
    *tail = 0;

  err = _gpgme_decode_percent_string (args, &address, 0, 0);
  if (err)
    goto leave;

  if (!sig->key)
    {
      err = _gpgme_key_new (&sig->key);
      if (err)
        goto leave;
      sig->key->fpr = fpr;
      sig->key->protocol = protocol;
      fpr = NULL;
    }
  else if (!sig->key->fpr)
    {
      err = trace_gpg_error (GPG_ERR_INTERNAL);
      goto leave;
    }

  err = _gpgme_key_append_name (sig->key, address, 0);
  if (err)
    goto leave;

  uid = sig->key->_last_uid;
  assert (uid);

  ti = calloc (1, sizeof *ti);
  if (!ti)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  uid->tofu = ti;


 leave:
  free (fpr);
  free (address);
  return err;
}


/* Parse a TOFU_STATS line and store it in the last tofu info of SIG.
 *
 *   TOFU_STATS <validity> <sign-count> <encr-count> \
 *                         [<policy> [<tm1> <tm2> <tm3> <tm4>]]
 */
static gpgme_error_t
parse_tofu_stats (gpgme_signature_t sig, char *args)
{
  gpgme_error_t err;
  gpgme_tofu_info_t ti;
  char *field[8];
  int nfields;
  unsigned long uval;

  if (!sig->key || !sig->key->_last_uid || !(ti = sig->key->_last_uid->tofu))
    return trace_gpg_error (GPG_ERR_INV_ENGINE); /* No TOFU_USER seen.  */
  if (ti->signfirst || ti->signcount || ti->validity || ti->policy)
    return trace_gpg_error (GPG_ERR_INV_ENGINE); /* Already set.  */

  nfields = _gpgme_split_fields (args, field, DIM (field));
  if (nfields < 3)
    return trace_gpg_error (GPG_ERR_INV_ENGINE); /* Required args missing.  */

  /* Note that we allow a value of up to 7 which is what we can store
   * in the ti->validity.  */
  err = _gpgme_strtoul_field (field[0], &uval);
  if (err || uval > 7)
    return trace_gpg_error (GPG_ERR_INV_ENGINE);
  ti->validity = uval;

  /* Parse the sign-count.  */
  err = _gpgme_strtoul_field (field[1], &uval);
  if (err)
    return trace_gpg_error (GPG_ERR_INV_ENGINE);
  if (uval > USHRT_MAX)
    uval = USHRT_MAX;
  ti->signcount = uval;

  /* Parse the encr-count.  */
  err = _gpgme_strtoul_field (field[2], &uval);
  if (err)
    return trace_gpg_error (GPG_ERR_INV_ENGINE);
  if (uval > USHRT_MAX)
    uval = USHRT_MAX;
  ti->encrcount = uval;

  if (nfields == 3)
    return 0; /* All mandatory fields parsed.  */

  /* Parse the policy.  */
  if (!strcmp (field[3], "none"))
    ti->policy = GPGME_TOFU_POLICY_NONE;
  else if (!strcmp (field[3], "auto"))
    ti->policy = GPGME_TOFU_POLICY_AUTO;
  else if (!strcmp (field[3], "good"))
    ti->policy = GPGME_TOFU_POLICY_GOOD;
  else if (!strcmp (field[3], "bad"))
    ti->policy = GPGME_TOFU_POLICY_BAD;
  else if (!strcmp (field[3], "ask"))
    ti->policy = GPGME_TOFU_POLICY_ASK;
  else /* "unknown" and invalid policy strings.  */
    ti->policy = GPGME_TOFU_POLICY_UNKNOWN;

  if (nfields == 4)
    return 0; /* No more optional fields.  */

  /* Parse first and last seen timestamps (none or both are required).  */
  if (nfields < 6)
    return trace_gpg_error (GPG_ERR_INV_ENGINE); /* "tm2" missing.  */
  err = _gpgme_strtoul_field (field[4], &uval);
  if (err)
    return trace_gpg_error (GPG_ERR_INV_ENGINE);
  ti->signfirst = uval;
  err = _gpgme_strtoul_field (field[5], &uval);
  if (err)
    return trace_gpg_error (GPG_ERR_INV_ENGINE);
  ti->signlast = uval;
  if (nfields > 7)
    {
      /* This condition is only to allow for gpg 2.1.15 - can
       * eventually be removed.  */
      err = _gpgme_strtoul_field (field[6], &uval);
      if (err)
        return trace_gpg_error (GPG_ERR_INV_ENGINE);
      ti->encrfirst = uval;
      err = _gpgme_strtoul_field (field[7], &uval);
      if (err)
        return trace_gpg_error (GPG_ERR_INV_ENGINE);
      ti->encrlast = uval;
    }

  return 0;
}


/* Parse a TOFU_STATS_LONG line and store it in the last tofu info of SIG.  */
static gpgme_error_t
parse_tofu_stats_long (gpgme_signature_t sig, char *args, int raw)
{
  gpgme_error_t err;
  gpgme_tofu_info_t ti;
  char *p;

  if (!sig->key || !sig->key->_last_uid || !(ti = sig->key->_last_uid->tofu))
    return trace_gpg_error (GPG_ERR_INV_ENGINE); /* No TOFU_USER seen.  */
  if (ti->description)
    return trace_gpg_error (GPG_ERR_INV_ENGINE); /* Already set.  */

  err = _gpgme_decode_percent_string (args, &ti->description, 0, 0);
  if (err)
    return err;

  /* Remove the non-breaking spaces.  */
  if (!raw)
    {
      for (p = ti->description; *p; p++)
        if (*p == '~')
          *p = ' ';
    }
  return 0;
}


/* Parse an error status line and if SET_STATUS is true update the
   result status as appropriate.  With SET_STATUS being false, only
   check for an error.  */
static gpgme_error_t
parse_error (gpgme_signature_t sig, char *args, int set_status)
{
  gpgme_error_t err;
  char *where = strchr (args, ' ');
  char *which;

  if (where)
    {
      *where = '\0';
      which = where + 1;

      where = strchr (which, ' ');
      if (where)
	*where = '\0';

      where = args;
    }
  else
    return trace_gpg_error (GPG_ERR_INV_ENGINE);

  err = atoi (which);

  if (!strcmp (where, "proc_pkt.plaintext")
      && gpg_err_code (err) == GPG_ERR_BAD_DATA)
    {
      /* This indicates a double plaintext.  The only solid way to
         handle this is by failing the oepration.  */
      return gpg_error (GPG_ERR_BAD_DATA);
    }
  else if (!set_status)
    ;
  else if (!strcmp (where, "verify.findkey"))
    sig->status = err;
  else if (!strcmp (where, "verify.keyusage")
	   && gpg_err_code (err) == GPG_ERR_WRONG_KEY_USAGE)
    sig->wrong_key_usage = 1;

  return 0;
}


gpgme_error_t
_gpgme_verify_status_handler (void *priv, gpgme_status_code_t code, char *args)
{
  gpgme_ctx_t ctx = (gpgme_ctx_t) priv;
  gpgme_error_t err;
  void *hook;
  op_data_t opd;
  gpgme_signature_t sig;
  char *end;

  err = _gpgme_op_data_lookup (ctx, OPDATA_VERIFY, &hook, -1, NULL);
  opd = hook;
  if (err)
    return err;

  sig = opd->current_sig;

  switch (code)
    {
    case GPGME_STATUS_NEWSIG:
      if (sig)
        calc_sig_summary (sig);
      err = prepare_new_sig (opd);
      opd->only_newsig_seen = 1;
      opd->conflict_user_seen = 0;
      return err;

    case GPGME_STATUS_GOODSIG:
    case GPGME_STATUS_EXPSIG:
    case GPGME_STATUS_EXPKEYSIG:
    case GPGME_STATUS_BADSIG:
    case GPGME_STATUS_ERRSIG:
    case GPGME_STATUS_REVKEYSIG:
      if (sig && !opd->did_prepare_new_sig)
	calc_sig_summary (sig);
      opd->only_newsig_seen = 0;
      return parse_new_sig (opd, code, args, ctx->protocol);

    case GPGME_STATUS_VALIDSIG:
      opd->only_newsig_seen = 0;
      return sig ? parse_valid_sig (sig, args, ctx->protocol)
	: trace_gpg_error (GPG_ERR_INV_ENGINE);

    case GPGME_STATUS_NODATA:
      opd->only_newsig_seen = 0;
      if (!sig)
	return gpg_error (GPG_ERR_NO_DATA);
      sig->status = gpg_error (GPG_ERR_NO_DATA);
      break;

    case GPGME_STATUS_UNEXPECTED:
      opd->only_newsig_seen = 0;
      if (!sig)
	return gpg_error (GPG_ERR_BAD_DATA);
      sig->status = gpg_error (GPG_ERR_NO_DATA);
      break;

    case GPGME_STATUS_NOTATION_NAME:
    case GPGME_STATUS_NOTATION_FLAGS:
    case GPGME_STATUS_NOTATION_DATA:
    case GPGME_STATUS_POLICY_URL:
      opd->only_newsig_seen = 0;
      return sig ? parse_notation (sig, code, args)
	: trace_gpg_error (GPG_ERR_INV_ENGINE);

    case GPGME_STATUS_TRUST_UNDEFINED:
    case GPGME_STATUS_TRUST_NEVER:
    case GPGME_STATUS_TRUST_MARGINAL:
    case GPGME_STATUS_TRUST_FULLY:
    case GPGME_STATUS_TRUST_ULTIMATE:
      opd->only_newsig_seen = 0;
      return sig ? parse_trust (sig, code, args)
	: trace_gpg_error (GPG_ERR_INV_ENGINE);

    case GPGME_STATUS_PKA_TRUST_BAD:
    case GPGME_STATUS_PKA_TRUST_GOOD:
      opd->only_newsig_seen = 0;
      /* Check that we only get one of these status codes per
         signature; if not the crypto backend misbehaves.  */
      if (!sig || sig->pka_trust || sig->pka_address)
        return trace_gpg_error (GPG_ERR_INV_ENGINE);
      sig->pka_trust = code == GPGME_STATUS_PKA_TRUST_GOOD? 2 : 1;
      end = strchr (args, ' ');
      if (end)
        *end = 0;
      sig->pka_address = strdup (args);
      break;

    case GPGME_STATUS_TOFU_USER:
      opd->only_newsig_seen = 0;
      if (!sig)
        return trace_gpg_error (GPG_ERR_INV_ENGINE);
      err = parse_tofu_user (sig, args, ctx->protocol);
      /* gpg emits TOFU User lines for each conflicting key.
       * GPGME does not expose this to have a clean API and
       * a GPGME user can do a keylisting with the address
       * normalisation.
       * So when a duplicated TOFU_USER line is encountered
       * we ignore the conflicting tofu stats emitted afterwards.
       */
      if (gpg_err_code (err) == GPG_ERR_DUP_VALUE)
        {
          opd->conflict_user_seen = 1;
          break;
        }
      opd->conflict_user_seen = 0;
      return trace_gpg_error (err);

    case GPGME_STATUS_TOFU_STATS:
      opd->only_newsig_seen = 0;
      if (opd->conflict_user_seen)
        break;
      return sig ? parse_tofu_stats (sig, args)
        /*    */ : trace_gpg_error (GPG_ERR_INV_ENGINE);

    case GPGME_STATUS_TOFU_STATS_LONG:
      opd->only_newsig_seen = 0;
      if (opd->conflict_user_seen)
        break;
      return sig ? parse_tofu_stats_long (sig, args, ctx->raw_description)
        /*    */ : trace_gpg_error (GPG_ERR_INV_ENGINE);

    case GPGME_STATUS_ERROR:
      opd->only_newsig_seen = 0;
      /* Some  error stati are informational, so we don't return an
         error code if we are not ready to process this status.  */
      return parse_error (sig, args, !!sig );

    case GPGME_STATUS_FAILURE:
      opd->failure_code = _gpgme_parse_failure (args);
      break;

    case GPGME_STATUS_EOF:
      if (sig && !opd->did_prepare_new_sig)
	calc_sig_summary (sig);
      if (opd->only_newsig_seen && sig)
        {
          gpgme_signature_t sig2;
          /* The last signature has no valid information - remove it
             from the list. */
          assert (!sig->next);
          if (sig == opd->result.signatures)
            opd->result.signatures = NULL;
          else
            {
              for (sig2 = opd->result.signatures; sig2; sig2 = sig2->next)
                if (sig2->next == sig)
                  {
                    sig2->next = NULL;
                    break;
                  }
            }
          /* Note that there is no need to release the members of SIG
             because we won't be here if they have been set. */
          free (sig);
          opd->current_sig = NULL;
        }
      opd->only_newsig_seen = 0;
      if (opd->failure_code)
        return opd->failure_code;
      break;

    case GPGME_STATUS_PLAINTEXT:
      if (++opd->plaintext_seen > 1)
        return gpg_error (GPG_ERR_BAD_DATA);
      {
        int mime = 0;
        err = _gpgme_parse_plaintext (args, &opd->result.file_name, &mime);
        if (err)
          return err;
        opd->result.is_mime = !!mime;
      }
      break;

    case GPGME_STATUS_VERIFICATION_COMPLIANCE_MODE:
      PARSE_COMPLIANCE_FLAGS (args, opd->current_sig);
      break;

    default:
      break;
    }
  return 0;
}


static gpgme_error_t
verify_status_handler (void *priv, gpgme_status_code_t code, char *args)
{
  gpgme_error_t err;

  err = _gpgme_progress_status_handler (priv, code, args);
  if (!err)
    err = _gpgme_verify_status_handler (priv, code, args);
  return err;
}


gpgme_error_t
_gpgme_op_verify_init_result (gpgme_ctx_t ctx)
{
  void *hook;
  op_data_t opd;

  return _gpgme_op_data_lookup (ctx, OPDATA_VERIFY, &hook,
				sizeof (*opd), release_op_data);
}


static gpgme_error_t
verify_start (gpgme_ctx_t ctx, int synchronous, gpgme_verify_flags_t flags,
              gpgme_data_t sig, gpgme_data_t signed_text,
              gpgme_data_t plaintext)
{
  gpgme_error_t err;

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    return err;

  err = _gpgme_op_verify_init_result (ctx);
  if (err)
    return err;

  _gpgme_engine_set_status_handler (ctx->engine, verify_status_handler, ctx);

  if (!sig)
    return gpg_error (GPG_ERR_NO_DATA);

  return _gpgme_engine_op_verify (ctx->engine, flags, sig, signed_text,
                                  plaintext, ctx);
}


/* Old version of gpgme_op_verify_ext_start without FLAGS.  */
gpgme_error_t
gpgme_op_verify_start (gpgme_ctx_t ctx, gpgme_data_t sig,
		       gpgme_data_t signed_text, gpgme_data_t plaintext)
{
  return gpgme_op_verify_ext_start (ctx, 0, sig, signed_text, plaintext);
}


/* Old version of gpgme_op_verify_ext without FLAGS.  */
gpgme_error_t
gpgme_op_verify (gpgme_ctx_t ctx, gpgme_data_t sig, gpgme_data_t signed_text,
		 gpgme_data_t plaintext)
{
  return gpgme_op_verify_ext (ctx, 0, sig, signed_text, plaintext);
}


/* Decrypt ciphertext CIPHER and make a signature verification within
   CTX and store the resulting plaintext in PLAIN.  */
gpgme_error_t
gpgme_op_verify_ext_start (gpgme_ctx_t ctx, gpgme_verify_flags_t flags,
                           gpgme_data_t sig, gpgme_data_t signed_text,
                           gpgme_data_t plaintext)
{
  gpg_error_t err;
  TRACE_BEG  (DEBUG_CTX, "gpgme_op_verify_start", ctx,
	      "flags=0x%x, sig=%p, signed_text=%p, plaintext=%p",
	      flags, sig, signed_text, plaintext);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = verify_start (ctx, 0, flags, sig, signed_text, plaintext);
  return TRACE_ERR (err);
}


/* Decrypt ciphertext CIPHER and make a signature verification within
   CTX and store the resulting plaintext in PLAIN.  */
gpgme_error_t
gpgme_op_verify_ext (gpgme_ctx_t ctx, gpgme_verify_flags_t flags,
                     gpgme_data_t sig, gpgme_data_t signed_text,
                     gpgme_data_t plaintext)
{
  gpgme_error_t err;

  TRACE_BEG  (DEBUG_CTX, "gpgme_op_verify", ctx,
	      "flags=0x%x, sig=%p, signed_text=%p, plaintext=%p",
	      flags, sig, signed_text, plaintext);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = verify_start (ctx, 1, flags, sig, signed_text, plaintext);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return TRACE_ERR (err);
}


/* Compatibility interfaces.  */

/* Get the key used to create signature IDX in CTX and return it in
   R_KEY.  */
gpgme_error_t
gpgme_get_sig_key (gpgme_ctx_t ctx, int idx, gpgme_key_t *r_key)
{
  gpgme_verify_result_t result;
  gpgme_signature_t sig;

  if (!ctx)
    return gpg_error (GPG_ERR_INV_VALUE);

  result = gpgme_op_verify_result (ctx);
  sig = result->signatures;

  while (sig && idx)
    {
      sig = sig->next;
      idx--;
    }
  if (!sig || idx)
    return gpg_error (GPG_ERR_EOF);

  return gpgme_get_key (ctx, sig->fpr, r_key, 0);
}


/* Retrieve the signature status of signature IDX in CTX after a
   successful verify operation in R_STAT (if non-null).  The creation
   time stamp of the signature is returned in R_CREATED (if non-null).
   The function returns a string containing the fingerprint.  */
const char *
gpgme_get_sig_status (gpgme_ctx_t ctx, int idx,
                      _gpgme_sig_stat_t *r_stat, time_t *r_created)
{
  gpgme_verify_result_t result;
  gpgme_signature_t sig;

  result = gpgme_op_verify_result (ctx);
  sig = result->signatures;

  while (sig && idx)
    {
      sig = sig->next;
      idx--;
    }
  if (!sig || idx)
    return NULL;

  if (r_stat)
    {
      switch (gpg_err_code (sig->status))
	{
	case GPG_ERR_NO_ERROR:
	  *r_stat = GPGME_SIG_STAT_GOOD;
	  break;

	case GPG_ERR_BAD_SIGNATURE:
	  *r_stat = GPGME_SIG_STAT_BAD;
	  break;

	case GPG_ERR_NO_PUBKEY:
	  *r_stat = GPGME_SIG_STAT_NOKEY;
	  break;

	case GPG_ERR_NO_DATA:
	  *r_stat = GPGME_SIG_STAT_NOSIG;
	  break;

	case GPG_ERR_SIG_EXPIRED:
	  *r_stat = GPGME_SIG_STAT_GOOD_EXP;
	  break;

	case GPG_ERR_KEY_EXPIRED:
	  *r_stat = GPGME_SIG_STAT_GOOD_EXPKEY;
	  break;

	default:
	  *r_stat = GPGME_SIG_STAT_ERROR;
	  break;
	}
    }
  if (r_created)
    *r_created = sig->timestamp;
  return sig->fpr;
}


/* Retrieve certain attributes of a signature.  IDX is the index
   number of the signature after a successful verify operation.  WHAT
   is an attribute where GPGME_ATTR_EXPIRE is probably the most useful
   one.  WHATIDX is to be passed as 0 for most attributes . */
unsigned long
gpgme_get_sig_ulong_attr (gpgme_ctx_t ctx, int idx,
                          _gpgme_attr_t what, int whatidx)
{
  gpgme_verify_result_t result;
  gpgme_signature_t sig;

  (void)whatidx;

  result = gpgme_op_verify_result (ctx);
  sig = result->signatures;

  while (sig && idx)
    {
      sig = sig->next;
      idx--;
    }
  if (!sig || idx)
    return 0;

  switch (what)
    {
    case GPGME_ATTR_CREATED:
      return sig->timestamp;

    case GPGME_ATTR_EXPIRE:
      return sig->exp_timestamp;

    case GPGME_ATTR_VALIDITY:
      return (unsigned long) sig->validity;

    case GPGME_ATTR_SIG_STATUS:
      switch (gpg_err_code (sig->status))
	{
	case GPG_ERR_NO_ERROR:
	  return GPGME_SIG_STAT_GOOD;

	case GPG_ERR_BAD_SIGNATURE:
	  return GPGME_SIG_STAT_BAD;

	case GPG_ERR_NO_PUBKEY:
	  return GPGME_SIG_STAT_NOKEY;

	case GPG_ERR_NO_DATA:
	  return GPGME_SIG_STAT_NOSIG;

	case GPG_ERR_SIG_EXPIRED:
	  return GPGME_SIG_STAT_GOOD_EXP;

	case GPG_ERR_KEY_EXPIRED:
	  return GPGME_SIG_STAT_GOOD_EXPKEY;

	default:
	  return GPGME_SIG_STAT_ERROR;
	}

    case GPGME_ATTR_SIG_SUMMARY:
      return sig->summary;

    default:
      break;
    }
  return 0;
}


const char *
gpgme_get_sig_string_attr (gpgme_ctx_t ctx, int idx,
                           _gpgme_attr_t what, int whatidx)
{
  gpgme_verify_result_t result;
  gpgme_signature_t sig;

  result = gpgme_op_verify_result (ctx);
  sig = result->signatures;

  while (sig && idx)
    {
      sig = sig->next;
      idx--;
    }
  if (!sig || idx)
    return NULL;

  switch (what)
    {
    case GPGME_ATTR_FPR:
      return sig->fpr;

    case GPGME_ATTR_ERRTOK:
      if (whatidx == 1)
        return sig->wrong_key_usage ? "Wrong_Key_Usage" : "";
      else
	return "";
    default:
      break;
    }

  return NULL;
}
