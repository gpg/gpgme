/* json-core.c - Core of the JSON based interface to gpgme
 * Copyright (C) 2018, 2025 g10 Code GmbH
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif
#include <stdint.h>
#include <sys/stat.h>

#include "json-common.h"

/* Minimal chunk size for returned data.*/
#define MIN_REPLY_CHUNK_SIZE  30

/* If no chunksize is provided we print everything.  Changing
 * this to a positive value will result in all messages being
 * chunked. */
#define DEF_REPLY_CHUNK_SIZE  0
#define MAX_REPLY_CHUNK_SIZE (10 * 1024 * 1024)



/*
 * Helper functions and macros
 */


/* This is similar to cJSON_AddStringToObject but takes (DATA,
 * DATALEN) and adds it under NAME as a base 64 encoded string to
 * OBJECT.  */
static gpg_error_t
add_base64_to_object (cjson_t object, const char *name,
                      const void *data, size_t datalen)
{
  gpg_err_code_t err;
  estream_t fp = NULL;
  gpgrt_b64state_t state = NULL;
  cjson_t j_str = NULL;
  void *buffer = NULL;

  fp = es_fopenmem (0, "rwb");
  if (!fp)
    {
      err = gpg_err_code_from_syserror ();
      goto leave;
    }
  state = gpgrt_b64enc_start (fp, "");
  if (!state)
    {
      err = gpg_err_code_from_syserror ();
      goto leave;
    }

  err = gpgrt_b64enc_write (state, data, datalen);
  if (err)
    goto leave;

  err = gpgrt_b64enc_finish (state);
  state = NULL;
  if (err)
    return err;

  es_fputc (0, fp);
  if (es_fclose_snatch (fp, &buffer, NULL))
    {
      fp = NULL;
      err = gpg_error_from_syserror ();
      goto leave;
    }
  fp = NULL;

  j_str = cJSON_CreateStringConvey (buffer);
  if (!j_str)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  buffer = NULL;

  if (!cJSON_AddItemToObject (object, name, j_str))
    {
      err = gpg_error_from_syserror ();
      cJSON_Delete (j_str);
      j_str = NULL;
      goto leave;
    }
  j_str = NULL;

 leave:
  xfree (buffer);
  cJSON_Delete (j_str);
  gpgrt_b64enc_finish (state);
  es_fclose (fp);
  return err;
}



/* Get the boolean property NAME from the JSON object and store true
 * or valse at R_VALUE.  If the name is unknown the value of DEF_VALUE
 * is returned.  If the type of the value is not boolean,
 * GPG_ERR_INV_VALUE is returned and R_VALUE set to DEF_VALUE.  */
static gpg_error_t
get_boolean_flag (cjson_t json, const char *name, int def_value, int *r_value)
{
  cjson_t j_item;

  j_item = cJSON_GetObjectItem (json, name);
  if (!j_item)
    *r_value = def_value;
  else if (cjson_is_true (j_item))
    *r_value = 1;
  else if (cjson_is_false (j_item))
    *r_value = 0;
  else
    {
      *r_value = def_value;
      return gpg_error (GPG_ERR_INV_VALUE);
    }

  return 0;
}


/* Get the boolean property PROTOCOL from the JSON object and store
 * its value at R_PROTOCOL.  The default is OpenPGP.  */
static gpg_error_t
get_protocol (cjson_t json, gpgme_protocol_t *r_protocol)
{
  cjson_t j_item;

  *r_protocol = GPGME_PROTOCOL_OpenPGP;
  j_item = cJSON_GetObjectItem (json, "protocol");
  if (!j_item)
    ;
  else if (!cjson_is_string (j_item))
    return gpg_error (GPG_ERR_INV_VALUE);
  else if (!strcmp(j_item->valuestring, "openpgp"))
    ;
  else if (!strcmp(j_item->valuestring, "cms"))
    *r_protocol = GPGME_PROTOCOL_CMS;
  else
    return gpg_error (GPG_ERR_UNSUPPORTED_PROTOCOL);

  return 0;
}


/* Get the chunksize from JSON and store it at R_CHUNKSIZE.  */
static gpg_error_t
get_chunksize (cjson_t json, size_t *r_chunksize)
{
  cjson_t j_item;

  *r_chunksize = DEF_REPLY_CHUNK_SIZE;
  j_item = cJSON_GetObjectItem (json, "chunksize");
  if (!j_item)
    ;
  else if (!cjson_is_number (j_item))
    return gpg_error (GPG_ERR_INV_VALUE);
  else if ((size_t)j_item->valueint < MIN_REPLY_CHUNK_SIZE)
    *r_chunksize = MIN_REPLY_CHUNK_SIZE;
  else if ((size_t)j_item->valueint > MAX_REPLY_CHUNK_SIZE)
    *r_chunksize = MAX_REPLY_CHUNK_SIZE;
  else
    *r_chunksize = (size_t)j_item->valueint;

  return 0;
}


/* Extract the keys from the array or string with the name "name"
 * in the JSON object.  On success a string with the keys identifiers
 * is stored at R_KEYS.
 * The keys in that string are LF delimited.  On failure an error code
 * is returned.  */
static gpg_error_t
get_keys (cjson_t json, const char *name, char **r_keystring)
{
  cjson_t j_keys, j_item;
  int i, nkeys;
  char *p;
  size_t length;

  *r_keystring = NULL;

  j_keys = cJSON_GetObjectItem (json, name);
  if (!j_keys)
    return gpg_error (GPG_ERR_NO_KEY);
  if (!cjson_is_array (j_keys) && !cjson_is_string (j_keys))
    return gpg_error (GPG_ERR_INV_VALUE);

  /* Fixme: We should better use a membuf like thing.  */
  length = 1; /* For the EOS.  */
  if (cjson_is_string (j_keys))
    {
      nkeys = 1;
      length += strlen (j_keys->valuestring);
      if (strchr (j_keys->valuestring, '\n'))
        return gpg_error (GPG_ERR_INV_USER_ID);
    }
  else
    {
      nkeys = cJSON_GetArraySize (j_keys);
      if (!nkeys)
        return gpg_error (GPG_ERR_NO_KEY);
      for (i=0; i < nkeys; i++)
        {
          j_item = cJSON_GetArrayItem (j_keys, i);
          if (!j_item || !cjson_is_string (j_item))
            return gpg_error (GPG_ERR_INV_VALUE);
          if (i)
            length++; /* Space for delimiter. */
          length += strlen (j_item->valuestring);
          if (strchr (j_item->valuestring, '\n'))
            return gpg_error (GPG_ERR_INV_USER_ID);
        }
    }

  p = *r_keystring = xtrymalloc (length);
  if (!p)
    return gpg_error_from_syserror ();

  if (cjson_is_string (j_keys))
    {
      strcpy (p, j_keys->valuestring);
    }
  else
    {
      for (i=0; i < nkeys; i++)
        {
          j_item = cJSON_GetArrayItem (j_keys, i);
          if (i)
            *p++ = '\n'; /* Add delimiter.  */
          p = stpcpy (p, j_item->valuestring);
        }
    }
  return 0;
}




/*
 *  GPGME support functions.
 */

/* Helper for get_context.  */
static gpgme_ctx_t
_create_new_context (gpgme_protocol_t proto)
{
  gpg_error_t err;
  gpgme_ctx_t ctx;

  err = gpgme_new (&ctx);
  if (err)
    log_fatal ("error creating GPGME context: %s\n", gpg_strerror (err));
  gpgme_set_protocol (ctx, proto);
  gpgme_set_ctx_flag (ctx, "request-origin", "browser");
  return ctx;
}


/* Return a context object for protocol PROTO.  This is currently a
 * statically allocated context initialized for PROTO.  Terminates
 * process on failure.  */
static gpgme_ctx_t
get_context (gpgme_protocol_t proto)
{
  static gpgme_ctx_t ctx_openpgp, ctx_cms, ctx_conf;

  if (proto == GPGME_PROTOCOL_OpenPGP)
    {
      if (!ctx_openpgp)
        ctx_openpgp = _create_new_context (proto);
      return ctx_openpgp;
    }
  else if (proto == GPGME_PROTOCOL_CMS)
    {
      if (!ctx_cms)
        ctx_cms = _create_new_context (proto);
      return ctx_cms;
    }
  else if (proto == GPGME_PROTOCOL_GPGCONF)
    {
      if (!ctx_conf)
        ctx_conf = _create_new_context (proto);
      return ctx_conf;
    }
  else
    log_bug ("invalid protocol %d requested\n", proto);
}


/* Free context object retrieved by get_context.  */
static void
release_context (gpgme_ctx_t ctx)
{
  /* Nothing to do right now.  */
  (void)ctx;
}


/* Create an addition context for short operations. */
static gpgme_ctx_t
create_onetime_context (gpgme_protocol_t proto)
{
  return _create_new_context (proto);

}


/* Release a one-time context.  */
static void
release_onetime_context (gpgme_ctx_t ctx)
{
  return gpgme_release (ctx);

}


/* Given a Base-64 encoded string object in JSON return a gpgme data
 * object at R_DATA.  */
static gpg_error_t
data_from_base64_string (gpgme_data_t *r_data, cjson_t json)
{
  gpg_error_t err;
  size_t len;
  char *buf = NULL;
  gpgrt_b64state_t state = NULL;
  gpgme_data_t data = NULL;

  *r_data = NULL;

  /* A quick check on the JSON.  */
  if (!cjson_is_string (json))
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      goto leave;
    }

  state = gpgrt_b64dec_start (NULL);
  if (!state)
    {
      err = gpg_err_code_from_syserror ();
      goto leave;
    }

  /* Fixme: Data duplication - we should see how to snatch the memory
   * from the json object.  */
  len = strlen (json->valuestring);
  buf = xtrystrdup (json->valuestring);
  if (!buf)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  err = gpgrt_b64dec_proc (state, buf, len, &len);
  if (err)
    goto leave;

  err = gpgrt_b64dec_finish (state);
  state = NULL;
  if (err)
    goto leave;

  err = gpgme_data_new_from_mem (&data, buf, len, 1);
  if (err)
    goto leave;
  *r_data = data;
  data = NULL;

 leave:
  xfree (data);
  xfree (buf);
  gpgrt_b64dec_finish (state);
  return err;
}


/* Create a keylist pattern array from a json keys object
 * in the request. Returns either a malloced NULL terminated
 * string array which can be used as patterns for
 * op_keylist_ext or NULL. */
static char **
create_keylist_patterns (cjson_t request, const char *name)
{
  char *keystring;
  char *p;
  char *tmp;
  char **ret;
  int cnt = 2; /* Last NULL and one is not newline delimited */
  int i = 0;

  if (get_keys (request, name, &keystring))
    return NULL;

  for (p = keystring; *p; p++)
    if (*p == '\n')
      cnt++;

  ret = xcalloc (cnt, sizeof *ret);

  for (p = keystring, tmp = keystring; *p; p++)
    {
      if (*p != '\n')
        continue;
      *p = '\0';
      ret[i++] = xstrdup (tmp);
      tmp = p + 1;
    }
  /* The last key is not newline delimited. */
  ret[i] = *tmp ? xstrdup (tmp) : NULL;

  xfree (keystring);
  return ret;
}


/* Do a secret keylisting for protocol proto and add the fingerprints of
   the secret keys for patterns to the result as "sec-fprs" array. */
static gpg_error_t
add_secret_fprs (const char **patterns, gpgme_protocol_t protocol,
                 cjson_t result)
{
  gpgme_ctx_t ctx;
  gpg_error_t err;
  gpgme_key_t key = NULL;
  cjson_t j_fprs = xjson_CreateArray ();

  ctx = create_onetime_context (protocol);

  gpgme_set_keylist_mode (ctx, GPGME_KEYLIST_MODE_LOCAL |
                               GPGME_KEYLIST_MODE_WITH_SECRET);

  err = gpgme_op_keylist_ext_start (ctx, patterns, 1, 0);

  if (err)
    {
      gpg_error_object (result, err, "Error listing keys: %s",
                        gpg_strerror (err));
      goto leave;
    }

  while (!(err = gpgme_op_keylist_next (ctx, &key)))
    {
      if (!key || !key->fpr)
        continue;
      cJSON_AddItemToArray (j_fprs, cJSON_CreateString (key->fpr));
      gpgme_key_unref (key);
      key = NULL;
    }
  err = 0;

  release_onetime_context (ctx);
  ctx = NULL;

  xjson_AddItemToObject (result, "sec-fprs", j_fprs);

leave:
  release_onetime_context (ctx);
  gpgme_key_unref (key);

  return err;
}


/* Create sigsum json array */
static cjson_t
sigsum_to_json (gpgme_sigsum_t summary)
{
  cjson_t result = xjson_CreateObject ();
  cjson_t sigsum_array = xjson_CreateArray ();

  if ( (summary & GPGME_SIGSUM_VALID      ))
    cJSON_AddItemToArray (sigsum_array,
        cJSON_CreateString ("valid"));
  if ( (summary & GPGME_SIGSUM_GREEN      ))
    cJSON_AddItemToArray (sigsum_array,
        cJSON_CreateString ("green"));
  if ( (summary & GPGME_SIGSUM_RED        ))
    cJSON_AddItemToArray (sigsum_array,
        cJSON_CreateString ("red"));
  if ( (summary & GPGME_SIGSUM_KEY_REVOKED))
    cJSON_AddItemToArray (sigsum_array,
        cJSON_CreateString ("revoked"));
  if ( (summary & GPGME_SIGSUM_KEY_EXPIRED))
    cJSON_AddItemToArray (sigsum_array,
        cJSON_CreateString ("key-expired"));
  if ( (summary & GPGME_SIGSUM_SIG_EXPIRED))
    cJSON_AddItemToArray (sigsum_array,
        cJSON_CreateString ("sig-expired"));
  if ( (summary & GPGME_SIGSUM_KEY_MISSING))
    cJSON_AddItemToArray (sigsum_array,
        cJSON_CreateString ("key-missing"));
  if ( (summary & GPGME_SIGSUM_CRL_MISSING))
    cJSON_AddItemToArray (sigsum_array,
        cJSON_CreateString ("crl-missing"));
  if ( (summary & GPGME_SIGSUM_CRL_TOO_OLD))
    cJSON_AddItemToArray (sigsum_array,
        cJSON_CreateString ("crl-too-old"));
  if ( (summary & GPGME_SIGSUM_BAD_POLICY ))
    cJSON_AddItemToArray (sigsum_array,
        cJSON_CreateString ("bad-policy"));
  if ( (summary & GPGME_SIGSUM_SYS_ERROR  ))
    cJSON_AddItemToArray (sigsum_array,
        cJSON_CreateString ("sys-error"));
  /* The signature summary as string array. */
  xjson_AddItemToObject (result, "sigsum", sigsum_array);

  /* Bools for the same. */
  xjson_AddBoolToObject (result, "valid",
                         (summary & GPGME_SIGSUM_VALID      ));
  xjson_AddBoolToObject (result, "green",
                         (summary & GPGME_SIGSUM_GREEN      ));
  xjson_AddBoolToObject (result, "red",
                         (summary & GPGME_SIGSUM_RED        ));
  xjson_AddBoolToObject (result, "revoked",
                         (summary & GPGME_SIGSUM_KEY_REVOKED));
  xjson_AddBoolToObject (result, "key-expired",
                         (summary & GPGME_SIGSUM_KEY_EXPIRED));
  xjson_AddBoolToObject (result, "sig-expired",
                         (summary & GPGME_SIGSUM_SIG_EXPIRED));
  xjson_AddBoolToObject (result, "key-missing",
                         (summary & GPGME_SIGSUM_KEY_MISSING));
  xjson_AddBoolToObject (result, "crl-missing",
                         (summary & GPGME_SIGSUM_CRL_MISSING));
  xjson_AddBoolToObject (result, "crl-too-old",
                         (summary & GPGME_SIGSUM_CRL_TOO_OLD));
  xjson_AddBoolToObject (result, "bad-policy",
                         (summary & GPGME_SIGSUM_BAD_POLICY ));
  xjson_AddBoolToObject (result, "sys-error",
                         (summary & GPGME_SIGSUM_SYS_ERROR  ));

  return result;
}


/* Helper for summary formatting */
static const char *
validity_to_string (gpgme_validity_t val)
{
  switch (val)
    {
    case GPGME_VALIDITY_UNDEFINED:return "undefined";
    case GPGME_VALIDITY_NEVER:    return "never";
    case GPGME_VALIDITY_MARGINAL: return "marginal";
    case GPGME_VALIDITY_FULL:     return "full";
    case GPGME_VALIDITY_ULTIMATE: return "ultimate";
    case GPGME_VALIDITY_UNKNOWN:
    default:                      return "unknown";
    }
}

static const char *
protocol_to_string (gpgme_protocol_t proto)
{
  switch (proto)
    {
    case GPGME_PROTOCOL_OpenPGP: return "OpenPGP";
    case GPGME_PROTOCOL_CMS:     return "CMS";
    case GPGME_PROTOCOL_GPGCONF: return "gpgconf";
    case GPGME_PROTOCOL_ASSUAN:  return "assuan";
    case GPGME_PROTOCOL_G13:     return "g13";
    case GPGME_PROTOCOL_UISERVER:return "uiserver";
    case GPGME_PROTOCOL_SPAWN:   return "spawn";
    default:
                                 return "unknown";
    }
}

/* Create a sig_notation json object */
static cjson_t
sig_notation_to_json (gpgme_sig_notation_t not)
{
  cjson_t result = xjson_CreateObject ();
  xjson_AddBoolToObject (result, "human_readable", not->human_readable);
  xjson_AddBoolToObject (result, "critical", not->critical);

  xjson_AddStringToObject0 (result, "name", not->name);
  xjson_AddStringToObject0 (result, "value", not->value);

  xjson_AddNumberToObject (result, "flags", not->flags);

  return result;
}

/* Create a key_sig json object */
static cjson_t
key_sig_to_json (gpgme_key_sig_t sig)
{
  cjson_t result = xjson_CreateObject ();

  xjson_AddBoolToObject (result, "revoked", sig->revoked);
  xjson_AddBoolToObject (result, "expired", sig->expired);
  xjson_AddBoolToObject (result, "invalid", sig->invalid);
  xjson_AddBoolToObject (result, "exportable", sig->exportable);

  xjson_AddStringToObject0 (result, "pubkey_algo_name",
                            gpgme_pubkey_algo_name (sig->pubkey_algo));
  xjson_AddStringToObject0 (result, "keyid", sig->keyid);
  xjson_AddStringToObject0 (result, "status", gpgme_strerror (sig->status));
  xjson_AddStringToObject0 (result, "name", sig->name);
  xjson_AddStringToObject0 (result, "email", sig->email);
  xjson_AddStringToObject0 (result, "comment", sig->comment);

  xjson_AddNumberToObject (result, "pubkey_algo", sig->pubkey_algo);
  xjson_AddNumberToObject (result, "timestamp", sig->timestamp);
  xjson_AddNumberToObject (result, "expires", sig->expires);
  xjson_AddNumberToObject (result, "status_code", sig->status);
  xjson_AddNumberToObject (result, "sig_class", sig->sig_class);

  if (sig->notations)
    {
      gpgme_sig_notation_t not;
      cjson_t array = xjson_CreateArray ();
      for (not = sig->notations; not; not = not->next)
        cJSON_AddItemToArray (array, sig_notation_to_json (not));
      xjson_AddItemToObject (result, "notations", array);
    }

  return result;
}

/* Create a tofu info object */
static cjson_t
tofu_to_json (gpgme_tofu_info_t tofu)
{
  cjson_t result = xjson_CreateObject ();

  xjson_AddStringToObject0 (result, "description", tofu->description);

  xjson_AddNumberToObject (result, "validity", tofu->validity);
  xjson_AddNumberToObject (result, "policy", tofu->policy);
  xjson_AddNumberToObject (result, "signcount", tofu->signcount);
  xjson_AddNumberToObject (result, "encrcount", tofu->encrcount);
  xjson_AddNumberToObject (result, "signfirst", tofu->signfirst);
  xjson_AddNumberToObject (result, "signlast", tofu->signlast);
  xjson_AddNumberToObject (result, "encrfirst", tofu->encrfirst);
  xjson_AddNumberToObject (result, "encrlast", tofu->encrlast);

  return result;
}

/* Create a userid json object */
static cjson_t
uid_to_json (gpgme_user_id_t uid)
{
  cjson_t result = xjson_CreateObject ();

  xjson_AddBoolToObject (result, "revoked", uid->revoked);
  xjson_AddBoolToObject (result, "invalid", uid->invalid);

  xjson_AddStringToObject0 (result, "validity",
                            validity_to_string (uid->validity));
  xjson_AddStringToObject0 (result, "uid", uid->uid);
  xjson_AddStringToObject0 (result, "name", uid->name);
  xjson_AddStringToObject0 (result, "email", uid->email);
  xjson_AddStringToObject0 (result, "comment", uid->comment);
  xjson_AddStringToObject0 (result, "address", uid->address);

  xjson_AddNumberToObject (result, "origin", uid->origin);
  xjson_AddNumberToObject (result, "last_update", uid->last_update);

  /* Key sigs */
  if (uid->signatures)
    {
      cjson_t sig_array = xjson_CreateArray ();
      gpgme_key_sig_t sig;

      for (sig = uid->signatures; sig; sig = sig->next)
        cJSON_AddItemToArray (sig_array, key_sig_to_json (sig));

      xjson_AddItemToObject (result, "signatures", sig_array);
    }

  /* TOFU info */
  if (uid->tofu)
    {
      gpgme_tofu_info_t tofu;
      cjson_t array = xjson_CreateArray ();
      for (tofu = uid->tofu; tofu; tofu = tofu->next)
        cJSON_AddItemToArray (array, tofu_to_json (tofu));
      xjson_AddItemToObject (result, "tofu", array);
    }

  return result;
}

/* Create a subkey json object */
static cjson_t
subkey_to_json (gpgme_subkey_t sub)
{
  cjson_t result = xjson_CreateObject ();
  char *tmp;

  xjson_AddBoolToObject (result, "revoked", sub->revoked);
  xjson_AddBoolToObject (result, "expired", sub->expired);
  xjson_AddBoolToObject (result, "disabled", sub->disabled);
  xjson_AddBoolToObject (result, "invalid", sub->invalid);
  xjson_AddBoolToObject (result, "can_encrypt", sub->can_encrypt);
  xjson_AddBoolToObject (result, "can_sign", sub->can_sign);
  xjson_AddBoolToObject (result, "can_certify", sub->can_certify);
  xjson_AddBoolToObject (result, "can_authenticate", sub->can_authenticate);
  xjson_AddBoolToObject (result, "secret", sub->secret);
  xjson_AddBoolToObject (result, "is_qualified", sub->is_qualified);
  xjson_AddBoolToObject (result, "is_cardkey", sub->is_cardkey);
  xjson_AddBoolToObject (result, "is_de_vs", sub->is_de_vs);
  xjson_AddStringToObject0 (result, "pubkey_algo_name",
                            gpgme_pubkey_algo_name (sub->pubkey_algo));

  tmp = gpgme_pubkey_algo_string (sub);
  xjson_AddStringToObject0 (result, "pubkey_algo_string", tmp);
  gpgme_free (tmp);

  xjson_AddStringToObject0 (result, "keyid", sub->keyid);
  xjson_AddStringToObject0 (result, "card_number", sub->card_number);
  xjson_AddStringToObject0 (result, "curve", sub->curve);
  xjson_AddStringToObject0 (result, "keygrip", sub->keygrip);

  xjson_AddNumberToObject (result, "pubkey_algo", sub->pubkey_algo);
  xjson_AddNumberToObject (result, "length", sub->length);
  xjson_AddNumberToObject (result, "timestamp", sub->timestamp);
  xjson_AddNumberToObject (result, "expires", sub->expires);

  return result;
}

/* Create a revocation key json object */
static cjson_t
revocation_key_to_json (gpgme_revocation_key_t revkey)
{
  cjson_t result = xjson_CreateObject ();

  xjson_AddBoolToObject (result, "sensitive", revkey->sensitive);

  xjson_AddStringToObject0 (result, "fingerprint", revkey->fpr);
  xjson_AddStringToObject0 (result, "pubkey_algo_name",
                            gpgme_pubkey_algo_name (revkey->pubkey_algo));

  xjson_AddNumberToObject (result, "pubkey_algo", revkey->pubkey_algo);
  xjson_AddNumberToObject (result, "key_class", revkey->key_class);

  return result;
}

/* Create a key json object */
static cjson_t
key_to_json (gpgme_key_t key)
{
  cjson_t result = xjson_CreateObject ();

  xjson_AddBoolToObject (result, "revoked", key->revoked);
  xjson_AddBoolToObject (result, "expired", key->expired);
  xjson_AddBoolToObject (result, "disabled", key->disabled);
  xjson_AddBoolToObject (result, "invalid", key->invalid);
  xjson_AddBoolToObject (result, "can_encrypt", key->can_encrypt);
  xjson_AddBoolToObject (result, "can_sign", key->can_sign);
  xjson_AddBoolToObject (result, "can_certify", key->can_certify);
  xjson_AddBoolToObject (result, "can_authenticate", key->can_authenticate);
  xjson_AddBoolToObject (result, "secret", key->secret);
  xjson_AddBoolToObject (result, "is_qualified", key->is_qualified);

  xjson_AddStringToObject0 (result, "protocol",
                            protocol_to_string (key->protocol));
  xjson_AddStringToObject0 (result, "issuer_serial", key->issuer_serial);
  xjson_AddStringToObject0 (result, "issuer_name", key->issuer_name);
  xjson_AddStringToObject0 (result, "fingerprint", key->fpr);
  xjson_AddStringToObject0 (result, "chain_id", key->chain_id);
  xjson_AddStringToObject0 (result, "owner_trust",
                            validity_to_string (key->owner_trust));

  xjson_AddNumberToObject (result, "origin", key->origin);
  xjson_AddNumberToObject (result, "last_update", key->last_update);

  /* Add subkeys */
  if (key->subkeys)
    {
      cjson_t subkey_array = xjson_CreateArray ();
      gpgme_subkey_t sub;
      for (sub = key->subkeys; sub; sub = sub->next)
        cJSON_AddItemToArray (subkey_array, subkey_to_json (sub));

      xjson_AddItemToObject (result, "subkeys", subkey_array);
    }

  /* User Ids */
  if (key->uids)
    {
      cjson_t uid_array = xjson_CreateArray ();
      gpgme_user_id_t uid;
      for (uid = key->uids; uid; uid = uid->next)
        cJSON_AddItemToArray (uid_array, uid_to_json (uid));

      xjson_AddItemToObject (result, "userids", uid_array);
    }

  /* Revocation keys */
  if (key->revocation_keys)
    {
      gpgme_revocation_key_t revkey;
      cjson_t array = xjson_CreateArray ();
      for (revkey = key->revocation_keys; revkey; revkey = revkey->next)
        cJSON_AddItemToArray (array, revocation_key_to_json (revkey));
      xjson_AddItemToObject (result, "revocation_keys", array);
    }

  return result;
}


/* Create a signature json object */
static cjson_t
signature_to_json (gpgme_signature_t sig)
{
  cjson_t result = xjson_CreateObject ();

  xjson_AddItemToObject (result, "summary", sigsum_to_json (sig->summary));

  xjson_AddBoolToObject (result, "wrong_key_usage", sig->wrong_key_usage);
  xjson_AddBoolToObject (result, "chain_model", sig->chain_model);
  xjson_AddBoolToObject (result, "is_de_vs", sig->is_de_vs);

  xjson_AddStringToObject0 (result, "status_string",
                            gpgme_strerror (sig->status));
  xjson_AddStringToObject0 (result, "fingerprint", sig->fpr);
  xjson_AddStringToObject0 (result, "validity_string",
                            validity_to_string (sig->validity));
  xjson_AddStringToObject0 (result, "pubkey_algo_name",
                            gpgme_pubkey_algo_name (sig->pubkey_algo));
  xjson_AddStringToObject0 (result, "hash_algo_name",
                            gpgme_hash_algo_name (sig->hash_algo));
  xjson_AddStringToObject0 (result, "pka_address", sig->pka_address);

  xjson_AddNumberToObject (result, "status_code", sig->status);
  xjson_AddNumberToObject (result, "timestamp", sig->timestamp);
  xjson_AddNumberToObject (result, "exp_timestamp", sig->exp_timestamp);
  xjson_AddNumberToObject (result, "pka_trust", sig->pka_trust);
  xjson_AddNumberToObject (result, "validity", sig->validity);
  xjson_AddNumberToObject (result, "validity_reason", sig->validity_reason);

  if (sig->notations)
    {
      gpgme_sig_notation_t not;
      cjson_t array = xjson_CreateArray ();
      for (not = sig->notations; not; not = not->next)
        cJSON_AddItemToArray (array, sig_notation_to_json (not));
      xjson_AddItemToObject (result, "notations", array);
    }

  return result;
}


/* Create a JSON object from a gpgme_verify result */
static cjson_t
verify_result_to_json (gpgme_verify_result_t verify_result)
{
  cjson_t result = xjson_CreateObject ();

  xjson_AddBoolToObject (result, "is_mime", verify_result->is_mime);

  if (verify_result->signatures)
    {
      cjson_t array = xjson_CreateArray ();
      gpgme_signature_t sig;

      for (sig = verify_result->signatures; sig; sig = sig->next)
        cJSON_AddItemToArray (array, signature_to_json (sig));
      xjson_AddItemToObject (result, "signatures", array);
    }

  return result;
}

/* Create a recipient json object */
static cjson_t
recipient_to_json (gpgme_recipient_t recp)
{
  cjson_t result = xjson_CreateObject ();

  xjson_AddStringToObject0 (result, "keyid", recp->keyid);
  xjson_AddStringToObject0 (result, "pubkey_algo_name",
                            gpgme_pubkey_algo_name (recp->pubkey_algo));
  xjson_AddStringToObject0 (result, "status_string",
                            gpgme_strerror (recp->status));

  xjson_AddNumberToObject (result, "status_code", recp->status);

  return result;
}


/* Create a JSON object from a gpgme_decrypt result */
static cjson_t
decrypt_result_to_json (gpgme_decrypt_result_t decrypt_result)
{
  cjson_t result = xjson_CreateObject ();

  xjson_AddStringToObject0 (result, "file_name", decrypt_result->file_name);
  xjson_AddStringToObject0 (result, "symkey_algo",
                            decrypt_result->symkey_algo);

  xjson_AddBoolToObject (result, "wrong_key_usage",
                         decrypt_result->wrong_key_usage);
  xjson_AddBoolToObject (result, "is_de_vs",
                         decrypt_result->is_de_vs);
  xjson_AddBoolToObject (result, "is_mime", decrypt_result->is_mime);
  xjson_AddBoolToObject (result, "legacy_cipher_nomdc",
                         decrypt_result->legacy_cipher_nomdc);

  if (decrypt_result->recipients)
    {
      cjson_t array = xjson_CreateArray ();
      gpgme_recipient_t recp;

      for (recp = decrypt_result->recipients; recp; recp = recp->next)
        cJSON_AddItemToArray (array, recipient_to_json (recp));
      xjson_AddItemToObject (result, "recipients", array);
    }

  return result;
}


/* Create a JSON object from an engine_info */
static cjson_t
engine_info_to_json (gpgme_engine_info_t info)
{
  cjson_t result = xjson_CreateObject ();

  xjson_AddStringToObject0 (result, "protocol",
                            protocol_to_string (info->protocol));
  xjson_AddStringToObject0 (result, "fname", info->file_name);
  xjson_AddStringToObject0 (result, "version", info->version);
  xjson_AddStringToObject0 (result, "req_version", info->req_version);
  xjson_AddStringToObject0 (result, "homedir", info->home_dir ?
                                                info->home_dir :
                                                "default");
  return result;
}


/* Create a JSON object from an import_status */
static cjson_t
import_status_to_json (gpgme_import_status_t sts)
{
  cjson_t result = xjson_CreateObject ();

  xjson_AddStringToObject0 (result, "fingerprint", sts->fpr);
  xjson_AddStringToObject0 (result, "error_string",
                            gpgme_strerror (sts->result));

  xjson_AddNumberToObject (result, "status", sts->status);

  return result;
}

/* Create a JSON object from an import result */
static cjson_t
import_result_to_json (gpgme_import_result_t imp)
{
  cjson_t result = xjson_CreateObject ();

  xjson_AddNumberToObject (result, "considered", imp->considered);
  xjson_AddNumberToObject (result, "no_user_id", imp->no_user_id);
  xjson_AddNumberToObject (result, "imported", imp->imported);
  xjson_AddNumberToObject (result, "imported_rsa", imp->imported_rsa);
  xjson_AddNumberToObject (result, "unchanged", imp->unchanged);
  xjson_AddNumberToObject (result, "new_user_ids", imp->new_user_ids);
  xjson_AddNumberToObject (result, "new_sub_keys", imp->new_sub_keys);
  xjson_AddNumberToObject (result, "new_signatures", imp->new_signatures);
  xjson_AddNumberToObject (result, "new_revocations", imp->new_revocations);
  xjson_AddNumberToObject (result, "secret_read", imp->secret_read);
  xjson_AddNumberToObject (result, "secret_imported", imp->secret_imported);
  xjson_AddNumberToObject (result, "secret_unchanged", imp->secret_unchanged);
  xjson_AddNumberToObject (result, "skipped_new_keys", imp->skipped_new_keys);
  xjson_AddNumberToObject (result, "not_imported", imp->not_imported);
  xjson_AddNumberToObject (result, "skipped_v3_keys", imp->skipped_v3_keys);


  if (imp->imports)
    {
      cjson_t array = xjson_CreateArray ();
      gpgme_import_status_t status;

      for (status = imp->imports; status; status = status->next)
        cJSON_AddItemToArray (array, import_status_to_json (status));
      xjson_AddItemToObject (result, "imports", array);
    }

  return result;
}


/* Create a JSON object from a gpgconf arg */
static cjson_t
conf_arg_to_json (gpgme_conf_arg_t arg, gpgme_conf_type_t type)
{
  cjson_t result = xjson_CreateObject ();
  int is_none = 0;
  switch (type)
    {
      case GPGME_CONF_STRING:
      case GPGME_CONF_PATHNAME:
      case GPGME_CONF_LDAP_SERVER:
      case GPGME_CONF_KEY_FPR:
      case GPGME_CONF_PUB_KEY:
      case GPGME_CONF_SEC_KEY:
      case GPGME_CONF_ALIAS_LIST:
        xjson_AddStringToObject0 (result, "string", arg->value.string);
        break;

      case GPGME_CONF_UINT32:
        xjson_AddNumberToObject (result, "number", arg->value.uint32);
        break;

      case GPGME_CONF_INT32:
        xjson_AddNumberToObject (result, "number", arg->value.int32);
        break;

      case GPGME_CONF_NONE:
      default:
        is_none = 1;
        break;
    }
  xjson_AddBoolToObject (result, "is_none", is_none);
  return result;
}


/* Create a JSON object from a gpgconf option */
static cjson_t
conf_opt_to_json (gpgme_conf_opt_t opt)
{
  cjson_t result = xjson_CreateObject ();

  xjson_AddStringToObject0 (result, "name", opt->name);
  xjson_AddStringToObject0 (result, "description", opt->description);
  xjson_AddStringToObject0 (result, "argname", opt->argname);
  xjson_AddStringToObject0 (result, "default_description",
                            opt->default_description);
  xjson_AddStringToObject0 (result, "no_arg_description",
                            opt->no_arg_description);

  xjson_AddNumberToObject (result, "flags", opt->flags);
  xjson_AddNumberToObject (result, "level", opt->level);
  xjson_AddNumberToObject (result, "type", opt->type);
  xjson_AddNumberToObject (result, "alt_type", opt->alt_type);

  if (opt->default_value)
    {
      cjson_t array = xjson_CreateArray ();
      gpgme_conf_arg_t arg;

      for (arg = opt->default_value; arg; arg = arg->next)
        cJSON_AddItemToArray (array, conf_arg_to_json (arg, opt->alt_type));
      xjson_AddItemToObject (result, "default_value", array);
    }

  if (opt->no_arg_value)
    {
      cjson_t array = xjson_CreateArray ();
      gpgme_conf_arg_t arg;

      for (arg = opt->no_arg_value; arg; arg = arg->next)
        cJSON_AddItemToArray (array, conf_arg_to_json (arg, opt->alt_type));
      xjson_AddItemToObject (result, "no_arg_value", array);
    }

  if (opt->value)
    {
      cjson_t array = xjson_CreateArray ();
      gpgme_conf_arg_t arg;

      for (arg = opt->value; arg; arg = arg->next)
        cJSON_AddItemToArray (array, conf_arg_to_json (arg, opt->alt_type));
      xjson_AddItemToObject (result, "value", array);
    }
  return result;
}


/* Create a JSON object from a gpgconf component*/
static cjson_t
conf_comp_to_json (gpgme_conf_comp_t cmp)
{
  cjson_t result = xjson_CreateObject ();

  xjson_AddStringToObject0 (result, "name", cmp->name);
  xjson_AddStringToObject0 (result, "description", cmp->description);
  xjson_AddStringToObject0 (result, "program_name", cmp->program_name);


  if (cmp->options)
    {
      cjson_t array = xjson_CreateArray ();
      gpgme_conf_opt_t opt;

      for (opt = cmp->options; opt; opt = opt->next)
        cJSON_AddItemToArray (array, conf_opt_to_json (opt));
      xjson_AddItemToObject (result, "options", array);
    }

  return result;
}


/* Create a gpgme_data from json string data named "name"
 * in the request. Takes the base64 option into account.
 *
 * Adds an error to the "result" on error. */
static gpg_error_t
get_string_data (cjson_t request, cjson_t result, const char *name,
                 gpgme_data_t *r_data)
{
  gpgme_error_t err;
  int opt_base64;
  cjson_t j_data;

  if ((err = get_boolean_flag (request, "base64", 0, &opt_base64)))
    return err;

  /* Get the data.  Note that INPUT is a shallow data object with the
   * storage hold in REQUEST.  */
  j_data = cJSON_GetObjectItem (request, name);
  if (!j_data)
    {
      return gpg_error (GPG_ERR_NO_DATA);
    }
  if (!cjson_is_string (j_data))
    {
      return gpg_error (GPG_ERR_INV_VALUE);
    }
  if (opt_base64)
    {
      err = data_from_base64_string (r_data, j_data);
      if (err)
        {
          gpg_error_object (result, err,
                            "Error decoding Base-64 encoded '%s': %s",
                            name, gpg_strerror (err));
          return err;
        }
    }
  else
    {
      err = gpgme_data_new_from_mem (r_data, j_data->valuestring,
                                     strlen (j_data->valuestring), 0);
      if (err)
        {
          gpg_error_object (result, err, "Error getting '%s': %s",
                            name, gpg_strerror (err));
          return err;
        }
    }
  return 0;
}


/* Create a "data" object and the "type" and "base64" flags
 * from DATA and append them to RESULT.  Ownership of DATA is
 * transferred to this function.  TYPE must be a fixed string.
 * If BASE64 is -1 the need for base64 encoding is determined
 * by the content of DATA, all other values are taken as true
 * or false. */
static gpg_error_t
make_data_object (cjson_t result, gpgme_data_t data,
                  const char *type, int base64)
{
  gpg_error_t err;
  char *buffer;
  const char *s;
  size_t buflen, n;

  if (!base64 || base64 == -1) /* Make sure that we really have a string.  */
    gpgme_data_write (data, "", 1);

  buffer = gpgme_data_release_and_get_mem (data, &buflen);
  data = NULL;
  if (!buffer)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  if (base64 == -1)
    {
      base64 = 0;
      if (!buflen)
        log_fatal ("Appended Nul byte got lost\n");
      /* Figure out if there is any Nul octet in the buffer.  In that
       * case we need to Base-64 the buffer.  Due to problems with the
       * browser's Javascript we use Base-64 also in case an UTF-8
       * character is in the buffer.  This is because the chunking may
       * split an UTF-8 characters and JS can't handle this.  */
      for (s=buffer, n=0; n < buflen -1; s++, n++)
        if (!*s || (*s & 0x80))
          {
            buflen--; /* Adjust for the extra nul byte.  */
            base64 = 1;
            break;
          }
    }

  xjson_AddStringToObject (result, "type", type);
  xjson_AddBoolToObject (result, "base64", base64);

  if (base64)
    err = add_base64_to_object (result, "data", buffer, buflen);
  else
    err = cjson_AddStringToObject (result, "data", buffer);

 leave:
  gpgme_free (buffer);
  return err;
}


/* Encode and chunk response.
 *
 * If necessary this base64 encodes and chunks the response
 * for getmore so that we always return valid json independent
 * of the chunksize.
 *
 * A chunked response contains the base64 encoded chunk
 * as a string and a boolean if there is still more data
 * available for getmore like:
 * {
 *   chunk: "SGVsbG8gV29ybGQK"
 *   more: true
 * }
 *
 * Chunking is only done if the response is larger then the
 * chunksize.
 *
 * caller has to xfree the return value.
 */
static char *
encode_and_chunk (ctrl_t ctrl, cjson_t request, cjson_t response)
{
  char *data;
  gpg_error_t err = 0;
  size_t chunksize = 0;
  char *getmore_request = NULL;

  if (ctrl->interactive)
    data = cJSON_Print (response);
  else
    data = cJSON_PrintUnformatted (response);

  if (!data)
    {
      err = GPG_ERR_NO_DATA;
      goto leave;
    }

  if (!request)
    {
      goto leave;
    }

  if ((err = get_chunksize (request, &chunksize)))
    {
      err = GPG_ERR_INV_VALUE;
      goto leave;
    }

  if (!chunksize)
    goto leave;

  ctrl->pending_data.buffer = data;
  /* Data should already be encoded so that it does not
     contain 0.*/
  ctrl->pending_data.length = strlen (data);
  ctrl->pending_data.written = 0;

  if (gpgrt_asprintf (&getmore_request,
                  "{ \"op\":\"getmore\", \"chunksize\": %i }",
                  (int) chunksize) == -1)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  data = json_core_process_request (ctrl, getmore_request);

leave:
  xfree (getmore_request);

  if (!err && !data)
    {
      err = GPG_ERR_GENERAL;
    }

  if (err)
    {
      cjson_t err_obj = gpg_error_object (NULL, err,
                                          "Encode and chunk failed: %s",
                                          gpgme_strerror (err));
      xfree (data);
      if (ctrl->interactive)
        data = cJSON_Print (err_obj);
      else
        data = cJSON_PrintUnformatted (err_obj);

      cJSON_Delete (err_obj);
    }

  return data;
}



/*
 * Implementation of the commands.
 */
static const char hlp_encrypt[] =
  "op:     \"encrypt\"\n"
  "keys:   Array of strings with the fingerprints or user-ids\n"
  "        of the keys to encrypt the data.  For a single key\n"
  "        a String may be used instead of an array.\n"
  "data:   Input data. \n"
  "\n"
  "Optional parameters:\n"
  "protocol:      Either \"openpgp\" (default) or \"cms\".\n"
  "signing_keys:  Similar to the keys parameter for added signing.\n"
  "               (openpgp only)"
  "file_name:     The file name associated with the data.\n"
  "sender:        Sender info to embed in a signature.\n"
  "\n"
  "Optional boolean flags (default is false):\n"
  "base64:        Input data is base64 encoded.\n"
  "mime:          Indicate that data is a MIME object.\n"
  "armor:         Request output in armored format.\n"
  "always-trust:  Request --always-trust option.\n"
  "no-encrypt-to: Do not use a default recipient.\n"
  "no-compress:   Do not compress the plaintext first.\n"
  "throw-keyids:  Request the --throw-keyids option.\n"
  "want-address:  Require that the keys include a mail address.\n"
  "wrap:          Assume the input is an OpenPGP message.\n"
  "\n"
  "Response on success:\n"
  "type:   \"ciphertext\"\n"
  "data:   Unless armor mode is used a Base64 encoded binary\n"
  "        ciphertext.  In armor mode a string with an armored\n"
  "        OpenPGP or a PEM message.\n"
  "base64: Boolean indicating whether data is base64 encoded.";
static gpg_error_t
op_encrypt (ctrl_t ctrl, cjson_t request, cjson_t result)
{
  gpg_error_t err;
  gpgme_ctx_t ctx = NULL;
  gpgme_protocol_t protocol;
  char **signing_patterns = NULL;
  int opt_mime;
  char *keystring = NULL;
  char *file_name = NULL;
  gpgme_data_t input = NULL;
  gpgme_data_t output = NULL;
  int abool;
  gpgme_encrypt_flags_t encrypt_flags = 0;
  gpgme_ctx_t keylist_ctx = NULL;
  gpgme_key_t key = NULL;
  cjson_t j_tmp = NULL;

  (void)ctrl;

  if ((err = get_protocol (request, &protocol)))
    goto leave;
  ctx = get_context (protocol);

  if ((err = get_boolean_flag (request, "mime", 0, &opt_mime)))
    goto leave;

  if ((err = get_boolean_flag (request, "armor", 0, &abool)))
    goto leave;
  gpgme_set_armor (ctx, abool);
  if ((err = get_boolean_flag (request, "always-trust", 0, &abool)))
    goto leave;
  if (abool)
    encrypt_flags |= GPGME_ENCRYPT_ALWAYS_TRUST;
  if ((err = get_boolean_flag (request, "no-encrypt-to", 0,&abool)))
    goto leave;
  if (abool)
    encrypt_flags |= GPGME_ENCRYPT_NO_ENCRYPT_TO;
  if ((err = get_boolean_flag (request, "no-compress", 0, &abool)))
    goto leave;
  if (abool)
    encrypt_flags |= GPGME_ENCRYPT_NO_COMPRESS;
  if ((err = get_boolean_flag (request, "throw-keyids", 0, &abool)))
    goto leave;
  if (abool)
    encrypt_flags |= GPGME_ENCRYPT_THROW_KEYIDS;
  if ((err = get_boolean_flag (request, "wrap", 0, &abool)))
    goto leave;
  if (abool)
    encrypt_flags |= GPGME_ENCRYPT_WRAP;
  if ((err = get_boolean_flag (request, "want-address", 0, &abool)))
    goto leave;
  if (abool)
    encrypt_flags |= GPGME_ENCRYPT_WANT_ADDRESS;

  j_tmp = cJSON_GetObjectItem (request, "file_name");
  if (j_tmp && cjson_is_string (j_tmp))
    {
      file_name = j_tmp->valuestring;
    }

  j_tmp = cJSON_GetObjectItem (request, "sender");
  if (j_tmp && cjson_is_string (j_tmp))
    {
      gpgme_set_sender (ctx, j_tmp->valuestring);
    }

  /* Get the keys.  */
  err = get_keys (request, "keys", &keystring);
  if (err)
    {
      /* Provide a custom error response.  */
      gpg_error_object (result, err, "Error getting keys: %s",
                        gpg_strerror (err));
      goto leave;
    }

  /* Do we have signing keys ? */
  signing_patterns = create_keylist_patterns (request, "signing_keys");
  if (signing_patterns)
    {
      keylist_ctx = create_onetime_context (protocol);
      gpgme_set_keylist_mode (keylist_ctx, GPGME_KEYLIST_MODE_LOCAL);

      err = gpgme_op_keylist_ext_start (keylist_ctx,
                                        (const char **) signing_patterns,
                                        1, 0);
      if (err)
        {
          gpg_error_object (result, err, "Error listing keys: %s",
                            gpg_strerror (err));
          goto leave;
        }
      while (!(err = gpgme_op_keylist_next (keylist_ctx, &key)))
        {
          if ((err = gpgme_signers_add (ctx, key)))
            {
              gpg_error_object (result, err, "Error adding signer: %s",
                                gpg_strerror (err));
              goto leave;
            }
          gpgme_key_unref (key);
          key = NULL;
        }
      release_onetime_context (keylist_ctx);
      keylist_ctx = NULL;
    }

  if ((err = get_string_data (request, result, "data", &input)))
      goto leave;

  if (opt_mime)
    gpgme_data_set_encoding (input, GPGME_DATA_ENCODING_MIME);

  if (file_name)
    {
      gpgme_data_set_file_name (input, file_name);
    }

  /* Create an output data object.  */
  err = gpgme_data_new (&output);
  if (err)
    {
      gpg_error_object (result, err, "Error creating output data object: %s",
                        gpg_strerror (err));
      goto leave;
    }

  /* Encrypt.  */
  if (!signing_patterns)
    {
      err = gpgme_op_encrypt_ext (ctx, NULL, keystring, encrypt_flags,
                                  input, output);
    }
  else
    {
      err = gpgme_op_encrypt_sign_ext (ctx, NULL, keystring, encrypt_flags,
                                       input, output);

    }
  /* encrypt_result = gpgme_op_encrypt_result (ctx); */
  if (err)
    {
      gpg_error_object (result, err, "Encryption failed: %s",
                        gpg_strerror (err));
      goto leave;
    }
  gpgme_data_release (input);
  input = NULL;

  /* We need to base64 if armoring has not been requested.  */
  err = make_data_object (result, output,
                          "ciphertext", !gpgme_get_armor (ctx));
  output = NULL;

 leave:
  xfree_array (signing_patterns);
  xfree (keystring);
  release_onetime_context (keylist_ctx);
  /* Reset sender in case the context is reused */
  gpgme_set_sender (ctx, NULL);
  gpgme_key_unref (key);
  gpgme_signers_clear (ctx);
  release_context (ctx);
  gpgme_data_release (input);
  gpgme_data_release (output);
  return err;
}



static const char hlp_decrypt[] =
  "op:     \"decrypt\"\n"
  "data:   The encrypted data.\n"
  "\n"
  "Optional parameters:\n"
  "protocol:      Either \"openpgp\" (default) or \"cms\".\n"
  "\n"
  "Optional boolean flags (default is false):\n"
  "base64:        Input data is base64 encoded.\n"
  "\n"
  "Response on success:\n"
  "type:     \"plaintext\"\n"
  "data:     The decrypted data.  This may be base64 encoded.\n"
  "base64:   Boolean indicating whether data is base64 encoded.\n"
  "mime:     deprecated - use dec_info is_mime instead\n"
  "dec_info: An object with decryption information. (gpgme_decrypt_result_t)\n"
  " Boolean values:\n"
  "  wrong_key_usage:     Key should not have been used for encryption.\n"
  "  is_de_vs:            Message was encrypted in compliance to the de-vs\n"
  "                       mode.\n"
  "  is_mime:             Message claims that the content is a MIME Message.\n"
  "  legacy_cipher_nomdc: The message was made by a legacy algorithm\n"
  "                       without integrity protection.\n"
  " String values:\n"
  "  file_name:   The filename contained in the decrypt result.\n"
  "  symkey_algo: A string with the symmetric encryption algorithm and\n"
  "               mode using the format \"<algo>.<mode>\".\n"
  " Array values:\n"
  "  recipients:  The list of recipients (gpgme_recipient_t).\n"
  "   String values:\n"
  "    keyid:            The keyid of the recipient.\n"
  "    pubkey_algo_name: gpgme_pubkey_algo_name of used algo.\n"
  "    status_string:    The status code as localized gpg-error string\n"
  "   Number values:\n"
  "    status_code:      The status as a number. (gpg_error_t)\n"
  "info:     Optional an object with verification information.\n"
  "          (gpgme_verify_result_t)\n"
  " file_name: The filename contained in the verify result.\n"
  " is_mime:   The is_mime info contained in the verify result.\n"
  " signatures: Array of signatures\n"
  "  summary: Object containing summary information.\n"
  "   Boolean values: (Check gpgme_sigsum_t doc for meaning)\n"
  "    valid\n"
  "    green\n"
  "    red\n"
  "    revoked\n"
  "    key-expired\n"
  "    sig-expired\n"
  "    key-missing\n"
  "    crl-missing\n"
  "    crl-too-old\n"
  "    bad-policy\n"
  "    sys-error\n"
  "   sigsum: Array of strings representing the sigsum.\n"
  "  Boolean values:\n"
  "   wrong_key_usage: Key should not have been used for signing.\n"
  "   chain_model:     Validity has been verified using the chain model.\n"
  "   is_de_vs:        signature is in compliance to the de-vs mode.\n"
  "  String values:\n"
  "   status_string:      The status code as localized gpg-error string\n"
  "   fingerprint:        The fingerprint of the signing key.\n"
  "   validity_string:    The validity as string.\n"
  "   pubkey_algo_name:   gpgme_pubkey_algo_name of used algo.\n"
  "   hash_algo_name:     gpgme_hash_algo_name of used hash algo\n"
  "   pka_address:        The mailbox from the PKA information.\n"
  "  Number values:\n"
  "   status_code:     The status as a number. (gpg_error_t)\n"
  "   timestamp:       Signature creation time. (secs since epoch)\n"
  "   exp_timestamp:   Signature expiration or 0. (secs since epoch)\n"
  "   pka_trust: PKA status: 0 = not available, 1 = bad, 2 = okay, 3 = RFU.\n"
  "   validity: validity as number (gpgme_validity_t)\n"
  "   validity_reason: (gpg_error_t)\n"
  "  Array values:\n"
  "   notations: Notation data and policy urls (gpgme_sig_notation_t)\n"
  "    Boolean values:\n"
  "     human_readable\n"
  "     critical\n"
  "    String values:\n"
  "     name\n"
  "     value\n"
  "    Number values:\n"
  "     flags\n";
static gpg_error_t
op_decrypt (ctrl_t ctrl, cjson_t request, cjson_t result)
{
  gpg_error_t err;
  gpgme_ctx_t ctx = NULL;
  gpgme_protocol_t protocol;
  gpgme_data_t input = NULL;
  gpgme_data_t output = NULL;
  gpgme_decrypt_result_t decrypt_result;
  gpgme_verify_result_t verify_result;

  (void)ctrl;

  if ((err = get_protocol (request, &protocol)))
    goto leave;
  ctx = get_context (protocol);

  if ((err = get_string_data (request, result, "data", &input)))
      goto leave;

  /* Create an output data object.  */
  err = gpgme_data_new (&output);
  if (err)
    {
      gpg_error_object (result, err,
                        "Error creating output data object: %s",
                        gpg_strerror (err));
      goto leave;
    }

  /* Decrypt.  */
  err = gpgme_op_decrypt_ext (ctx, GPGME_DECRYPT_VERIFY,
                              input, output);
  decrypt_result = gpgme_op_decrypt_result (ctx);
  if (err)
    {
      gpg_error_object (result, err, "Decryption failed: %s",
                        gpg_strerror (err));
      goto leave;
    }
  gpgme_data_release (input);
  input = NULL;

  if (decrypt_result->is_mime)
    xjson_AddBoolToObject (result, "mime", 1);

  xjson_AddItemToObject (result, "dec_info",
                         decrypt_result_to_json (decrypt_result));

  verify_result = gpgme_op_verify_result (ctx);
  if (verify_result && verify_result->signatures)
    {
      xjson_AddItemToObject (result, "info",
                             verify_result_to_json (verify_result));
    }

  err = make_data_object (result, output, "plaintext", -1);
  output = NULL;

  if (err)
    {
      gpg_error_object (result, err, "Plaintext output failed: %s",
                        gpg_strerror (err));
      goto leave;
    }

 leave:
  release_context (ctx);
  gpgme_data_release (input);
  gpgme_data_release (output);
  return err;
}



static const char hlp_sign[] =
  "op:     \"sign\"\n"
  "keys:   Array of strings with the fingerprints of the signing key.\n"
  "        For a single key a String may be used instead of an array.\n"
  "data:   Input data. \n"
  "\n"
  "Optional parameters:\n"
  "protocol:      Either \"openpgp\" (default) or \"cms\".\n"
  "sender:        The mail address of the sender.\n"
  "mode:          A string with the signing mode can be:\n"
  "               detached (default)\n"
  "               opaque\n"
  "               clearsign\n"
  "\n"
  "Optional boolean flags (default is false):\n"
  "base64:        Input data is base64 encoded.\n"
  "armor:         Request output in armored format.\n"
  "\n"
  "Response on success:\n"
  "type:   \"signature\"\n"
  "data:   Unless armor mode is used a Base64 encoded binary\n"
  "        signature.  In armor mode a string with an armored\n"
  "        OpenPGP or a PEM message.\n"
  "base64: Boolean indicating whether data is base64 encoded.\n";
static gpg_error_t
op_sign (ctrl_t ctrl, cjson_t request, cjson_t result)
{
  gpg_error_t err;
  gpgme_ctx_t ctx = NULL;
  gpgme_protocol_t protocol;
  char **patterns = NULL;
  gpgme_data_t input = NULL;
  gpgme_data_t output = NULL;
  int abool;
  cjson_t j_tmp;
  gpgme_sig_mode_t mode = GPGME_SIG_MODE_DETACH;
  gpgme_ctx_t keylist_ctx = NULL;
  gpgme_key_t key = NULL;

  (void)ctrl;

  if ((err = get_protocol (request, &protocol)))
    goto leave;
  ctx = get_context (protocol);

  if ((err = get_boolean_flag (request, "armor", 0, &abool)))
    goto leave;
  gpgme_set_armor (ctx, abool);

  j_tmp = cJSON_GetObjectItem (request, "mode");
  if (j_tmp && cjson_is_string (j_tmp))
    {
      if (!strcmp (j_tmp->valuestring, "opaque"))
        {
          mode = GPGME_SIG_MODE_NORMAL;
        }
      else if (!strcmp (j_tmp->valuestring, "clearsign"))
        {
          mode = GPGME_SIG_MODE_CLEAR;
        }
    }

  j_tmp = cJSON_GetObjectItem (request, "sender");
  if (j_tmp && cjson_is_string (j_tmp))
    {
      gpgme_set_sender (ctx, j_tmp->valuestring);
    }

  patterns = create_keylist_patterns (request, "keys");
  if (!patterns)
    {
      gpg_error_object (result, err, "Error getting keys: %s",
                        gpg_strerror (gpg_error (GPG_ERR_NO_KEY)));
      goto leave;
    }

  /* Do a keylisting and add the keys */
  keylist_ctx = create_onetime_context (protocol);
  gpgme_set_keylist_mode (keylist_ctx, GPGME_KEYLIST_MODE_LOCAL);

  err = gpgme_op_keylist_ext_start (keylist_ctx,
                                    (const char **) patterns, 1, 0);
  if (err)
    {
      gpg_error_object (result, err, "Error listing keys: %s",
                        gpg_strerror (err));
      goto leave;
    }
  while (!(err = gpgme_op_keylist_next (keylist_ctx, &key)))
    {
      if ((err = gpgme_signers_add (ctx, key)))
        {
          gpg_error_object (result, err, "Error adding signer: %s",
                            gpg_strerror (err));
          goto leave;
        }
      gpgme_key_unref (key);
      key = NULL;
    }

  if ((err = get_string_data (request, result, "data", &input)))
    goto leave;

  /* Create an output data object.  */
  err = gpgme_data_new (&output);
  if (err)
    {
      gpg_error_object (result, err, "Error creating output data object: %s",
                        gpg_strerror (err));
      goto leave;
    }

  /* Sign. */
  err = gpgme_op_sign (ctx, input, output, mode);
  if (err)
    {
      gpg_error_object (result, err, "Signing failed: %s",
                        gpg_strerror (err));
      goto leave;
    }

  gpgme_data_release (input);
  input = NULL;

  /* We need to base64 if armoring has not been requested.  */
  err = make_data_object (result, output,
                          "signature", !gpgme_get_armor (ctx));
  output = NULL;

 leave:
  xfree_array (patterns);
  gpgme_signers_clear (ctx);
  gpgme_key_unref (key);
  release_onetime_context (keylist_ctx);
  release_context (ctx);
  gpgme_data_release (input);
  gpgme_data_release (output);
  return err;
}



static const char hlp_verify[] =
  "op:     \"verify\"\n"
  "data:   The data to verify.\n"
  "\n"
  "Optional parameters:\n"
  "protocol:      Either \"openpgp\" (default) or \"cms\".\n"
  "signature:     A detached signature. If missing opaque is assumed.\n"
  "\n"
  "Optional boolean flags (default is false):\n"
  "base64:        Input data is base64 encoded.\n"
  "\n"
  "Response on success:\n"
  "type:   \"plaintext\"\n"
  "data:   The verified data.  This may be base64 encoded.\n"
  "base64: Boolean indicating whether data is base64 encoded.\n"
  "info:   An object with verification information (gpgme_verify_result_t).\n"
  " is_mime:    Boolean that is true if the messages claims it is MIME.\n"
  "             Note that this flag is not covered by the signature.)\n"
  " signatures: Array of signatures\n"
  "  summary: Object containing summary information.\n"
  "   Boolean values: (Check gpgme_sigsum_t doc for meaning)\n"
  "    valid\n"
  "    green\n"
  "    red\n"
  "    revoked\n"
  "    key-expired\n"
  "    sig-expired\n"
  "    key-missing\n"
  "    crl-missing\n"
  "    crl-too-old\n"
  "    bad-policy\n"
  "    sys-error\n"
  "   sigsum: Array of strings representing the sigsum.\n"
  "  Boolean values:\n"
  "   wrong_key_usage: Key should not have been used for signing.\n"
  "   chain_model:     Validity has been verified using the chain model.\n"
  "   is_de_vs:        signature is in compliance to the de-vs mode.\n"
  "  String values:\n"
  "   status_string:      The status code as localized gpg-error string\n"
  "   fingerprint:        The fingerprint of the signing key.\n"
  "   validity_string:    The validity as string.\n"
  "   pubkey_algo_name:   gpgme_pubkey_algo_name of used algo.\n"
  "   hash_algo_name:     gpgme_hash_algo_name of used hash algo\n"
  "   pka_address:        The mailbox from the PKA information.\n"
  "  Number values:\n"
  "   status_code:     The status as a number. (gpg_error_t)\n"
  "   timestamp:       Signature creation time. (secs since epoch)\n"
  "   exp_timestamp:   Signature expiration or 0. (secs since epoch)\n"
  "   pka_trust: PKA status: 0 = not available, 1 = bad, 2 = okay, 3 = RFU.\n"
  "   validity: validity as number (gpgme_validity_t)\n"
  "   validity_reason: (gpg_error_t)\n"
  "  Array values:\n"
  "   notations: Notation data and policy urls (gpgme_sig_notation_t)\n"
  "    Boolean values:\n"
  "     human_readable\n"
  "     critical\n"
  "    String values:\n"
  "     name\n"
  "     value\n"
  "    Number values:\n"
  "     flags\n";
static gpg_error_t
op_verify (ctrl_t ctrl, cjson_t request, cjson_t result)
{
  gpg_error_t err;
  gpgme_ctx_t ctx = NULL;
  gpgme_protocol_t protocol;
  gpgme_data_t input = NULL;
  gpgme_data_t signature = NULL;
  gpgme_data_t output = NULL;
  gpgme_verify_result_t verify_result;

  (void)ctrl;

  if ((err = get_protocol (request, &protocol)))
    goto leave;
  ctx = get_context (protocol);

  if ((err = get_string_data (request, result, "data", &input)))
    goto leave;

  err = get_string_data (request, result, "signature", &signature);
  /* Signature data is optional otherwise we expect opaque or clearsigned. */
  if (err && err != gpg_error (GPG_ERR_NO_DATA))
    goto leave;

  if (!signature)
    {
      /* Verify opaque or clearsigned we need an output data object.  */
      err = gpgme_data_new (&output);
      if (err)
        {
          gpg_error_object (result, err,
                            "Error creating output data object: %s",
                            gpg_strerror (err));
          goto leave;
        }
      err = gpgme_op_verify (ctx, input, 0, output);
    }
  else
    {
      err = gpgme_op_verify (ctx, signature, input, NULL);
    }

  if (err)
    {
      gpg_error_object (result, err, "Verify failed: %s", gpg_strerror (err));
      goto leave;
    }
  gpgme_data_release (input);
  input = NULL;
  gpgme_data_release (signature);
  signature = NULL;

  verify_result = gpgme_op_verify_result (ctx);
  if (verify_result && verify_result->signatures)
    {
      xjson_AddItemToObject (result, "info",
                             verify_result_to_json (verify_result));
    }

  if (output)
    {
      err = make_data_object (result, output, "plaintext", -1);
      output = NULL;

      if (err)
        {
          gpg_error_object (result, err, "Plaintext output failed: %s",
                            gpg_strerror (err));
          goto leave;
        }
    }

 leave:
  release_context (ctx);
  gpgme_data_release (input);
  gpgme_data_release (output);
  gpgme_data_release (signature);
  return err;
}



static const char hlp_version[] =
  "op:     \"version\"\n"
  "\n"
  "Response on success:\n"
  "gpgme:  The GPGME Version.\n"
  "info:   dump of engine info. containing:\n"
  "        protocol: The protocol.\n"
  "        fname:    The file name.\n"
  "        version:  The version.\n"
  "        req_ver:  The required version.\n"
  "        homedir:  The homedir of the engine or \"default\".\n";
static gpg_error_t
op_version (ctrl_t ctrl, cjson_t request, cjson_t result)
{
  gpg_error_t err = 0;
  gpgme_engine_info_t ei = NULL;
  cjson_t infos = xjson_CreateArray ();

  (void)ctrl;
  (void)request;

  if (!cJSON_AddStringToObject (result, "gpgme", gpgme_check_version (NULL)))
    {
      cJSON_Delete (infos);
      return gpg_error_from_syserror ();
    }

  if ((err = gpgme_get_engine_info (&ei)))
    {
      cJSON_Delete (infos);
      return err;
    }

  for (; ei; ei = ei->next)
    cJSON_AddItemToArray (infos, engine_info_to_json (ei));

  if (!cJSON_AddItemToObject (result, "info", infos))
    {
      err = gpg_error_from_syserror ();
      cJSON_Delete (infos);
      return err;
    }

  return 0;
}



static const char hlp_keylist[] =
  "op:     \"keylist\"\n"
  "\n"
  "Optional parameters:\n"
  "keys:          Array of strings or fingerprints to lookup\n"
  "               For a single key a String may be used instead of an array.\n"
  "               default lists all keys.\n"
  "protocol:      Either \"openpgp\" (default) or \"cms\".\n"
  "\n"
  "Optional boolean flags (default is false):\n"
  "secret:        List only secret keys.\n"
  "with-secret:   Add KEYLIST_MODE_WITH_SECRET.\n"
  "extern:        Add KEYLIST_MODE_EXTERN.\n"
  "local:         Add KEYLIST_MODE_LOCAL. (default mode).\n"
  "sigs:          Add KEYLIST_MODE_SIGS.\n"
  "notations:     Add KEYLIST_MODE_SIG_NOTATIONS.\n"
  "tofu:          Add KEYLIST_MODE_WITH_TOFU.\n"
  "keygrip:       Add KEYLIST_MODE_WITH_KEYGRIP.\n"
  "ephemeral:     Add KEYLIST_MODE_EPHEMERAL.\n"
  "validate:      Add KEYLIST_MODE_VALIDATE.\n"
  "locate:        Add KEYLIST_MODE_LOCATE.\n"
  "\n"
  "Response on success:\n"
  "keys:   Array of keys.\n"
  "  Boolean values:\n"
  "   revoked\n"
  "   expired\n"
  "   disabled\n"
  "   invalid\n"
  "   can_encrypt\n"
  "   can_sign\n"
  "   can_certify\n"
  "   can_authenticate\n"
  "   secret\n"
  "   is_qualified\n"
  "  String values:\n"
  "   protocol\n"
  "   issuer_serial (CMS Only)\n"
  "   issuer_name (CMS Only)\n"
  "   chain_id (CMS Only)\n"
  "   owner_trust (OpenPGP only)\n"
  "   fingerprint\n"
  "  Number values:\n"
  "   last_update\n"
  "   origin\n"
  "  Array values:\n"
  "   subkeys\n"
  "    Boolean values:\n"
  "     revoked\n"
  "     expired\n"
  "     disabled\n"
  "     invalid\n"
  "     can_encrypt\n"
  "     can_sign\n"
  "     can_certify\n"
  "     can_authenticate\n"
  "     secret\n"
  "     is_qualified\n"
  "     is_cardkey\n"
  "     is_de_vs\n"
  "    String values:\n"
  "     pubkey_algo_name\n"
  "     pubkey_algo_string\n"
  "     keyid\n"
  "     card_number\n"
  "     curve\n"
  "     keygrip\n"
  "    Number values:\n"
  "     pubkey_algo\n"
  "     length\n"
  "     timestamp\n"
  "     expires\n"
  "   userids\n"
  "    Boolean values:\n"
  "     revoked\n"
  "     invalid\n"
  "    String values:\n"
  "     validity\n"
  "     uid\n"
  "     name\n"
  "     email\n"
  "     comment\n"
  "     address\n"
  "    Number values:\n"
  "     origin\n"
  "     last_update\n"
  "    Array values:\n"
  "     signatures\n"
  "      Boolean values:\n"
  "       revoked\n"
  "       expired\n"
  "       invalid\n"
  "       exportable\n"
  "      String values:\n"
  "       pubkey_algo_name\n"
  "       keyid\n"
  "       status\n"
  "       uid\n"
  "       name\n"
  "       email\n"
  "       comment\n"
  "      Number values:\n"
  "       pubkey_algo\n"
  "       timestamp\n"
  "       expires\n"
  "       status_code\n"
  "       sig_class\n"
  "      Array values:\n"
  "       notations\n"
  "        Boolean values:\n"
  "         human_readable\n"
  "         critical\n"
  "        String values:\n"
  "         name\n"
  "         value\n"
  "        Number values:\n"
  "         flags\n"
  "     tofu\n"
  "      String values:\n"
  "       description\n"
  "      Number values:\n"
  "       validity\n"
  "       policy\n"
  "       signcount\n"
  "       encrcount\n"
  "       signfirst\n"
  "       signlast\n"
  "       encrfirst\n"
  "       encrlast\n";
static gpg_error_t
op_keylist (ctrl_t ctrl, cjson_t request, cjson_t result)
{
  gpg_error_t err;
  gpgme_ctx_t ctx = NULL;
  gpgme_protocol_t protocol;
  char **patterns = NULL;
  int abool;
  int secret_only = 0;
  gpgme_keylist_mode_t mode = 0;
  gpgme_key_t key = NULL;
  cjson_t keyarray = xjson_CreateArray ();

  (void)ctrl;

  if ((err = get_protocol (request, &protocol)))
    goto leave;
  ctx = get_context (protocol);

  /* Handle the various keylist mode bools. */
  if ((err = get_boolean_flag (request, "secret", 0, &abool)))
    goto leave;
  if (abool)
    {
      mode |= GPGME_KEYLIST_MODE_WITH_SECRET;
      secret_only = 1;
    }
  if ((err = get_boolean_flag (request, "with-secret", 0, &abool)))
    goto leave;
  if (abool)
    mode |= GPGME_KEYLIST_MODE_WITH_SECRET;
  if ((err = get_boolean_flag (request, "extern", 0, &abool)))
    goto leave;
  if (abool)
    mode |= GPGME_KEYLIST_MODE_EXTERN;

  if ((err = get_boolean_flag (request, "local", 0, &abool)))
    goto leave;
  if (abool)
    mode |= GPGME_KEYLIST_MODE_LOCAL;

  if ((err = get_boolean_flag (request, "sigs", 0, &abool)))
    goto leave;
  if (abool)
    mode |= GPGME_KEYLIST_MODE_SIGS;

  if ((err = get_boolean_flag (request, "notations", 0, &abool)))
    goto leave;
  if (abool)
    mode |= GPGME_KEYLIST_MODE_SIG_NOTATIONS;

  if ((err = get_boolean_flag (request, "tofu", 0, &abool)))
    goto leave;
  if (abool)
    mode |= GPGME_KEYLIST_MODE_WITH_TOFU;

  if ((err = get_boolean_flag (request, "keygrip", 0, &abool)))
    goto leave;
  if (abool)
    mode |= GPGME_KEYLIST_MODE_WITH_KEYGRIP;

  if ((err = get_boolean_flag (request, "ephemeral", 0, &abool)))
    goto leave;
  if (abool)
    mode |= GPGME_KEYLIST_MODE_EPHEMERAL;

  if ((err = get_boolean_flag (request, "validate", 0, &abool)))
    goto leave;
  if (abool)
    mode |= GPGME_KEYLIST_MODE_VALIDATE;

  if ((err = get_boolean_flag (request, "locate", 0, &abool)))
    goto leave;
  if (abool)
    mode |= GPGME_KEYLIST_MODE_LOCATE;

  if ((err = get_boolean_flag (request, "force-extern", 0, &abool)))
    goto leave;
  if (abool)
    mode |= GPGME_KEYLIST_MODE_FORCE_EXTERN;

  if (!mode)
    {
      /* default to local */
      mode = GPGME_KEYLIST_MODE_LOCAL;
    }

  /* Get the keys.  */
  patterns = create_keylist_patterns (request, "keys");

  /* Do a keylisting and add the keys */
  gpgme_set_keylist_mode (ctx, mode);

  err = gpgme_op_keylist_ext_start (ctx, (const char **) patterns,
                                    secret_only, 0);
  if (err)
    {
      gpg_error_object (result, err, "Error listing keys: %s",
                        gpg_strerror (err));
      goto leave;
    }

  while (!(err = gpgme_op_keylist_next (ctx, &key)))
    {
      cJSON_AddItemToArray (keyarray, key_to_json (key));
      gpgme_key_unref (key);
    }
  err = 0;

  if (!cJSON_AddItemToObject (result, "keys", keyarray))
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

 leave:
  xfree_array (patterns);
  if (err)
    {
      cJSON_Delete (keyarray);
    }
  return err;
}



static const char hlp_import[] =
  "op:     \"import\"\n"
  "data:   The data to import.\n"
  "\n"
  "Optional parameters:\n"
  "protocol:      Either \"openpgp\" (default) or \"cms\".\n"
  "\n"
  "Optional boolean flags (default is false):\n"
  "base64:        Input data is base64 encoded.\n"
  "\n"
  "Response on success:\n"
  "result: The import result.\n"
  "  Number values:\n"
  "   considered\n"
  "   no_user_id\n"
  "   imported\n"
  "   imported_rsa\n"
  "   unchanged\n"
  "   new_user_ids\n"
  "   new_sub_keys\n"
  "   new_signatures\n"
  "   new_revocations\n"
  "   secret_read\n"
  "   secret_imported\n"
  "   secret_unchanged\n"
  "   skipped_new_keys\n"
  "   not_imported\n"
  "   skipped_v3_keys\n"
  "  Array values:\n"
  "   imports: List of keys for which an import was attempted\n"
  "    String values:\n"
  "     fingerprint\n"
  "     error_string\n"
  "    Number values:\n"
  "     error_code\n"
  "     status\n";
static gpg_error_t
op_import (ctrl_t ctrl, cjson_t request, cjson_t result)
{
  gpg_error_t err;
  gpgme_ctx_t ctx = NULL;
  gpgme_data_t input = NULL;
  gpgme_import_result_t import_result;
  gpgme_protocol_t protocol;

  (void)ctrl;

  if ((err = get_protocol (request, &protocol)))
    goto leave;
  ctx = get_context (protocol);

  if ((err = get_string_data (request, result, "data", &input)))
      goto leave;

  /* Import.  */
  err = gpgme_op_import (ctx, input);
  import_result = gpgme_op_import_result (ctx);
  if (err)
    {
      gpg_error_object (result, err, "Import failed: %s",
                        gpg_strerror (err));
      goto leave;
    }
  gpgme_data_release (input);
  input = NULL;

  xjson_AddItemToObject (result, "result",
                         import_result_to_json (import_result));

 leave:
  release_context (ctx);
  gpgme_data_release (input);
  return err;
}


static const char hlp_export[] =
  "op:     \"export\"\n"
  "\n"
  "Optional parameters:\n"
  "keys:          Array of strings or fingerprints to lookup\n"
  "               For a single key a String may be used instead of an array.\n"
  "               default exports all keys.\n"
  "protocol:      Either \"openpgp\" (default) or \"cms\".\n"
  "\n"
  "Optional boolean flags (default is false):\n"
  "armor:         Request output in armored format.\n"
  "extern:        Add EXPORT_MODE_EXTERN.\n"
  "minimal:       Add EXPORT_MODE_MINIMAL.\n"
  "raw:           Add EXPORT_MODE_RAW.\n"
  "pkcs12:        Add EXPORT_MODE_PKCS12.\n"
  "with-sec-fprs: Add the sec-fprs array to the result.\n"
  "\n"
  "Response on success:\n"
  "type:     \"keys\"\n"
  "data:     Unless armor mode is used a Base64 encoded binary.\n"
  "          In armor mode a string with an armored\n"
  "          OpenPGP or a PEM / PKCS12 key.\n"
  "base64:   Boolean indicating whether data is base64 encoded.\n"
  "sec-fprs: Optional, only if with-secret is set. An array containing\n"
  "          the fingerprints of the keys in the export for which a secret\n"
  "          key is available";
static gpg_error_t
op_export (ctrl_t ctrl, cjson_t request, cjson_t result)
{
  gpg_error_t err;
  gpgme_ctx_t ctx = NULL;
  gpgme_protocol_t protocol;
  char **patterns = NULL;
  int abool;
  int with_secret = 0;
  gpgme_export_mode_t mode = 0;
  gpgme_data_t output = NULL;

  (void)ctrl;

  if ((err = get_protocol (request, &protocol)))
    goto leave;
  ctx = get_context (protocol);

  if ((err = get_boolean_flag (request, "armor", 0, &abool)))
    goto leave;
  gpgme_set_armor (ctx, abool);

  /* Handle the various export mode bools. */
  if ((err = get_boolean_flag (request, "secret", 0, &abool)))
    goto leave;
  if (abool)
    {
      err = gpg_error (GPG_ERR_FORBIDDEN);
      goto leave;
    }

  if ((err = get_boolean_flag (request, "extern", 0, &abool)))
    goto leave;
  if (abool)
    mode |= GPGME_EXPORT_MODE_EXTERN;

  if ((err = get_boolean_flag (request, "minimal", 0, &abool)))
    goto leave;
  if (abool)
    mode |= GPGME_EXPORT_MODE_MINIMAL;

  if ((err = get_boolean_flag (request, "raw", 0, &abool)))
    goto leave;
  if (abool)
    mode |= GPGME_EXPORT_MODE_RAW;

  if ((err = get_boolean_flag (request, "pkcs12", 0, &abool)))
    goto leave;
  if (abool)
    mode |= GPGME_EXPORT_MODE_PKCS12;

  if ((err = get_boolean_flag (request, "with-sec-fprs", 0, &abool)))
    goto leave;
  if (abool)
    with_secret = 1;

  /* Get the export patterns.  */
  patterns = create_keylist_patterns (request, "keys");

  /* Create an output data object.  */
  err = gpgme_data_new (&output);
  if (err)
    {
      gpg_error_object (result, err, "Error creating output data object: %s",
                        gpg_strerror (err));
      goto leave;
    }

  err = gpgme_op_export_ext (ctx, (const char **) patterns,
                             mode, output);
  if (err)
    {
      gpg_error_object (result, err, "Error exporting keys: %s",
                        gpg_strerror (err));
      goto leave;
    }

  /* We need to base64 if armoring has not been requested.  */
  err = make_data_object (result, output,
                          "keys", !gpgme_get_armor (ctx));
  output = NULL;

  if (!err && with_secret)
    {
      err = add_secret_fprs ((const char **) patterns, protocol, result);
    }

leave:
  xfree_array (patterns);
  release_context (ctx);
  gpgme_data_release (output);

  return err;
}


static const char hlp_delete[] =
  "op:     \"delete\"\n"
  "key:    Fingerprint of the key to delete.\n"
  "\n"
  "Optional parameters:\n"
  "protocol:      Either \"openpgp\" (default) or \"cms\".\n"
  "\n"
  "Response on success:\n"
  "success:   Boolean true.\n";
static gpg_error_t
op_delete (ctrl_t ctrl, cjson_t request, cjson_t result)
{
  gpg_error_t err;
  gpgme_ctx_t ctx = NULL;
  gpgme_ctx_t keylist_ctx = NULL;
  gpgme_protocol_t protocol;
  gpgme_key_t key = NULL;
  int secret = 0;
  cjson_t j_key = NULL;

  (void)ctrl;

  if ((err = get_protocol (request, &protocol)))
    goto leave;
  ctx = get_context (protocol);
  keylist_ctx = get_context (protocol);

  if ((err = get_boolean_flag (request, "secret", 0, &secret)))
    goto leave;
  if (secret)
    {
      err = gpg_error (GPG_ERR_FORBIDDEN);
      goto leave;
    }

  j_key = cJSON_GetObjectItem (request, "key");
  if (!j_key)
    {
      err = gpg_error (GPG_ERR_NO_KEY);
      goto leave;
    }
  if (!cjson_is_string (j_key))
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      goto leave;
    }

  /* Get the key */
  if ((err = gpgme_get_key (keylist_ctx, j_key->valuestring, &key, 0)))
    {
      gpg_error_object (result, err, "Error fetching key for delete: %s",
                        gpg_strerror (err));
      goto leave;
    }

  err = gpgme_op_delete (ctx, key, 0);
  if (err)
    {
      gpg_error_object (result, err, "Error deleting key: %s",
                        gpg_strerror (err));
      goto leave;
    }

  xjson_AddBoolToObject (result, "success", 1);

leave:
  gpgme_key_unref (key);
  release_context (ctx);
  release_context (keylist_ctx);

  return err;
}


static const char hlp_config_opt[] =
  "op:       \"config_opt\"\n"
  "component: The component of the option.\n"
  "option:    The name of the option.\n"
  "\n"
  "Response on success:\n"
  "\n"
  "option: Information about the option.\n"
  " String values:\n"
  "  name: The name of the option\n"
  "  description: Localized description of the opt.\n"
  "  argname: Thhe argument name e.g. --verbose\n"
  "  default_description\n"
  "  no_arg_description\n"
  " Number values:\n"
  "  flags: Flags for this option.\n"
  "  level: the level of the description. See gpgme_conf_level_t.\n"
  "  type: The type of the option. See gpgme_conf_type_t.\n"
  "  alt_type: Alternate type of the option. See gpgme_conf_type_t\n"
  " Arg type values: (see desc. below)\n"
  "  default_value: Array of the default value.\n"
  "  no_arg_value: Array of the value if it is not set.\n"
  "  value: Array for the current value if the option is set.\n"
  "\n"
  "If the response is empty the option was not found\n"
  "";
static gpg_error_t
op_config_opt (ctrl_t ctrl, cjson_t request, cjson_t result)
{
  gpg_error_t err;
  gpgme_ctx_t ctx = NULL;
  gpgme_conf_comp_t conf = NULL;
  gpgme_conf_comp_t comp = NULL;
  cjson_t j_tmp;
  char *comp_name = NULL;
  char *opt_name = NULL;

  (void)ctrl;

  ctx = get_context (GPGME_PROTOCOL_GPGCONF);

  j_tmp = cJSON_GetObjectItem (request, "component");
  if (!j_tmp || !cjson_is_string (j_tmp))
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      goto leave;
    }
  comp_name = j_tmp->valuestring;


  j_tmp = cJSON_GetObjectItem (request, "option");
  if (!j_tmp || !cjson_is_string (j_tmp))
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      goto leave;
    }
  opt_name = j_tmp->valuestring;

  /* Load the config */
  err = gpgme_op_conf_load (ctx, &conf);
  if (err)
    {
      goto leave;
    }

  comp = conf;
  for (comp = conf; comp; comp = comp->next)
    {
      gpgme_conf_opt_t opt = NULL;
      int found = 0;
      if (!comp->name || strcmp (comp->name, comp_name))
        {
          /* Skip components if a single one is specified */
          continue;
        }
      for (opt = comp->options; opt; opt = opt->next)
        {
          if (!opt->name || strcmp (opt->name, opt_name))
            {
              /* Skip components if a single one is specified */
              continue;
            }
          xjson_AddItemToObject (result, "option", conf_opt_to_json (opt));
          found = 1;
          break;
        }
      if (found)
        break;
    }

leave:
  gpgme_conf_release (conf);
  release_context (ctx);

  return err;
}


static const char hlp_config[] =
  "op:     \"config\"\n"
  "\n"
  "Optional parameters:\n"
  "component:    Component of entries to list.\n"
  "              Default: all\n"
  "\n"
  "Response on success:\n"
  "   components: Array of the component program configs.\n"
  "     name:         The component name.\n"
  "     description:  Description of the component.\n"
  "     program_name: The absolute path to the program.\n"
  "     options: Array of config options\n"
  "      String values:\n"
  "       name: The name of the option\n"
  "       description: Localized description of the opt.\n"
  "       argname: Thhe argument name e.g. --verbose\n"
  "       default_description\n"
  "       no_arg_description\n"
  "      Number values:\n"
  "       flags: Flags for this option.\n"
  "       level: the level of the description. See gpgme_conf_level_t.\n"
  "       type: The type of the option. See gpgme_conf_type_t.\n"
  "       alt_type: Alternate type of the option. See gpgme_conf_type_t\n"
  "      Arg type values: (see desc. below)\n"
  "       default_value: Array of the default value.\n"
  "       no_arg_value: Array of the value if it is not set.\n"
  "       value: Array for the current value if the option is set.\n"
  "\n"
  "Conf type values are an array of values that are either\n"
  "of type number named \"number\" or of type string,\n"
  "named \"string\".\n"
  "If the type is none the bool value is_none is true.\n"
  "";
static gpg_error_t
op_config (ctrl_t ctrl, cjson_t request, cjson_t result)
{
  gpg_error_t err;
  gpgme_ctx_t ctx = NULL;
  gpgme_conf_comp_t conf = NULL;
  gpgme_conf_comp_t comp = NULL;
  cjson_t j_tmp;
  char *comp_name = NULL;
  cjson_t j_comps;

  (void)ctrl;

  ctx = get_context (GPGME_PROTOCOL_GPGCONF);

  j_tmp = cJSON_GetObjectItem (request, "component");
  if (j_tmp && cjson_is_string (j_tmp))
    {
      comp_name = j_tmp->valuestring;
    }
  else if (j_tmp && !cjson_is_string (j_tmp))
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      goto leave;
    }

  /* Load the config */
  err = gpgme_op_conf_load (ctx, &conf);
  if (err)
    {
      goto leave;
    }

  j_comps = xjson_CreateArray ();
  comp = conf;
  for (comp = conf; comp; comp = comp->next)
    {
      if (comp_name && comp->name && strcmp (comp->name, comp_name))
        {
          /* Skip components if a single one is specified */
          continue;
        }
      cJSON_AddItemToArray (j_comps, conf_comp_to_json (comp));
    }
  xjson_AddItemToObject (result, "components", j_comps);

 leave:
  gpgme_conf_release (conf);
  release_context (ctx);

  return err;
}



static const char hlp_createkey[] =
  "op:      \"createkey\"\n"
  "userid:  The user id. E.g. \"Foo Bar <foo@bar.baz>\"\n"
  "\n"
  "Optional parameters:\n"
  "algo:        Algo of the key as string.  See doc for gpg --quick-gen-key.\n"
  "             Supported values are \"default\" and \"future-default\".\n"
  "expires:     Seconds from now to expiry as Number.  0 means no expiry.\n"
  "             The default is to use a standard expiration interval.\n"
  "\n"
  "Response on success:\n"
  "fingerprint:   The fingerprint of the created key.\n"
  "\n"
  "Note: This interface does not allow key generation if the userid\n"
  "of the new key already exists in the keyring.\n";
static gpg_error_t
op_createkey (ctrl_t ctrl, cjson_t request, cjson_t result)
{
  gpg_error_t err;
  gpgme_ctx_t ctx = NULL;
  unsigned int flags = GPGME_CREATE_FORCE; /* Always force as the GUI should
                                              handle checks, if required. */
  unsigned long expires = 0;
  cjson_t j_tmp;
  const char *algo = "default";
  const char *userid;
  gpgme_genkey_result_t res;

  (void)ctrl;

#ifdef GPG_AGENT_ALLOWS_KEYGEN_THROUGH_BROWSER
  /* GnuPG forbids keygen through the browser socket so for
     this we create an unrestricted context.
     See GnuPG-Bug-Id: T4010 for more info */
  ctx = get_context (GPGME_PROTOCOL_OpenPGP);
#else
    err = gpgme_new (&ctx);
  if (err)
    log_fatal ("error creating GPGME context: %s\n", gpg_strerror (err));
  gpgme_set_protocol (ctx, GPGME_PROTOCOL_OpenPGP);
#endif

  j_tmp = cJSON_GetObjectItem (request, "algo");
  if (j_tmp && cjson_is_string (j_tmp))
    {
      algo = j_tmp->valuestring;
    }

  j_tmp = cJSON_GetObjectItem (request, "userid");
  if (!j_tmp || !cjson_is_string (j_tmp))
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      goto leave;
    }

  userid = j_tmp->valuestring;

  j_tmp = cJSON_GetObjectItem (request, "expires");
  if (j_tmp)
    {
      if (!cjson_is_number (j_tmp))
        {
          err = gpg_error (GPG_ERR_INV_VALUE);
          goto leave;
        }
      expires = j_tmp->valueint;

      if (!expires)
        flags |= GPGME_CREATE_NOEXPIRE;
    }


  if ((err = gpgme_op_createkey (ctx, userid, algo, 0, expires, NULL, flags)))
    goto leave;

  res = gpgme_op_genkey_result (ctx);
  if (!res)
    {
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }

  xjson_AddStringToObject0 (result, "fingerprint", res->fpr);

leave:
#ifdef GPG_AGENT_ALLOWS_KEYGEN_THROUGH_BROWSER
  release_context (ctx);
#else
  gpgme_release (ctx);
#endif

  return err;
}


static const char hlp_identify[] =
  "op:     \"identify\"\n"
  "data:   The data to identify.\n"
  "\n"
  "Optional boolean flags (default is false):\n"
  "base64: Input data is base64 encoded.\n"
  "\n"
  "Response:\n"
  "result: A string describing the object.\n";
static gpg_error_t
op_identify (ctrl_t ctrl, cjson_t request, cjson_t result)
{
  gpg_error_t err;
  gpgme_data_t input = NULL;
  gpgme_data_type_t dt;

  (void)ctrl;

  if ((err = get_string_data (request, result, "data", &input)))
    goto leave;

  dt = gpgme_data_identify (input, 0);
  xjson_AddStringToObject (result, "result", data_type_to_string (dt));

 leave:
  gpgme_data_release (input);
  return err;
}



static const char hlp_getmore[] =
  "op:     \"getmore\"\n"
  "\n"
  "Response on success:\n"
  "response:       base64 encoded json response.\n"
  "more:           Another getmore is required.\n"
  "base64:         boolean if the response is base64 encoded.\n";
static gpg_error_t
op_getmore (ctrl_t ctrl, cjson_t request, cjson_t result)
{
  gpg_error_t err;
  int c;
  size_t n;
  size_t chunksize;

  if ((err = get_chunksize (request, &chunksize)))
    goto leave;

  /* For the meta data we need 41 bytes:
     {"more":true,"base64":true,"response":""} */
  chunksize -= 41;

  /* Adjust the chunksize for the base64 conversion.  */
  chunksize = (chunksize / 4) * 3;

  /* Do we have anything pending?  */
  if (!ctrl->pending_data.buffer)
    {
      err = gpg_error (GPG_ERR_NO_DATA);
      gpg_error_object (result, err, "Operation not possible: %s",
                        gpg_strerror (err));
      goto leave;
    }

  /* We currently always use base64 encoding for simplicity. */
  xjson_AddBoolToObject (result, "base64", 1);

  if (ctrl->pending_data.written >= ctrl->pending_data.length)
    {
      /* EOF reached.  This should not happen but we return an empty
       * string once in case of client errors.  */
      gpgme_free (ctrl->pending_data.buffer);
      ctrl->pending_data.buffer = NULL;
      xjson_AddBoolToObject (result, "more", 0);
      err = cjson_AddStringToObject (result, "response", "");
    }
  else
    {
      n = ctrl->pending_data.length - ctrl->pending_data.written;
      if (n > chunksize)
        {
          n = chunksize;
          xjson_AddBoolToObject (result, "more", 1);
        }
      else
        xjson_AddBoolToObject (result, "more", 0);

      c = ctrl->pending_data.buffer[ctrl->pending_data.written + n];
      ctrl->pending_data.buffer[ctrl->pending_data.written + n] = 0;
      err = add_base64_to_object (result, "response",
                                  (ctrl->pending_data.buffer
                                   + ctrl->pending_data.written), n);
      ctrl->pending_data.buffer[ctrl->pending_data.written + n] = c;
      if (!err)
        {
          ctrl->pending_data.written += n;
          if (ctrl->pending_data.written >= ctrl->pending_data.length)
            {
              xfree (ctrl->pending_data.buffer);
              ctrl->pending_data.buffer = NULL;
            }
        }
    }

 leave:
  return err;
}



static const char hlp_help[] =
  "The tool expects a JSON object with the request and responds with\n"
  "another JSON object.  Even on error a JSON object is returned.  The\n"
  "property \"op\" is mandatory and its string value selects the\n"
  "operation; if the property \"help\" with the value \"true\" exists, the\n"
  "operation is not performned but a string with the documentation\n"
  "returned.  To list all operations it is allowed to leave out \"op\" in\n"
  "help mode.  Supported values for \"op\" are:\n\n"
  "  config      Read configuration values.\n"
  "  config_opt  Read a single configuration value.\n"
  "  decrypt     Decrypt data.\n"
  "  delete      Delete a key.\n"
  "  encrypt     Encrypt data.\n"
  "  export      Export keys.\n"
  "  createkey   Generate a keypair (OpenPGP only).\n"
  "  import      Import data.\n"
  "  keylist     List keys.\n"
  "  sign        Sign data.\n"
  "  verify      Verify data.\n"
  "  identify    Identify the type of the data\n"
  "  version     Get engine information.\n"
  "  getmore     Retrieve remaining data if chunksize was used.\n"
  "  help        Help overview.\n"
  "\n"
  "If the data needs to be transferred in smaller chunks the\n"
  "property \"chunksize\" with an integer value can be added.\n"
  "When \"chunksize\" is set the response (including json) will\n"
  "not be larger then \"chunksize\" but might be smaller.\n"
  "The chunked result will be transferred in base64 encoded chunks\n"
  "using the \"getmore\" operation. See help getmore for more info.";
static gpg_error_t
op_help (ctrl_t ctrl, cjson_t request, cjson_t result)
{
  cjson_t j_tmp;
  char *buffer = NULL;
  const char *msg;

  j_tmp = cJSON_GetObjectItem (request, "interactive_help");
  if (ctrl->interactive && j_tmp && cjson_is_string (j_tmp))
    msg = buffer = xstrconcat (hlp_help, "\n", j_tmp->valuestring, NULL);
  else
    msg = hlp_help;

  xjson_AddStringToObject (result, "type", "help");
  xjson_AddStringToObject (result, "msg", msg);

  xfree (buffer);
  return 0;
}



/*
 * Dispatcher
 */

/* Process a request and return the response.  The response is a newly
 * allocated string or NULL in case of an error.  */
char *
json_core_process_request (ctrl_t ctrl, const char *request)
{
  static struct {
    const char *op;
    gpg_error_t (*handler)(ctrl_t ctrl, cjson_t request, cjson_t result);
    const char * const helpstr;
  } optbl[] = {
    { "config",     op_config,     hlp_config },
    { "config_opt", op_config_opt, hlp_config_opt },
    { "encrypt",    op_encrypt,    hlp_encrypt },
    { "export",     op_export,     hlp_export },
    { "decrypt",    op_decrypt,    hlp_decrypt },
    { "delete",     op_delete,     hlp_delete },
    { "createkey",  op_createkey,  hlp_createkey },
    { "keylist",    op_keylist,    hlp_keylist },
    { "import",     op_import,     hlp_import },
    { "identify",   op_identify,   hlp_identify },
    { "sign",       op_sign,       hlp_sign },
    { "verify",     op_verify,     hlp_verify },
    { "version",    op_version,    hlp_version },
    { "getmore",    op_getmore,    hlp_getmore },
    { "help",       op_help,       hlp_help },
    { NULL }
  };
  size_t erroff;
  cjson_t json;
  cjson_t j_tmp, j_op;
  cjson_t response;
  int helpmode;
  int is_getmore = 0;
  const char *op;
  char *res = NULL;
  int idx;

  response = xjson_CreateObject ();

  json = cJSON_Parse (request, &erroff);
  if (!json)
    {
      log_string (GPGRT_LOGLVL_INFO, request);
      log_info ("invalid JSON object at offset %zu\n", erroff);
      error_object (response, "invalid JSON object at offset %zu\n", erroff);
      goto leave;
    }

  j_tmp = cJSON_GetObjectItem (json, "help");
  helpmode = (j_tmp && cjson_is_true (j_tmp));

  j_op = cJSON_GetObjectItem (json, "op");
  if (!j_op || !cjson_is_string (j_op))
    {
      if (!helpmode)
        {
          error_object (response, "Property \"op\" missing");
          goto leave;
        }
      op = "help";  /* Help summary.  */
    }
  else
    op = j_op->valuestring;

  for (idx=0; optbl[idx].op; idx++)
    if (!strcmp (op, optbl[idx].op))
      break;
  if (optbl[idx].op)
    {
      if (helpmode && strcmp (op, "help"))
        {
          xjson_AddStringToObject (response, "type", "help");
          xjson_AddStringToObject (response, "op", op);
          xjson_AddStringToObject (response, "msg", optbl[idx].helpstr);
        }
      else
        {
          gpg_error_t err;
          is_getmore = optbl[idx].handler == op_getmore;
          /* If this is not the "getmore" command and we have any
           * pending data release that data.  */
          if (ctrl->pending_data.buffer && optbl[idx].handler != op_getmore)
            {
              gpgme_free (ctrl->pending_data.buffer);
              ctrl->pending_data.buffer = NULL;
            }

          err = optbl[idx].handler (ctrl, json, response);
          if (err)
            {
              if (!(j_tmp = cJSON_GetObjectItem (response, "type"))
                  || !cjson_is_string (j_tmp)
                  || strcmp (j_tmp->valuestring, "error"))
                {
                  /* No error type response - provide a generic one.  */
                  gpg_error_object (response, err, "Operation failed: %s",
                                    gpg_strerror (err));
                }

              xjson_AddStringToObject (response, "op", op);
            }
        }
    }
  else  /* Operation not supported.  */
    {
      error_object (response, "Unknown operation '%s'", op);
      xjson_AddStringToObject (response, "op", op);
    }

 leave:
  if (is_getmore)
    {
      /* For getmore we bypass the encode_and_chunk. */
      if (ctrl->interactive)
        res = cJSON_Print (response);
      else
        res = cJSON_PrintUnformatted (response);
    }
  else
    res = encode_and_chunk (ctrl, json, response);
  if (!res)
    {
      cjson_t err_obj;

      log_error ("printing JSON data failed\n");

      err_obj = error_object (NULL, "Printing JSON data failed");
      if (ctrl->interactive)
        res = cJSON_Print (err_obj);
      else
        res = cJSON_PrintUnformatted (err_obj);
      cJSON_Delete (err_obj);
    }

  cJSON_Delete (json);
  cJSON_Delete (response);

  if (!res)
    {
      /* Can't happen unless we created a broken error_object above */
      return xtrystrdup ("Bug: Fatal error in process request\n");
    }
  return res;
}
