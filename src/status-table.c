/* gpgme.c - GnuPG Made Easy.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003, 2004, 2005, 2007, 2012 g10 Code GmbH

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
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include "util.h"

struct status_table_s {
    const char *name;
    gpgme_status_code_t code;
};


/* Lexicographically sorted ('_' comes after any letter).  You can use
   the Emacs command M-x sort-lines.  But don't sweat it, the table is
   sorted at start up, too.  */
static struct status_table_s status_table[] =
{
  { "ABORT", GPGME_STATUS_ABORT },
  { "ALREADY_SIGNED", GPGME_STATUS_ALREADY_SIGNED },
  { "ATTRIBUTE",         GPGME_STATUS_ATTRIBUTE        },
  { "BACKUP_KEY_CREATED", GPGME_STATUS_BACKUP_KEY_CREATED },
  { "BAD_PASSPHRASE", GPGME_STATUS_BAD_PASSPHRASE },
  { "BADARMOR", GPGME_STATUS_BADARMOR },
  { "BADMDC", GPGME_STATUS_BADMDC },
  { "BADSIG", GPGME_STATUS_BADSIG },
  { "BEGIN_DECRYPTION", GPGME_STATUS_BEGIN_DECRYPTION },
  { "BEGIN_ENCRYPTION", GPGME_STATUS_BEGIN_ENCRYPTION },
  { "BEGIN_SIGNING",     GPGME_STATUS_BEGIN_SIGNING    },
  { "BEGIN_STREAM", GPGME_STATUS_BEGIN_STREAM },
  { "CARDCTRL", GPGME_STATUS_CARDCTRL },
  { "DECRYPTION_FAILED", GPGME_STATUS_DECRYPTION_FAILED },
  { "DECRYPTION_INFO",   GPGME_STATUS_DECRYPTION_INFO  },
  { "DECRYPTION_OKAY", GPGME_STATUS_DECRYPTION_OKAY },
  { "DELETE_PROBLEM", GPGME_STATUS_DELETE_PROBLEM },
  { "ENC_TO", GPGME_STATUS_ENC_TO },
  { "END_DECRYPTION", GPGME_STATUS_END_DECRYPTION },
  { "END_ENCRYPTION", GPGME_STATUS_END_ENCRYPTION },
  { "END_STREAM", GPGME_STATUS_END_STREAM },
  { "ENTER", GPGME_STATUS_ENTER },
  { "ERRMDC", GPGME_STATUS_ERRMDC },
  { "ERROR", GPGME_STATUS_ERROR },
  { "ERRSIG", GPGME_STATUS_ERRSIG },
  { "EXPKEYSIG", GPGME_STATUS_EXPKEYSIG },
  { "EXPSIG", GPGME_STATUS_EXPSIG },
  { "FAILURE", GPGME_STATUS_FAILURE },
  { "FILE_DONE", GPGME_STATUS_FILE_DONE },
  { "FILE_ERROR", GPGME_STATUS_FILE_ERROR },
  { "FILE_START", GPGME_STATUS_FILE_START },
  { "GET_BOOL", GPGME_STATUS_GET_BOOL },
  { "GET_HIDDEN", GPGME_STATUS_GET_HIDDEN },
  { "GET_LINE", GPGME_STATUS_GET_LINE },
  { "GOOD_PASSPHRASE", GPGME_STATUS_GOOD_PASSPHRASE },
  { "GOODMDC", GPGME_STATUS_GOODMDC },
  { "GOODSIG", GPGME_STATUS_GOODSIG },
  { "GOT_IT", GPGME_STATUS_GOT_IT },
  { "IMPORT_OK", GPGME_STATUS_IMPORT_OK },
  { "IMPORT_PROBLEM", GPGME_STATUS_IMPORT_PROBLEM },
  { "IMPORT_RES", GPGME_STATUS_IMPORT_RES },
  { "IMPORTED", GPGME_STATUS_IMPORTED },
  { "INQUIRE_MAXLEN", GPGME_STATUS_INQUIRE_MAXLEN },
  { "INV_RECP", GPGME_STATUS_INV_RECP },
  { "INV_SGNR", GPGME_STATUS_INV_SGNR },
  { "KEY_CONSIDERED", GPGME_STATUS_KEY_CONSIDERED },
  { "KEY_CREATED", GPGME_STATUS_KEY_CREATED },
  { "KEY_NOT_CREATED",   GPGME_STATUS_KEY_NOT_CREATED  },
  { "KEYEXPIRED", GPGME_STATUS_KEYEXPIRED },
  { "KEYREVOKED", GPGME_STATUS_KEYREVOKED },
  { "LEAVE", GPGME_STATUS_LEAVE },
  { "MISSING_PASSPHRASE", GPGME_STATUS_MISSING_PASSPHRASE },
  { "MOUNTPOINT",        GPGME_STATUS_MOUNTPOINT       },
  { "NEED_PASSPHRASE", GPGME_STATUS_NEED_PASSPHRASE },
  { "NEED_PASSPHRASE_PIN", GPGME_STATUS_NEED_PASSPHRASE_PIN },
  { "NEED_PASSPHRASE_SYM", GPGME_STATUS_NEED_PASSPHRASE_SYM },
  { "NEWSIG", GPGME_STATUS_NEWSIG },
  { "NO_PUBKEY", GPGME_STATUS_NO_PUBKEY },
  { "NO_RECP", GPGME_STATUS_NO_RECP },
  { "NO_SECKEY", GPGME_STATUS_NO_SECKEY },
  { "NO_SGNR", GPGME_STATUS_NO_SGNR },
  { "NODATA", GPGME_STATUS_NODATA },
  { "NOTATION_DATA", GPGME_STATUS_NOTATION_DATA },
  { "NOTATION_FLAGS", GPGME_STATUS_NOTATION_FLAGS },
  { "NOTATION_NAME", GPGME_STATUS_NOTATION_NAME },
  { "PINENTRY_LAUNCHED", GPGME_STATUS_PINENTRY_LAUNCHED},
  { "PKA_TRUST_BAD", GPGME_STATUS_PKA_TRUST_BAD },
  { "PKA_TRUST_GOOD", GPGME_STATUS_PKA_TRUST_GOOD },
  { "PLAINTEXT", GPGME_STATUS_PLAINTEXT },
  { "PLAINTEXT_LENGTH",  GPGME_STATUS_PLAINTEXT_LENGTH },
  { "POLICY_URL", GPGME_STATUS_POLICY_URL },
  { "PROGRESS", GPGME_STATUS_PROGRESS },
  { "REVKEYSIG", GPGME_STATUS_REVKEYSIG },
  { "RSA_OR_IDEA", GPGME_STATUS_RSA_OR_IDEA },
  { "SC_OP_FAILURE", GPGME_STATUS_SC_OP_FAILURE },
  { "SC_OP_SUCCESS", GPGME_STATUS_SC_OP_SUCCESS },
  { "SESSION_KEY", GPGME_STATUS_SESSION_KEY },
  { "SHM_GET", GPGME_STATUS_SHM_GET },
  { "SHM_GET_BOOL", GPGME_STATUS_SHM_GET_BOOL },
  { "SHM_GET_HIDDEN", GPGME_STATUS_SHM_GET_HIDDEN },
  { "SHM_INFO", GPGME_STATUS_SHM_INFO },
  { "SIG_CREATED", GPGME_STATUS_SIG_CREATED },
  { "SIG_ID", GPGME_STATUS_SIG_ID },
  { "SIG_SUBPACKET", GPGME_STATUS_SIG_SUBPACKET },
  { "SIGEXPIRED", GPGME_STATUS_SIGEXPIRED },
  { "SUCCESS", GPGME_STATUS_SUCCESS },
  { "TOFU_STATS", GPGME_STATUS_TOFU_STATS },
  { "TOFU_STATS_LONG", GPGME_STATUS_TOFU_STATS_LONG },
  { "TOFU_USER", GPGME_STATUS_TOFU_USER },
  { "TRUNCATED", GPGME_STATUS_TRUNCATED },
  { "TRUST_FULLY", GPGME_STATUS_TRUST_FULLY },
  { "TRUST_MARGINAL", GPGME_STATUS_TRUST_MARGINAL },
  { "TRUST_NEVER", GPGME_STATUS_TRUST_NEVER },
  { "TRUST_ULTIMATE", GPGME_STATUS_TRUST_ULTIMATE },
  { "TRUST_UNDEFINED", GPGME_STATUS_TRUST_UNDEFINED },
  { "UNEXPECTED", GPGME_STATUS_UNEXPECTED },
  { "USERID_HINT", GPGME_STATUS_USERID_HINT },
  { "VALIDSIG", GPGME_STATUS_VALIDSIG },
  {NULL, 0}
};


static int
status_cmp (const void *ap, const void *bp)
{
  const struct status_table_s *a = ap;
  const struct status_table_s *b = bp;

  return strcmp (a->name, b->name);
}


void
_gpgme_status_init (void)
{
  qsort (status_table,
	 DIM(status_table) - 1, sizeof (status_table[0]),
	 status_cmp);
}


gpgme_status_code_t
_gpgme_parse_status (const char *name)
{
  struct status_table_s t, *r;
  t.name = name;
  r = bsearch (&t, status_table, DIM(status_table) - 1,
	       sizeof t, status_cmp);
  return r ? r->code : -1;
}


const char *
_gpgme_status_to_string (gpgme_status_code_t code)
{
  int i;

  for (i=0; i < DIM(status_table); i++)
    if (status_table[i].code == code)
      return status_table[i].name? status_table[i].name : "";
  return "status_code_lost";
}
