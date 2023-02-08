/* t-keylist-secret-sig.c - Regression test.
 * Copyright (C) 2000 Werner Koch (dd9jn)
 * Copyright (C) 2001, 2003, 2004 g10 Code GmbH
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

/* We need to include config.h so that we know whether we are building
   with large file system (LFS) support. */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <gpgme.h>

#include "t-support.h"


struct
{
  const char *fpr;
  const char *sec_keyid;
  struct
  {
    const char *name;
    const char *comment;
    const char *email;
    struct
    {
      gpgme_pubkey_algo_t algo;
      const char *keyid;
      const char *name;
      const char *comment;
      const char *email;
      unsigned int sig_class;
      int exportable;
    } sig;
  } uid[3];
}
keys[] =
  {
    { "A0FF4590BB6122EDEF6E3C542D727CC768697734", "6AE6D7EE46A871F8",
      { { "Alfa Test", "demo key", "alfa@example.net",
          { GPGME_PK_DSA, "2D727CC768697734",
	    "Alfa Test", "demo key", "alfa@example.net", 19, 1 } },
	{ "Alpha Test", "demo key", "alpha@example.net",
          { GPGME_PK_DSA, "2D727CC768697734",
	    "Alfa Test", "demo key", "alfa@example.net", 19, 1 } },
	{ "Alice", "demo key", NULL,
          { GPGME_PK_DSA, "2D727CC768697734",
	    "Alfa Test", "demo key", "alfa@example.net", 19, 1 } } } },
    { NULL }
  };


int
main (void)
{
  gpgme_error_t err;
  gpgme_ctx_t ctx;
  gpgme_key_t key;
  gpgme_keylist_result_t result;
  int mode;
  int i = 0;

  init_gpgme (GPGME_PROTOCOL_OpenPGP);

  err = gpgme_new (&ctx);
  fail_if_err (err);

  mode  = gpgme_get_keylist_mode (ctx);
  mode |= GPGME_KEYLIST_MODE_SIGS;
  err = gpgme_set_keylist_mode (ctx, mode);
  fail_if_err (err);

  err = gpgme_op_keylist_start (ctx, "Alpha", 1);
  fail_if_err (err);

  while (!(err = gpgme_op_keylist_next (ctx, &key)))
    {
      if (!keys[i].fpr)
	{
	  fprintf (stderr, "More keys returned than expected\n");
	  exit (1);
	}

      /* Global key flags.  */
      if (key->revoked)
	{
	  fprintf (stderr, "Key unexpectedly revoked\n");
	  exit (1);
	}
      if (key->expired)
	{
	  fprintf (stderr, "Key unexpectedly expired\n");
	  exit (1);
	}
      if (key->disabled)
	{
	  fprintf (stderr, "Key unexpectedly disabled\n");
	  exit (1);
	}
      if (key->invalid)
	{
	  fprintf (stderr, "Key unexpectedly invalid\n");
	  exit (1);
	}
      if (!key->can_encrypt)
	{
	  fprintf (stderr, "Key unexpectedly unusable for encryption\n");
	  exit (1);
	}
      if (!key->can_sign)
	{
	  fprintf (stderr, "Key unexpectedly unusable for signing\n");
	  exit (1);
	}
      if (!key->can_certify)
	{
	  fprintf (stderr, "Key unexpectedly unusable for certifications\n");
	  exit (1);
	}
      if (!key->secret)
	{
	  fprintf (stderr, "Key unexpectedly not secret\n");
	  exit (1);
	}
      if (key->protocol != GPGME_PROTOCOL_OpenPGP)
	{
	  fprintf (stderr, "Key has unexpected protocol: %s\n",
		   gpgme_get_protocol_name (key->protocol));
	  exit (1);
	}
      if (key->issuer_serial)
	{
	  fprintf (stderr, "Key unexpectedly carries issuer serial: %s\n",
		   key->issuer_serial);
	  exit (1);
	}
      if (key->issuer_name)
	{
	  fprintf (stderr, "Key unexpectedly carries issuer name: %s\n",
		   key->issuer_name);
	  exit (1);
	}
      if (key->chain_id)
	{
	  fprintf (stderr, "Key unexpectedly carries chain ID: %s\n",
		   key->chain_id);
	  exit (1);
	}
      if (key->owner_trust != GPGME_VALIDITY_ULTIMATE)
	{
	  fprintf (stderr, "Key has unexpected owner trust: %i\n",
		   key->owner_trust);
	  exit (1);
	}
      if (!key->subkeys || !key->subkeys->next || key->subkeys->next->next)
	{
	  fprintf (stderr, "Key has unexpected number of subkeys\n");
	  exit (1);
	}

      /* Primary key.  */
      if (key->subkeys->revoked)
	{
	  fprintf (stderr, "Primary key unexpectedly revoked\n");
	  exit (1);
	}
      if (key->subkeys->expired)
	{
	  fprintf (stderr, "Primary key unexpectedly expired\n");
	  exit (1);
	}
      if (key->subkeys->disabled)
	{
	  fprintf (stderr, "Primary key unexpectedly disabled\n");
	  exit (1);
	}
      if (key->subkeys->invalid)
	{
	  fprintf (stderr, "Primary key unexpectedly invalid\n");
	  exit (1);
	}
      if (key->subkeys->can_encrypt)
	{
	  fprintf (stderr, "Primary key unexpectedly usable for encryption\n");
	  exit (1);
	}
      if (!key->subkeys->can_sign)
	{
	  fprintf (stderr, "Primary key unexpectedly unusable for signing\n");
	  exit (1);
	}
      if (!key->subkeys->can_certify)
	{
	  fprintf (stderr, "Primary key unexpectedly unusable for certifications\n");
	  exit (1);
	}
      if (!key->subkeys->secret)
	{
	  fprintf (stderr, "Primary key unexpectedly not secret\n");
	  exit (1);
	}
      if (key->subkeys->pubkey_algo != GPGME_PK_DSA)
	{
	  fprintf (stderr, "Primary key has unexpected public key algo: %s\n",
		   gpgme_pubkey_algo_name (key->subkeys->pubkey_algo));
	  exit (1);
	}
      if (key->subkeys->length != 1024)
	{
	  fprintf (stderr, "Primary key has unexpected length: %i\n",
		   key->subkeys->length);
	  exit (1);
	}
      if (strcmp (key->subkeys->keyid, &keys[i].fpr[40 - 16]))
	{
	  fprintf (stderr, "Primary key has unexpected key ID: %s\n",
		   key->subkeys->keyid);
	  exit (1);
	}
      if (strcmp (key->subkeys->fpr, keys[i].fpr))
	{
	  fprintf (stderr, "Primary key has unexpected fingerprint: %s\n",
		   key->subkeys->fpr);
	  exit (1);
	}
      if (key->subkeys->expires)
	{
	  fprintf (stderr, "Primary key unexpectedly expires: %lu\n",
		   key->subkeys->expires);
	  exit (1);
	}

      /* Secondary key.  */
      if (key->subkeys->next->revoked)
	{
	  fprintf (stderr, "Secondary key unexpectedly revoked\n");
	  exit (1);
	}
      if (key->subkeys->next->expired)
	{
	  fprintf (stderr, "Secondary key unexpectedly expired\n");
	  exit (1);
	}
      if (key->subkeys->next->disabled)
	{
	  fprintf (stderr, "Secondary key unexpectedly disabled\n");
	  exit (1);
	}
      if (key->subkeys->next->invalid)
	{
	  fprintf (stderr, "Secondary key unexpectedly invalid\n");
	  exit (1);
	}
      if (!key->subkeys->next->can_encrypt)
	{
	  fprintf (stderr, "Secondary key unexpectedly unusable for encryption\n");
	  exit (1);
	}
      if (key->subkeys->next->can_sign)
	{
	  fprintf (stderr, "Secondary key unexpectedly usable for signing\n");
	  exit (1);
	}
      if (key->subkeys->next->can_certify)
	{
	  fprintf (stderr, "Secondary key unexpectedly usable for certifications\n");
	  exit (1);
	}
      if (!key->subkeys->next->secret)
	{
	  fprintf (stderr, "Secondary key unexpectedly not secret\n");
	  exit (1);
	}
      if (key->subkeys->next->pubkey_algo != GPGME_PK_ELG_E)
	{
	  fprintf (stderr, "Secondary key has unexpected public key algo: %s\n",
		   gpgme_pubkey_algo_name (key->subkeys->next->pubkey_algo));
	  exit (1);
	}
      if (key->subkeys->next->length != 1024)
	{
	  fprintf (stderr, "Secondary key has unexpected length: %i\n",
		   key->subkeys->next->length);
	  exit (1);
	}
      if (strcmp (key->subkeys->next->keyid, keys[i].sec_keyid))
	{
	  fprintf (stderr, "Secondary key has unexpected key ID: %s\n",
		   key->subkeys->next->keyid);
	  exit (1);
	}
      if (!key->subkeys->next->fpr)
	{
	  fprintf (stderr, "Secondary key has unexpectedly no fingerprint\n");
	  exit (1);
	}
      if (key->subkeys->next->expires)
	{
	  fprintf (stderr, "Secondary key unexpectedly expires: %lu\n",
		   key->subkeys->next->expires);
	  exit (1);
	}

      /* FIXME: The below test will crash if we want to check for a
	 name, comment or email that doesn't exist in the key's user
	 IDs.  */
      if (!((!keys[i].uid[0].name && !key->uids)
	    || (keys[i].uid[0].name && !keys[i].uid[1].name
		&& key->uids && !key->uids->next)
	    || (keys[i].uid[0].name && keys[i].uid[1].name
		&& !keys[i].uid[2].name
		&& key->uids && key->uids->next && !key->uids->next->next)
	    || (keys[i].uid[0].name && keys[i].uid[1].name
		&& keys[i].uid[2].name
		&& key->uids && key->uids->next && key->uids->next->next
		&& !key->uids->next->next->next)))
	  {
	    fprintf (stderr, "Key has unexpected number of user IDs\n");
	    exit (1);
	  }
      if (key->uids && key->uids->revoked)
	{
	  fprintf (stderr, "First user ID unexpectedly revoked\n");
	  exit (1);
	}
      if (key->uids && key->uids->invalid)
	{
	  fprintf (stderr, "First user ID unexpectedly invalid\n");
	  exit (1);
	}
      if (key->uids && key->uids->validity != GPGME_VALIDITY_ULTIMATE)
	{
	  fprintf (stderr, "First user ID has unexpectedly validity: %i\n",
		   key->uids->validity);
	  exit (1);
	}
      if (keys[i].uid[0].name
	  && strcmp (keys[i].uid[0].name, key->uids->name))
	{
	  fprintf (stderr, "Unexpected name in first user ID: %s\n",
		   key->uids->name);
	  exit (1);
	}
      if (keys[i].uid[0].comment
	  && strcmp (keys[i].uid[0].comment, key->uids->comment))
	{
	  fprintf (stderr, "Unexpected comment in first user ID: %s\n",
		   key->uids->comment);
	  exit (1);
	}
      if (keys[i].uid[0].email
	  && strcmp (keys[i].uid[0].email, key->uids->email))
	{
	  fprintf (stderr, "Unexpected email in first user ID: %s\n",
		   key->uids->email);
	  exit (1);
	}
      if (key->uids && (!key->uids->signatures || key->uids->signatures->next))
	{
	  fprintf (stderr, "First user ID unexpected number of signatures\n");
	  exit (1);
	}
      if (keys[i].uid[0].sig.algo != key->uids->signatures->pubkey_algo)
	{
	  fprintf (stderr, "Unexpected algorithm in first user ID sig: %s\n",
		   gpgme_pubkey_algo_name (key->uids->signatures->pubkey_algo));
	  exit (1);
	}
      if (strcmp (keys[i].uid[0].sig.keyid, key->uids->signatures->keyid))
	{
	  fprintf (stderr, "Unexpected key ID in first user ID sig: %s\n",
		   key->uids->signatures->keyid);
	  exit (1);
	}
      if (strcmp (keys[i].uid[0].sig.name, key->uids->signatures->name))
	{
	  fprintf (stderr, "Unexpected name in first user ID sig: %s\n",
		   key->uids->signatures->name);
	  exit (1);
	}
      if (strcmp (keys[i].uid[0].sig.comment, key->uids->signatures->comment))
	{
	  fprintf (stderr, "Unexpected comment in first user ID sig: %s\n",
		   key->uids->signatures->comment);
	  exit (1);
	}
      if (strcmp (keys[i].uid[0].sig.email, key->uids->signatures->email))
	{
	  fprintf (stderr, "Unexpected email in first user ID sig: %s\n",
		   key->uids->signatures->email);
	  exit (1);
	}
      if (keys[i].uid[0].sig.sig_class != key->uids->signatures->sig_class)
	{
	  fprintf (stderr, "Unexpected class in first user ID sig: %i\n",
		   key->uids->signatures->sig_class);
	  exit (1);
	}
      if (keys[i].uid[0].sig.exportable != key->uids->signatures->exportable)
	{
	  fprintf (stderr, "Unexpected exportable stat in first user ID sig: %i\n",
		   key->uids->signatures->exportable);
	  exit (1);
	}

      if (key->uids && key->uids->next && key->uids->next->revoked)
	{
	  fprintf (stderr, "Second user ID unexpectedly revoked\n");
	  exit (1);
	}
      if (key->uids && key->uids->next && key->uids->next->invalid)
	{
	  fprintf (stderr, "Second user ID unexpectedly invalid\n");
	  exit (1);
	}
      if (key->uids && key->uids->next
	  && key->uids->next->validity != GPGME_VALIDITY_ULTIMATE)
	{
	  fprintf (stderr, "Second user ID has unexpectedly validity: %i\n",
		   key->uids->next->validity);
	  exit (1);
	}
      if (keys[i].uid[1].name
	  && strcmp (keys[i].uid[1].name, key->uids->next->name))
	{
	  fprintf (stderr, "Unexpected name in second user ID: %s\n",
		   key->uids->next->name);
	  exit (1);
	}
      if (keys[i].uid[1].comment
	  && strcmp (keys[i].uid[1].comment, key->uids->next->comment))
	{
	  fprintf (stderr, "Unexpected comment in second user ID: %s\n",
		   key->uids->next->comment);
	  exit (1);
	}
      if (keys[i].uid[1].email
	  && strcmp (keys[i].uid[1].email, key->uids->next->email))
	{
	  fprintf (stderr, "Unexpected email in second user ID: %s\n",
		   key->uids->next->email);
	  exit (1);
	}
      /* Note: There is a bug in gpg 1.3.4 which duplicates a
         signature after importing the secret key.  Thus we disable
         the second part of the check. */
      if (key->uids && (!key->uids->next->signatures /*|| key->uids->next->signatures->next*/))
	{
	  fprintf (stderr, "Second user ID unexpected number of signatures\n");
	  exit (1);
	}
      if (keys[i].uid[1].sig.algo != key->uids->next->signatures->pubkey_algo)
	{
	  fprintf (stderr, "Unexpected algorithm in second user ID sig: %s\n",
		   gpgme_pubkey_algo_name (key->uids->next->signatures->pubkey_algo));
	  exit (1);
	}
      if (strcmp (keys[i].uid[1].sig.keyid, key->uids->next->signatures->keyid))
	{
	  fprintf (stderr, "Unexpected key ID in second user ID sig: %s\n",
		   key->uids->next->signatures->keyid);
	  exit (1);
	}
      if (strcmp (keys[i].uid[1].sig.name, key->uids->next->signatures->name))
	{
	  fprintf (stderr, "Unexpected name in second user ID sig: %s\n",
		   key->uids->next->signatures->name);
	  exit (1);
	}
      if (strcmp (keys[i].uid[1].sig.comment, key->uids->next->signatures->comment))
	{
	  fprintf (stderr, "Unexpected comment in second user ID sig: %s\n",
		   key->uids->next->signatures->comment);
	  exit (1);
	}
      if (strcmp (keys[i].uid[1].sig.email, key->uids->next->signatures->email))
	{
	  fprintf (stderr, "Unexpected email in second user ID sig: %s\n",
		   key->uids->next->signatures->email);
	  exit (1);
	}
      if (keys[i].uid[1].sig.sig_class != key->uids->next->signatures->sig_class)
	{
	  fprintf (stderr, "Unexpected class in second user ID sig: %i\n",
		   key->uids->next->signatures->sig_class);
	  exit (1);
	}
      if (keys[i].uid[1].sig.exportable != key->uids->next->signatures->exportable)
	{
	  fprintf (stderr, "Unexpected exportable stat in second user ID sig: %i\n",
		   key->uids->next->signatures->exportable);
	  exit (1);
	}

      if (key->uids && key->uids->next && key->uids->next->next
	  && key->uids->next->next->revoked)
	{
	  fprintf (stderr, "Third user ID unexpectedly revoked\n");
	  exit (1);
	}
      if (key->uids && key->uids->next && key->uids->next->next
	  && key->uids->next->next->invalid)
	{
	  fprintf (stderr, "Third user ID unexpectedly invalid\n");
	  exit (1);
	}
      if (key->uids && key->uids->next && key->uids->next->next
	  && key->uids->next->next->validity != GPGME_VALIDITY_ULTIMATE)
	{
	  fprintf (stderr, "Third user ID has unexpectedly validity: %i\n",
		   key->uids->next->next->validity);
	  exit (1);
	}
      if (keys[i].uid[2].name
	  && strcmp (keys[i].uid[2].name, key->uids->next->next->name))
	{
	  fprintf (stderr, "Unexpected name in third user ID: %s\n",
		   key->uids->next->next->name);
	  exit (1);
	}
      if (keys[i].uid[2].comment
	  && strcmp (keys[i].uid[2].comment, key->uids->next->next->comment))
	{
	  fprintf (stderr, "Unexpected comment in third user ID: %s\n",
		   key->uids->next->next->comment);
	  exit (1);
	}
      if (keys[i].uid[2].email
	  && strcmp (keys[i].uid[2].email, key->uids->next->next->email))
	{
	  fprintf (stderr, "Unexpected email in third user ID: %s\n",
		   key->uids->next->next->email);
	  exit (1);
	}
      if (key->uids && (!key->uids->next->next->signatures
			|| key->uids->next->next->signatures->next))
	{
	  fprintf (stderr, "Third user ID unexpected number of signatures\n");
	  exit (1);
	}
      if (keys[i].uid[2].sig.algo != key->uids->next->next->signatures->pubkey_algo)
	{
	  fprintf (stderr, "Unexpected algorithm in third user ID sig: %s\n",
		   gpgme_pubkey_algo_name (key->uids->next->next->signatures->pubkey_algo));
	  exit (1);
	}
      if (strcmp (keys[i].uid[2].sig.keyid, key->uids->next->next->signatures->keyid))
	{
	  fprintf (stderr, "Unexpected key ID in third user ID sig: %s\n",
		   key->uids->next->next->signatures->keyid);
	  exit (1);
	}
      if (strcmp (keys[i].uid[2].sig.name, key->uids->next->next->signatures->name))
	{
	  fprintf (stderr, "Unexpected name in third user ID sig: %s\n",
		   key->uids->next->next->signatures->name);
	  exit (1);
	}
      if (strcmp (keys[i].uid[2].sig.comment, key->uids->next->next->signatures->comment))
	{
	  fprintf (stderr, "Unexpected comment in third user ID sig: %s\n",
		   key->uids->next->next->signatures->comment);
	  exit (1);
	}
      if (strcmp (keys[i].uid[2].sig.email, key->uids->next->next->signatures->email))
	{
	  fprintf (stderr, "Unexpected email in third user ID sig: %s\n",
		   key->uids->next->next->signatures->email);
	  exit (1);
	}
      if (keys[i].uid[2].sig.sig_class != key->uids->next->next->signatures->sig_class)
	{
	  fprintf (stderr, "Unexpected class in third user ID sig: %i\n",
		   key->uids->next->next->signatures->sig_class);
	  exit (1);
	}
      if (keys[i].uid[2].sig.exportable != key->uids->next->next->signatures->exportable)
	{
	  fprintf (stderr, "Unexpected exportable stat in third user ID sig: %i\n",
		   key->uids->next->next->signatures->exportable);
	  exit (1);
	}

      gpgme_key_unref (key);
      i++;
    }
  if (gpgme_err_code (err) != GPG_ERR_EOF)
    fail_if_err (err);
  err = gpgme_op_keylist_end (ctx);
  fail_if_err (err);

  result = gpgme_op_keylist_result (ctx);
  if (result->truncated)
    {
      fprintf (stderr, "Key listing unexpectedly truncated\n");
      exit (1);
    }

  if (keys[i].fpr)
    {
      fprintf (stderr, "Less keys returned than expected\n");
      exit (1);
    }

  gpgme_release (ctx);
  return 0;
}
