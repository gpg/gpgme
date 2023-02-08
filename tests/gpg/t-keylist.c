/* t-keylist.c  - regression test
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


struct key_info_s
{
  const char *fpr;
  const char *sec_keyid;
  struct
  {
    const char *name;
    const char *comment;
    const char *email;
    gpgme_validity_t validity;
  } uid[3];
  int n_subkeys;
  gpgme_validity_t owner_trust;
  void (*misc_check)(struct key_info_s *keyinfo, gpgme_key_t key);
};


static void check_whisky (struct key_info_s *keyinfo, gpgme_key_t key);



struct key_info_s keys[] =
  {
    { "A0FF4590BB6122EDEF6E3C542D727CC768697734", "6AE6D7EE46A871F8",
      { { "Alfa Test", "demo key", "alfa@example.net",
	  GPGME_VALIDITY_ULTIMATE },
        { "Alpha Test", "demo key", "alpha@example.net",
	    GPGME_VALIDITY_ULTIMATE },
	{ "Alice", "demo key", NULL, GPGME_VALIDITY_ULTIMATE } }, 1,
	GPGME_VALIDITY_ULTIMATE },
    { "D695676BDCEDCC2CDD6152BCFE180B1DA9E3B0B2", "5381EA4EE29BA37F",
      { { "Bob", "demo key", NULL },
	{ "Bravo Test", "demo key", "bravo@example.net" } }, 1 },
    { "61EE841A2A27EB983B3B3C26413F4AF31AFDAB6C", "E71E72ACBC43DA60",
      { { "Charlie Test", "demo key", "charlie@example.net" } }, 1 },
    { "6560C59C43D031C54D7C588EEBA9F240EB9DC9E6", "06F22880B0C45424",
      { { "Delta Test", "demo key", "delta@example.net" } }, 1 },
    { "3531152DE293E26A07F504BC318C1FAEFAEF6D1B", "B5C79E1A7272144D",
      { { "Echelon", "demo key", NULL },
	{ "Echo Test", "demo key", "echo@example.net" },
	{ "Eve", "demo key", NULL } }, 1 },
    { "56D33268F7FE693FBB594762D4BF57F37372E243", "0A32EE79EE45198E",
      { { "Foxtrot Test", "demo key", "foxtrot@example.net" } }, 1 },
    { "C9C07DCC6621B9FB8D071B1D168410A48FC282E6", "247491CC9DCAD354",
      { { "Golf Test", "demo key", "golf@example.net" } }, 1 },
    { "9E91CBB11E4D4135583EF90513DB965534C6E3F1", "76E26537D622AD0A",
      { { "Hotel Test", "demo key", "hotel@example.net" } }, 1 },
    { "CD538D6CC9FB3D745ECDA5201FE8FC6F04259677", "C1C8EFDE61F76C73",
      { { "India Test", "demo key", "india@example.net" } }, 1 },
    { "F8F1EDC73995AB739AD54B380C820C71D2699313", "BD0B108735F8F136",
      { { "Juliet Test", "demo key", "juliet@example.net" } }, 1 },
    { "3FD11083779196C2ECDD9594AD1B0FAD43C2D0C7", "86CBB34A9AF64D02",
      { { "Kilo Test", "demo key", "kilo@example.net" } }, 1 },
    { "1DDD28CEF714F5B03B8C246937CAB51FB79103F8", "0363B449FE56350C",
      { { "Lima Test", "demo key", "lima@example.net" } }, 1 },
    { "2686AA191A278013992C72EBBE794852BE5CF886", "5F600A834F31EAE8",
      { { "Mallory", "demo key", NULL },
	{ "Mike Test", "demo key", "mike@example.net" } }, 1 },
    { "5AB9D6D7BAA1C95B3BAA3D9425B00FD430CEC684", "4C1D63308B70E472",
      { { "November Test", "demo key", "november@example.net" } }, 1 },
    { "43929E89F8F79381678CAE515F6356BA6D9732AC", "FF0785712681619F",
      { { "Oscar Test", "demo key", "oscar@example.net" } }, 1 },
    { "6FAA9C201E5E26DCBAEC39FD5D15E01D3FF13206", "2764E18263330D9C",
      { { "Papa test", "demo key", "papa@example.net" } }, 1 },
    { "A7969DA1C3297AA96D49843F1C67EC133C661C84", "6CDCFC44A029ACF4",
      { { "Quebec Test", "demo key", "quebec@example.net" } }, 1 },
    { "38FBE1E4BF6A5E1242C8F6A13BDBEDB1777FBED3", "9FAB805A11D102EA",
      { { "Romeo Test", "demo key", "romeo@example.net" } }, 1 },
    { "045B2334ADD69FC221076841A5E67F7FA3AE3EA1", "93B88B0F0F1B50B4",
      { { "Sierra Test", "demo key", "sierra@example.net" } }, 1 },
    { "ECAC774F4EEEB0620767044A58CB9A4C85A81F38", "97B60E01101C0402",
      { { "Tango Test", "demo key", "tango@example.net" } }, 1 },
    { "0DBCAD3F08843B9557C6C4D4A94C0F75653244D6", "93079B915522BDB9",
      { { "Uniform Test", "demo key", "uniform@example.net" } }, 1 },
    { "E8143C489C8D41124DC40D0B47AF4B6961F04784", "04071FB807287134",
      { { "Victor Test", "demo key", "victor@example.org" } }, 1 },
    { "E8D6C90B683B0982BD557A99DEF0F7B8EC67DBDE", "D7FBB421FD6E27F6",
      { { "Whisky Test", "demo key", "whisky@example.net" } }, 3,
	GPGME_VALIDITY_UNKNOWN, check_whisky },
    { "04C1DF62EFA0EBB00519B06A8979A6C5567FB34A", "5CC6F87F41E408BE",
      { { "XRay Test", "demo key", "xray@example.net" } }, 1 },
    { "ED9B316F78644A58D042655A9EEF34CD4B11B25F", "5ADFD255F7B080AD",
      { { "Yankee Test", "demo key", "yankee@example.net" } }, 1 },
    { "23FD347A419429BACCD5E72D6BC4778054ACD246", "EF9DC276A172C881",
      { { "Zulu Test", "demo key", "zulu@example.net" } }, 1 },
    { "ADAB7FCC1F4DE2616ECFA402AF82244F9CD9FD55", "087DD7E0381701C4",
      { { "Joe Random Hacker", "test key with passphrase \"abc\"",
	  "joe@example.com" } }, 1 },
    { NULL }
  };


int
main (int argc, char **argv)
{
  gpgme_error_t err;
  gpgme_ctx_t ctx;
  gpgme_key_t key;
  gpgme_keylist_result_t result;
  int i = 0;
  int n;
  gpgme_subkey_t subkey;

  (void)argc;
  (void)argv;

  init_gpgme (GPGME_PROTOCOL_OpenPGP);

  err = gpgme_new (&ctx);
  fail_if_err (err);

  err = gpgme_op_keylist_start (ctx, NULL, 0);
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
#if 0
      /* GnuPG 2.1+ have a different subkey for encryption.  */
      if (!key->can_encrypt)
	{
	  fprintf (stderr, "Key unexpectedly unusable for encryption\n");
	  exit (1);
	}
#endif
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
      if (key->secret)
	{
	  fprintf (stderr, "Key unexpectedly secret\n");
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
      if (key->owner_trust != keys[i].owner_trust)
	{
	  fprintf (stderr, "Key `%s' has unexpected owner trust: %i\n",
		   keys[i].uid[0].name, key->owner_trust);
	  exit (1);
	}

      for (n=0, subkey = key->subkeys; subkey; subkey = subkey->next)
        n++;
      if (!n || n-1 != keys[i].n_subkeys)
	{
	  fprintf (stderr, "Key `%s' has unexpected number of subkeys\n",
                   keys[i].uid[0].name);
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
      if (key->subkeys->secret)
	{
	  fprintf (stderr, "Primary key unexpectedly secret\n");
	  exit (1);
	}
      if (key->subkeys->is_cardkey)
	{
	  fprintf (stderr, "Public key marked as card key\n");
	  exit (1);
	}
      if (key->subkeys->card_number)
	{
	  fprintf (stderr, "Public key with card number set\n");
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
	  fprintf (stderr, "Primary key `%s' has unexpected key ID: %s\n",
		   keys[i].uid[0].name, key->subkeys->keyid);
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
	  fprintf (stderr, "Primary key `%s' unexpectedly expires: %lu\n",
		   keys[i].uid[0].name, key->subkeys->expires);
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
      if (key->subkeys->next->secret)
	{
	  fprintf (stderr, "Secondary key unexpectedly secret\n");
	  exit (1);
	}
      if (key->subkeys->next->is_cardkey)
	{
	  fprintf (stderr, "Secondary public key marked as card key\n");
	  exit (1);
	}
      if (key->subkeys->next->card_number)
	{
	  fprintf (stderr, "Secondary public key with card number set\n");
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
	  fprintf (stderr, "Secondary key `%s' has unexpected key ID: %s/%s\n",
		   keys[i].uid[0].name,
                   key->subkeys->next->keyid, keys[i].sec_keyid );
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
      if (key->uids && key->uids->validity != keys[i].uid[0].validity)
	{
	  fprintf (stderr, "First user ID `%s' has unexpectedly validity: %i\n",
		   key->uids->name, key->uids->validity);
	  exit (1);
	}
      if (key->uids && key->uids->signatures)
	{
	  fprintf (stderr, "First user ID unexpectedly signed\n");
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
	  && key->uids->next->validity != keys[i].uid[1].validity)
	{
	  fprintf (stderr, "Second user ID has unexpectedly validity: %i\n",
		   key->uids->next->validity);
	  exit (1);
	}
      if (key->uids && key->uids->next && key->uids->next->signatures)
	{
	  fprintf (stderr, "Second user ID unexpectedly signed\n");
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
	  && key->uids->next->next->validity != keys[i].uid[2].validity)
	{
	  fprintf (stderr, "Third user ID has unexpectedly validity: %i\n",
		   key->uids->next->next->validity);
	  exit (1);
	}
      if (key->uids && key->uids->next && key->uids->next->next
	  && key->uids->next->next->signatures)
	{
	  fprintf (stderr, "Third user ID unexpectedly signed\n");
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

      if (keys[i].misc_check)
        keys[i].misc_check (keys+i, key);

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
      fprintf (stderr, "Less keys (%d) returned than expected (%d)\n",
	       i, (int)(DIM (keys) - 1));
      exit (1);
    }

  gpgme_release (ctx);
  return 0;
}



/* Check expration of keys.  This test assumes three subkeys of which
   2 are expired; it is used with the "Whisky" test key.  It has
   already been checked that these 3 subkeys are available. */
static void
check_whisky (struct key_info_s *keyinfo, gpgme_key_t key)
{
  const char *name = keyinfo->uid[0].name;
  gpgme_subkey_t sub1, sub2;

  sub1 = key->subkeys->next->next;
  sub2 = sub1->next;

  if (!sub1->expired || !sub2->expired)
    {
      fprintf (stderr, "Subkey of `%s' not flagged as expired\n", name);
      exit (1);
    }
  if (sub1->expires != 1129636886 || sub2->expires != 1129636939)
    {
      fprintf (stderr, "Subkey of `%s' has wrong expiration date\n", name);
      exit (1);
    }

}

