#!/usr/bin/env python

# Copyright (C) 2016 g10 Code GmbH
#
# This file is part of GPGME.
#
# GPGME is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# GPGME is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General
# Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, print_function, unicode_literals
del absolute_import, print_function, unicode_literals

from pyme import core, constants
import support

support.init_gpgme(constants.PROTOCOL_OpenPGP)
c = core.Context()

# Check expration of keys.  This test assumes three subkeys of which
# 2 are expired; it is used with the "Whisky" test key.  It has
# already been checked that these 3 subkeys are available.
def check_whisky(name, key):
  sub1 = key.subkeys[2]
  sub2 = key.subkeys[3]

  assert sub1.expired and sub2.expired, \
      "Subkey of `{}' not flagged as expired".format(name)
  assert sub1.expires == 1129636886 and sub2.expires == 1129636939, \
      "Subkey of `{}' has wrong expiration date".format(name)

keys = [
    [ "A0FF4590BB6122EDEF6E3C542D727CC768697734", "6AE6D7EE46A871F8",
      [ [ "Alfa Test", "demo key", "alfa@example.net" ],
        [ "Alpha Test", "demo key", "alpha@example.net" ],
	[ "Alice", "demo key", "" ] ], 1 ],
    [ "D695676BDCEDCC2CDD6152BCFE180B1DA9E3B0B2", "5381EA4EE29BA37F",
      [ [ "Bob", "demo key", "" ],
	[ "Bravo Test", "demo key", "bravo@example.net" ] ], 1 ],
    [ "61EE841A2A27EB983B3B3C26413F4AF31AFDAB6C", "E71E72ACBC43DA60",
      [ [ "Charlie Test", "demo key", "charlie@example.net" ] ], 1 ],
    [ "6560C59C43D031C54D7C588EEBA9F240EB9DC9E6", "06F22880B0C45424",
      [ [ "Delta Test", "demo key", "delta@example.net" ] ], 1 ],
    [ "3531152DE293E26A07F504BC318C1FAEFAEF6D1B", "B5C79E1A7272144D",
      [ [ "Echelon", "demo key", "" ],
	[ "Echo Test", "demo key", "echo@example.net" ],
	[ "Eve", "demo key", "" ] ], 1 ],
    [ "56D33268F7FE693FBB594762D4BF57F37372E243", "0A32EE79EE45198E",
      [ [ "Foxtrot Test", "demo key", "foxtrot@example.net" ] ], 1 ],
    [ "C9C07DCC6621B9FB8D071B1D168410A48FC282E6", "247491CC9DCAD354",
      [ [ "Golf Test", "demo key", "golf@example.net" ] ], 1 ],
    [ "9E91CBB11E4D4135583EF90513DB965534C6E3F1", "76E26537D622AD0A",
      [ [ "Hotel Test", "demo key", "hotel@example.net" ] ], 1 ],
    [ "CD538D6CC9FB3D745ECDA5201FE8FC6F04259677", "C1C8EFDE61F76C73",
      [ [ "India Test", "demo key", "india@example.net" ] ], 1 ],
    [ "F8F1EDC73995AB739AD54B380C820C71D2699313", "BD0B108735F8F136",
      [ [ "Juliet Test", "demo key", "juliet@example.net" ] ], 1 ],
    [ "3FD11083779196C2ECDD9594AD1B0FAD43C2D0C7", "86CBB34A9AF64D02",
      [ [ "Kilo Test", "demo key", "kilo@example.net" ] ], 1 ],
    [ "1DDD28CEF714F5B03B8C246937CAB51FB79103F8", "0363B449FE56350C",
      [ [ "Lima Test", "demo key", "lima@example.net" ] ], 1 ],
    [ "2686AA191A278013992C72EBBE794852BE5CF886", "5F600A834F31EAE8",
      [ [ "Mallory", "demo key", "" ],
	[ "Mike Test", "demo key", "mike@example.net" ] ], 1 ],
    [ "5AB9D6D7BAA1C95B3BAA3D9425B00FD430CEC684", "4C1D63308B70E472",
      [ [ "November Test", "demo key", "november@example.net" ] ], 1 ],
    [ "43929E89F8F79381678CAE515F6356BA6D9732AC", "FF0785712681619F",
      [ [ "Oscar Test", "demo key", "oscar@example.net" ] ], 1 ],
    [ "6FAA9C201E5E26DCBAEC39FD5D15E01D3FF13206", "2764E18263330D9C",
      [ [ "Papa test", "demo key", "papa@example.net" ] ], 1 ],
    [ "A7969DA1C3297AA96D49843F1C67EC133C661C84", "6CDCFC44A029ACF4",
      [ [ "Quebec Test", "demo key", "quebec@example.net" ] ], 1 ],
    [ "38FBE1E4BF6A5E1242C8F6A13BDBEDB1777FBED3", "9FAB805A11D102EA",
      [ [ "Romeo Test", "demo key", "romeo@example.net" ] ], 1 ],
    [ "045B2334ADD69FC221076841A5E67F7FA3AE3EA1", "93B88B0F0F1B50B4",
      [ [ "Sierra Test", "demo key", "sierra@example.net" ] ], 1 ],
    [ "ECAC774F4EEEB0620767044A58CB9A4C85A81F38", "97B60E01101C0402",
      [ [ "Tango Test", "demo key", "tango@example.net" ] ], 1 ],
    [ "0DBCAD3F08843B9557C6C4D4A94C0F75653244D6", "93079B915522BDB9",
      [ [ "Uniform Test", "demo key", "uniform@example.net" ] ], 1 ],
    [ "E8143C489C8D41124DC40D0B47AF4B6961F04784", "04071FB807287134",
      [ [ "Victor Test", "demo key", "victor@example.org" ] ], 1 ],
    [ "E8D6C90B683B0982BD557A99DEF0F7B8EC67DBDE", "D7FBB421FD6E27F6",
      [ [ "Whisky Test", "demo key", "whisky@example.net" ] ], 3,
      check_whisky ],
    [ "04C1DF62EFA0EBB00519B06A8979A6C5567FB34A", "5CC6F87F41E408BE",
      [ [ "XRay Test", "demo key", "xray@example.net" ] ], 1 ],
    [ "ED9B316F78644A58D042655A9EEF34CD4B11B25F", "5ADFD255F7B080AD",
      [ [ "Yankee Test", "demo key", "yankee@example.net" ] ], 1 ],
    [ "23FD347A419429BACCD5E72D6BC4778054ACD246", "EF9DC276A172C881",
      [ [ "Zulu Test", "demo key", "zulu@example.net" ] ], 1 ],
]

def check_global(key, uids, n_subkeys):
    assert not key.revoked, "Key unexpectedly revoked"
    assert not key.expired, "Key unexpectedly expired"
    assert not key.disabled, "Key unexpectedly disabled"
    assert not key.invalid, "Key unexpectedly invalid"
    assert key.can_sign, "Key unexpectedly unusable for signing"
    assert key.can_certify, "Key unexpectedly unusable for certifications"
    assert not key.secret, "Key unexpectedly secret"
    assert not key.protocol != constants.PROTOCOL_OpenPGP, \
        "Key has unexpected protocol: {}".format(key.protocol)
    assert not key.issuer_serial, \
        "Key unexpectedly carries issuer serial: {}".format(key.issuer_serial)
    assert not key.issuer_name, \
        "Key unexpectedly carries issuer name: {}".format(key.issuer_name)
    assert not key.chain_id, \
        "Key unexpectedly carries chain ID: {}".format(key.chain_id)

    # Only key Alfa is trusted
    assert key.uids[0].name == 'Alfa Test' \
      or key.owner_trust == constants.VALIDITY_UNKNOWN, \
        "Key has unexpected owner trust: {}".format(key.owner_trust)
    assert key.uids[0].name != 'Alfa Test' \
      or key.owner_trust == constants.VALIDITY_ULTIMATE, \
        "Key has unexpected owner trust: {}".format(key.owner_trust)

    assert len(key.subkeys) - 1 == n_subkeys, \
        "Key `{}' has unexpected number of subkeys".format(uids[0][0])


def check_subkey(fpr, which, subkey):
    assert not subkey.revoked, which + " key unexpectedly revoked"
    assert not subkey.expired, which + " key unexpectedly expired"
    assert not subkey.disabled, which + " key unexpectedly disabled"
    assert not subkey.invalid, which + " key unexpectedly invalid"

    if which == "Primary":
        assert not subkey.can_encrypt, \
            which + " key unexpectedly usable for encryption"
        assert subkey.can_sign, \
            which + " key unexpectedly unusable for signing"
        assert subkey.can_certify, \
            which + " key unexpectedly unusable for certifications"
    else:
        assert subkey.can_encrypt, \
            which + " key unexpectedly unusable for encryption"
        assert not subkey.can_sign, \
            which + " key unexpectedly usable for signing"
        assert not subkey.can_certify, \
            which + " key unexpectedly usable for certifications"

    assert not subkey.secret, which + " key unexpectedly secret"
    assert not subkey.is_cardkey, "Public key marked as card key"
    assert not subkey.card_number, "Public key with card number set"
    assert not subkey.pubkey_algo != (constants.PK_DSA if which == "Primary"
                                      else constants.PK_ELG_E), \
        which + " key has unexpected public key algo: {}".\
            format(subkey.pubkey_algo)
    assert subkey.length == 1024, \
        which + " key has unexpected length: {}".format(subkey.length)
    assert fpr.endswith(subkey.keyid), \
        which + " key has unexpected key ID: {}".format(subkey.keyid)
    assert which == "Secondary" or subkey.fpr == fpr, \
        which + " key has unexpected fingerprint: {}".format(subkey.fpr)
    assert not subkey.expires, \
        which + " key unexpectedly expires: {}".format(subkey.expires)

def check_uid(which, ref, uid):
    assert not uid.revoked, which + " user ID unexpectedly revoked"
    assert not uid.invalid, which + " user ID unexpectedly invalid"
    assert uid.validity == (constants.VALIDITY_UNKNOWN
                            if uid.name.split()[0]
                            not in {'Alfa', 'Alpha', 'Alice'} else
                            constants.VALIDITY_ULTIMATE), \
      which + " user ID has unexpectedly validity: {}".format(uid.validity)
    assert not uid.signatures, which + " user ID unexpectedly signed"
    assert uid.name == ref[0], \
      "Unexpected name in {} user ID: {!r}".format(which.lower(), uid.name)
    assert uid.comment == ref[1], \
      "Unexpected comment in {} user ID: {!r}".format(which.lower(),
                                                      uid.comment)
    assert uid.email == ref[2], \
      "Unexpected email in {} user ID: {!r}".format(which.lower(), uid.email)

i = 0
c.op_keylist_start(None, False)
key = c.op_keylist_next ()
while key:
    try:
        if len(keys[i]) == 4:
            fpr, sec_keyid, uids, n_subkeys = keys[i]
            misc_check = None
        else:
            fpr, sec_keyid, uids, n_subkeys, misc_check = keys[i]
    except IndexError:
        # There are more keys.  We don't check for that.
        break

    # Global key flags.
    check_global(key, uids, n_subkeys)
    check_subkey(fpr, "Primary", key.subkeys[0])
    check_subkey(sec_keyid, "Secondary", key.subkeys[1])

    assert len(key.uids) == len(uids)
    check_uid("First", uids[0], key.uids[0])
    if len(key.uids) > 1:
      check_uid("Second", uids[1], key.uids[1])
    if len(key.uids) > 2:
      check_uid("Third", uids[2], key.uids[2])

    if misc_check:
        misc_check (uids[0][0], key)
    key = c.op_keylist_next ()
    i += 1

c.op_keylist_end()
result = c.op_keylist_result()
assert not result.truncated, "Key listing unexpectedly truncated"


for i, key in enumerate(c.keylist()):
    try:
        if len(keys[i]) == 4:
            fpr, sec_keyid, uids, n_subkeys = keys[i]
            misc_check = None
        else:
            fpr, sec_keyid, uids, n_subkeys, misc_check = keys[i]
    except IndexError:
        # There are more keys.  We don't check for that.
        break

    # Global key flags.
    check_global(key, uids, n_subkeys)
    check_subkey(fpr, "Primary", key.subkeys[0])
    check_subkey(sec_keyid, "Secondary", key.subkeys[1])

    assert len(key.uids) == len(uids)
    check_uid("First", uids[0], key.uids[0])
    if len(key.uids) > 1:
      check_uid("Second", uids[1], key.uids[1])
    if len(key.uids) > 2:
      check_uid("Third", uids[2], key.uids[2])

    if misc_check:
        misc_check (uids[0][0], key)
