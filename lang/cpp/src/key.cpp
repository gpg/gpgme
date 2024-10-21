/*
  key.cpp - wraps a gpgme key
  Copyright (C) 2003, 2005 Klarälvdalens Datakonsult AB

  This file is part of GPGME++.

  GPGME++ is free software; you can redistribute it and/or
  modify it under the terms of the GNU Library General Public
  License as published by the Free Software Foundation; either
  version 2 of the License, or (at your option) any later version.

  GPGME++ is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Library General Public License for more details.

  You should have received a copy of the GNU Library General Public License
  along with GPGME++; see the file COPYING.LIB.  If not, write to the
  Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
  Boston, MA 02110-1301, USA.
*/

#ifdef HAVE_CONFIG_H
 #include "config.h"
#endif

#include <key.h>

#include "util.h"
#include "tofuinfo.h"
#include "context.h"
#include "engineinfo.h"

#include <gpgme.h>

#include <string.h>
#include <strings.h>
#include <cassert>
#include <istream>
#include <iterator>

const GpgME::Key::Null GpgME::Key::null;

namespace GpgME
{

Key::Key() : key() {}

Key::Key(const Null &) : key() {}

Key::Key(const shared_gpgme_key_t &k) : key(k) {}

Key::Key(gpgme_key_t k, bool ref)
    : key(k
          ? shared_gpgme_key_t(k, &gpgme_key_unref)
          : shared_gpgme_key_t())
{
    if (ref && impl()) {
        gpgme_key_ref(impl());
    }
}

UserID Key::userID(unsigned int index) const
{
    return UserID(key, index);
}

Subkey Key::subkey(unsigned int index) const
{
    return Subkey(key, index);
}

unsigned int Key::numUserIDs() const
{
    if (!key) {
        return 0;
    }
    unsigned int count = 0;
    for (gpgme_user_id_t uid = key->uids ; uid ; uid = uid->next) {
        ++count;
    }
    return count;
}

unsigned int Key::numSubkeys() const
{
    if (!key) {
        return 0;
    }
    unsigned int count = 0;
    for (gpgme_sub_key_t subkey = key->subkeys ; subkey ; subkey = subkey->next) {
        ++count;
    }
    return count;
}

std::vector<UserID> Key::userIDs() const
{
    if (!key) {
        return std::vector<UserID>();
    }

    std::vector<UserID> v;
    v.reserve(numUserIDs());
    for (gpgme_user_id_t uid = key->uids ; uid ; uid = uid->next) {
        v.push_back(UserID(key, uid));
    }
    return v;
}

std::vector<Subkey> Key::subkeys() const
{
    if (!key) {
        return std::vector<Subkey>();
    }

    std::vector<Subkey> v;
    v.reserve(numSubkeys());
    for (gpgme_sub_key_t subkey = key->subkeys ; subkey ; subkey = subkey->next) {
        v.push_back(Subkey(key, subkey));
    }
    return v;
}

RevocationKey Key::revocationKey(unsigned int index) const
{
    return RevocationKey(key, index);
}

unsigned int Key::numRevocationKeys() const
{
    if (!key) {
        return 0;
    }
    unsigned int count = 0;
    for (auto revkey = key->revocation_keys; revkey; revkey = revkey->next) {
        ++count;
    }
    return count;
}

std::vector<RevocationKey> Key::revocationKeys() const
{
    if (!key) {
        return std::vector<RevocationKey>();
    }

    std::vector<RevocationKey> v;
    v.reserve(numRevocationKeys());
    for (auto revkey = key->revocation_keys; revkey; revkey = revkey->next) {
        v.push_back(RevocationKey(key, revkey));
    }
    return v;
}

Key::OwnerTrust Key::ownerTrust() const
{
    if (!key) {
        return Unknown;
    }
    switch (key->owner_trust) {
    default:
    case GPGME_VALIDITY_UNKNOWN:   return Unknown;
    case GPGME_VALIDITY_UNDEFINED: return Undefined;
    case GPGME_VALIDITY_NEVER:     return Never;
    case GPGME_VALIDITY_MARGINAL:  return Marginal;
    case GPGME_VALIDITY_FULL:     return Full;
    case GPGME_VALIDITY_ULTIMATE: return Ultimate;
    }
}
char Key::ownerTrustAsString() const
{
    if (!key) {
        return '?';
    }
    switch (key->owner_trust) {
    default:
    case GPGME_VALIDITY_UNKNOWN:   return '?';
    case GPGME_VALIDITY_UNDEFINED: return 'q';
    case GPGME_VALIDITY_NEVER:     return 'n';
    case GPGME_VALIDITY_MARGINAL:  return 'm';
    case GPGME_VALIDITY_FULL:     return 'f';
    case GPGME_VALIDITY_ULTIMATE: return 'u';
    }
}

Protocol Key::protocol() const
{
    if (!key) {
        return UnknownProtocol;
    }
    switch (key->protocol) {
    case GPGME_PROTOCOL_CMS:     return CMS;
    case GPGME_PROTOCOL_OpenPGP: return OpenPGP;
    default:                     return UnknownProtocol;
    }
}

const char *Key::protocolAsString() const
{
    return key ? gpgme_get_protocol_name(key->protocol) : nullptr ;
}

bool Key::isRevoked() const
{
    return key && key->revoked;
}

bool Key::isExpired() const
{
    return key && key->expired;
}

bool Key::isDisabled() const
{
    return key && key->disabled;
}

bool Key::isInvalid() const
{
    return key && key->invalid;
}

bool Key::hasSecret() const
{
    return key && key->secret;
}

bool Key::isRoot() const
{
    return key && key->subkeys && key->subkeys->fpr && key->chain_id &&
           strcasecmp(key->subkeys->fpr, key->chain_id) == 0;
}

bool Key::canEncrypt() const
{
    return key && key->can_encrypt;
}

bool Key::canSign() const
{
    return key && key->can_sign;
}

bool Key::canReallySign() const
{
    return canSign();
}

bool Key::canCertify() const
{
    return key && key->can_certify;
}

bool Key::canAuthenticate() const
{
    return key && key->can_authenticate;
}

bool Key::isQualified() const
{
    return key && key->is_qualified;
}

bool Key::isDeVs() const
{
    if (!key || !key->subkeys) {
        return false;
    }
    for (gpgme_sub_key_t subkey = key->subkeys ; subkey ; subkey = subkey->next) {
        if (!subkey->is_de_vs) {
            return false;
        }
    }
    return true;
}

bool Key::isBetaCompliance() const
{
    if (!key || !key->subkeys) {
        return false;
    }
    for (gpgme_sub_key_t subkey = key->subkeys ; subkey ; subkey = subkey->next) {
        if (!subkey->beta_compliance) {
            return false;
        }
    }
    return true;
}

bool Key::hasCertify() const
{
    return key && key->has_certify;
}

bool Key::hasSign() const
{
    return key && key->has_sign;
}

bool Key::hasEncrypt() const
{
    return key && key->has_encrypt;
}

bool Key::hasAuthenticate() const
{
    return key && key->has_authenticate;
}

const char *Key::issuerSerial() const
{
    return key ? key->issuer_serial : nullptr ;
}
const char *Key::issuerName() const
{
    return key ? key->issuer_name : nullptr ;
}
const char *Key::chainID() const
{
    return key ? key->chain_id : nullptr ;
}

const char *Key::keyID() const
{
    return key && key->subkeys ? key->subkeys->keyid : nullptr ;
}

const char *Key::shortKeyID() const
{
    if (!key || !key->subkeys || !key->subkeys->keyid) {
        return nullptr;
    }
    const int len = strlen(key->subkeys->keyid);
    if (len > 8) {
        return key->subkeys->keyid + len - 8; // return the last 8 bytes (in hex notation)
    } else {
        return key->subkeys->keyid;
    }
}

const char *Key::primaryFingerprint() const
{
    if (!key) {
        return nullptr;
    }
    if (key->fpr) {
        /* Return what gpgme thinks is the primary fingerprint */
        return key->fpr;
    }
    if (key->subkeys) {
        /* Return the first subkeys fingerprint */
        return key->subkeys->fpr;
    }
    return nullptr;
}

unsigned int Key::keyListMode() const
{
    return key ? convert_from_gpgme_keylist_mode_t(key->keylist_mode) : 0;
}

const Key &Key::mergeWith(const Key &other)
{
    // ### incomplete. Just merges has* and can*, nothing else atm
    // ### detach also missing

    if (!this->primaryFingerprint() ||
            !other.primaryFingerprint() ||
            strcasecmp(this->primaryFingerprint(), other.primaryFingerprint()) != 0) {
        return *this; // only merge the Key object which describe the same key
    }

    const gpgme_key_t me = impl();
    const gpgme_key_t him = other.impl();

    if (!me || !him) {
        return *this;
    }

    me->revoked          |= him->revoked;
    me->expired          |= him->expired;
    me->disabled         |= him->disabled;
    me->invalid          |= him->invalid;
    me->can_encrypt      |= him->can_encrypt;
    me->can_sign         |= him->can_sign;
    me->can_certify      |= him->can_certify;
    me->secret           |= him->secret;
    me->can_authenticate |= him->can_authenticate;
    me->is_qualified     |= him->is_qualified;
    me->keylist_mode     |= him->keylist_mode;

    // make sure the gpgme_sub_key_t::is_cardkey flag isn't lost:
    for (gpgme_sub_key_t mysk = me->subkeys ; mysk ; mysk = mysk->next) {
        for (gpgme_sub_key_t hissk = him->subkeys ; hissk ; hissk = hissk->next) {
            if (strcmp(mysk->fpr, hissk->fpr) == 0) {
                mysk->is_cardkey |= hissk->is_cardkey;
                mysk->secret |= hissk->secret;
                if (hissk->keygrip && !mysk->keygrip) {
                    mysk->keygrip = strdup(hissk->keygrip);
                }
                break;
            }
        }
    }

    return *this;
}

void Key::update()
{
    if (isNull() || !primaryFingerprint()) {
        return;
    }
    auto ctx = Context::createForProtocol(protocol());
    if (!ctx) {
        return;
    }
    ctx->setKeyListMode(KeyListMode::Local |
                        KeyListMode::Signatures |
                        KeyListMode::SignatureNotations |
                        KeyListMode::Validate |
                        KeyListMode::WithTofu |
                        KeyListMode::WithKeygrip |
                        KeyListMode::WithSecret);
    Error err;
    Key newKey;
    if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < "2.1.0") {
        newKey = ctx->key(primaryFingerprint(), err, true);
        // Not secret so we get the information from the pubring.
        if (newKey.isNull()) {
            newKey = ctx->key(primaryFingerprint(), err, false);
        }
    } else {
        newKey = ctx->key(primaryFingerprint(), err, false);
    }
    delete ctx;
    if (err) {
        return;
    }
    swap(newKey);
}

// static
Key Key::locate(const char *mbox)
{
    if (!mbox) {
        return Key();
    }

    auto ctx = Context::createForProtocol(OpenPGP);
    if (!ctx) {
        return Key();
    }

    ctx->setKeyListMode (Extern | Local);

    Error e = ctx->startKeyListing (mbox);
    auto ret = ctx->nextKey (e);
    delete ctx;

    return ret;
}

//
//
// class Subkey
//
//

static gpgme_sub_key_t find_subkey(const shared_gpgme_key_t &key, unsigned int idx)
{
    if (key) {
        for (gpgme_sub_key_t s = key->subkeys ; s ; s = s->next, --idx) {
            if (idx == 0) {
                return s;
            }
        }
    }
    return nullptr;
}

static gpgme_sub_key_t verify_subkey(const shared_gpgme_key_t &key, gpgme_sub_key_t subkey)
{
    if (key) {
        for (gpgme_sub_key_t s = key->subkeys ; s ; s = s->next) {
            if (s == subkey) {
                return subkey;
            }
        }
    }
    return nullptr;
}

Subkey::Subkey() : key(), subkey(nullptr) {}

Subkey::Subkey(const shared_gpgme_key_t &k, unsigned int idx)
    : key(k), subkey(find_subkey(k, idx))
{

}

Subkey::Subkey(const shared_gpgme_key_t &k, gpgme_sub_key_t sk)
    : key(k), subkey(verify_subkey(k, sk))
{

}

Key Subkey::parent() const
{
    return Key(key);
}

const char *Subkey::keyID() const
{
    return subkey ? subkey->keyid : nullptr ;
}

const char *Subkey::fingerprint() const
{
    return subkey ? subkey->fpr : nullptr ;
}

Subkey::PubkeyAlgo Subkey::publicKeyAlgorithm() const
{
    return subkey ? static_cast<PubkeyAlgo>(subkey->pubkey_algo) : AlgoUnknown;
}

const char *Subkey::publicKeyAlgorithmAsString() const
{
    return gpgme_pubkey_algo_name(subkey ? subkey->pubkey_algo : (gpgme_pubkey_algo_t)0);
}

/* static */
const char *Subkey::publicKeyAlgorithmAsString(PubkeyAlgo algo)
{
    if (algo == AlgoUnknown) {
        return NULL;
    }
    return gpgme_pubkey_algo_name(static_cast<gpgme_pubkey_algo_t>(algo));
}

std::string Subkey::algoName() const
{
    char *gpgmeStr;
    if (subkey && (gpgmeStr = gpgme_pubkey_algo_string(subkey))) {
        std::string ret = std::string(gpgmeStr);
        gpgme_free(gpgmeStr);
        return ret;
    }
    return std::string();
}

bool Subkey::canEncrypt() const
{
    return subkey && subkey->can_encrypt;
}

bool Subkey::canSign() const
{
    return subkey && subkey->can_sign;
}

bool Subkey::canCertify() const
{
    return subkey && subkey->can_certify;
}

bool Subkey::canAuthenticate() const
{
    return subkey && subkey->can_authenticate;
}

bool Subkey::canRenc() const
{
    return subkey && subkey->can_renc;
}

bool Subkey::canTimestamp() const
{
    return subkey && subkey->can_timestamp;
}

bool Subkey::isGroupOwned() const
{
    return subkey && subkey->is_group_owned;
}

bool Subkey::isQualified() const
{
    return subkey && subkey->is_qualified;
}

bool Subkey::isDeVs() const
{
    return subkey && subkey->is_de_vs;
}

bool Subkey::isBetaCompliance() const
{
    return subkey && subkey->beta_compliance;
}

bool Subkey::isCardKey() const
{
    return subkey && subkey->is_cardkey;
}

const char *Subkey::cardSerialNumber() const
{
    return subkey ? subkey->card_number : nullptr;
}

const char *Subkey::keyGrip() const
{
    return subkey ? subkey->keygrip : nullptr;
}

bool Subkey::isSecret() const
{
    return subkey && subkey->secret;
}

unsigned int Subkey::length() const
{
    return subkey ? subkey->length : 0 ;
}

time_t Subkey::creationTime() const
{
    return static_cast<time_t>(subkey ? subkey->timestamp : 0);
}

time_t Subkey::expirationTime() const
{
    return static_cast<time_t>(subkey ? subkey->expires : 0);
}

bool Subkey::neverExpires() const
{
    return expirationTime() == time_t(0);
}

bool Subkey::isRevoked() const
{
    return subkey && subkey->revoked;
}

bool Subkey::isInvalid() const
{
    return subkey && subkey->invalid;
}

bool Subkey::isExpired() const
{
    return subkey && subkey->expired;
}

bool Subkey::isDisabled() const
{
    return subkey && subkey->disabled;
}

//
//
// class UserID
//
//

static gpgme_user_id_t find_uid(const shared_gpgme_key_t &key, unsigned int idx)
{
    if (key) {
        for (gpgme_user_id_t u = key->uids ; u ; u = u->next, --idx) {
            if (idx == 0) {
                return u;
            }
        }
    }
    return nullptr;
}

static gpgme_user_id_t verify_uid(const shared_gpgme_key_t &key, gpgme_user_id_t uid)
{
    if (key) {
        for (gpgme_user_id_t u = key->uids ; u ; u = u->next) {
            if (u == uid) {
                return uid;
            }
        }
    }
    return nullptr;
}

UserID::UserID() : key(), uid(nullptr) {}

UserID::UserID(const shared_gpgme_key_t &k, gpgme_user_id_t u)
    : key(k), uid(verify_uid(k, u))
{

}

UserID::UserID(const shared_gpgme_key_t &k, unsigned int idx)
    : key(k), uid(find_uid(k, idx))
{

}

Key UserID::parent() const
{
    return Key(key);
}

UserID::Signature UserID::signature(unsigned int index) const
{
    return Signature(key, uid, index);
}

unsigned int UserID::numSignatures() const
{
    if (!uid) {
        return 0;
    }
    unsigned int count = 0;
    for (gpgme_key_sig_t sig = uid->signatures ; sig ; sig = sig->next) {
        ++count;
    }
    return count;
}

std::vector<UserID::Signature> UserID::signatures() const
{
    if (!uid) {
        return std::vector<Signature>();
    }

    std::vector<Signature> v;
    v.reserve(numSignatures());
    for (gpgme_key_sig_t sig = uid->signatures ; sig ; sig = sig->next) {
        v.push_back(Signature(key, uid, sig));
    }
    return v;
}

const char *UserID::id() const
{
    return uid ? uid->uid : nullptr ;
}

const char *UserID::name() const
{
    return uid ? uid->name : nullptr ;
}

const char *UserID::email() const
{
    return uid ? uid->email : nullptr ;
}

const char *UserID::comment() const
{
    return uid ? uid->comment : nullptr ;
}

const char *UserID::uidhash() const
{
    return uid ? uid->uidhash : nullptr ;
}

UserID::Validity UserID::validity() const
{
    if (!uid) {
        return Unknown;
    }
    switch (uid->validity) {
    default:
    case GPGME_VALIDITY_UNKNOWN:   return Unknown;
    case GPGME_VALIDITY_UNDEFINED: return Undefined;
    case GPGME_VALIDITY_NEVER:     return Never;
    case GPGME_VALIDITY_MARGINAL:  return Marginal;
    case GPGME_VALIDITY_FULL:      return Full;
    case GPGME_VALIDITY_ULTIMATE:  return Ultimate;
    }
}

char UserID::validityAsString() const
{
    if (!uid) {
        return '?';
    }
    switch (uid->validity) {
    default:
    case GPGME_VALIDITY_UNKNOWN:   return '?';
    case GPGME_VALIDITY_UNDEFINED: return 'q';
    case GPGME_VALIDITY_NEVER:     return 'n';
    case GPGME_VALIDITY_MARGINAL:  return 'm';
    case GPGME_VALIDITY_FULL:      return 'f';
    case GPGME_VALIDITY_ULTIMATE:  return 'u';
    }
}

bool UserID::isRevoked() const
{
    return uid && uid->revoked;
}

bool UserID::isInvalid() const
{
    return uid && uid->invalid;
}

TofuInfo UserID::tofuInfo() const
{
    if (!uid) {
        return TofuInfo();
    }
    return TofuInfo(uid->tofu);
}

static gpgme_key_sig_t find_last_valid_sig_for_keyid (gpgme_user_id_t uid,
                                                      const char *keyid)
{
    if (!keyid) {
        return nullptr;
    }
    gpgme_key_sig_t ret = NULL;
    for (gpgme_key_sig_t s = uid->signatures ; s ; s = s->next) {
        if (s->keyid && !strcmp(keyid, s->keyid)) {
            if (!s->expired && !s->revoked && !s->invalid && !s->status) {
                if (!ret) {
                    ret = s;
                } else if (ret && ret->timestamp <= s->timestamp) {
                    /* Equals because when the timestamps are the same we prefer
                       the last in the list */
                    ret = s;
                }
            }
        }
    }
    return ret;
}

const char *UserID::remark(const Key &remarker, Error &err) const
{
    if (!uid || remarker.isNull()) {
        err = Error::fromCode(GPG_ERR_GENERAL);
        return nullptr;
    }

    if (key->protocol != GPGME_PROTOCOL_OpenPGP) {
        return nullptr;
    }

    if (!(key->keylist_mode & GPGME_KEYLIST_MODE_SIG_NOTATIONS) ||
        !(key->keylist_mode & GPGME_KEYLIST_MODE_SIGS)) {
        err = Error::fromCode(GPG_ERR_NO_DATA);
        return nullptr;
    }

    gpgme_key_sig_t s = find_last_valid_sig_for_keyid(uid, remarker.keyID());

    if (!s) {
        return nullptr;
    }

    for (gpgme_sig_notation_t n = s->notations; n ; n = n->next) {
        if (n->name && !strcmp(n->name, "rem@gnupg.org")) {
            return n->value;
        }
    }
    return nullptr;
}

std::vector<std::string> UserID::remarks(std::vector<Key> keys, Error &err) const
{
    std::vector<std::string> ret;

    for (const auto &key: keys) {
        const char *rem = remark(key, err);
        if (err) {
            return ret;
        }
        if (rem) {
            ret.push_back(rem);
        }
    }
    return ret;
}

//
//
// class Signature
//
//

static gpgme_key_sig_t find_signature(gpgme_user_id_t uid, unsigned int idx)
{
    if (uid) {
        for (gpgme_key_sig_t s = uid->signatures ; s ; s = s->next, --idx) {
            if (idx == 0) {
                return s;
            }
        }
    }
    return nullptr;
}

static gpgme_key_sig_t verify_signature(gpgme_user_id_t uid, gpgme_key_sig_t sig)
{
    if (uid) {
        for (gpgme_key_sig_t s = uid->signatures ; s ; s = s->next) {
            if (s == sig) {
                return sig;
            }
        }
    }
    return nullptr;
}

static int signature_index(gpgme_user_id_t uid, gpgme_key_sig_t sig)
{
    if (uid) {
        int i = 0;
        for (gpgme_key_sig_t s = uid->signatures ; s ; s = s->next, ++i) {
            if (s == sig) {
                return i;
            }
        }
    }
    return -1;
}

UserID::Signature::Signature() : key(), uid(nullptr), sig(nullptr) {}

UserID::Signature::Signature(const shared_gpgme_key_t &k, gpgme_user_id_t u, unsigned int idx)
    : key(k), uid(verify_uid(k, u)), sig(find_signature(uid, idx))
{
}

UserID::Signature::Signature(const shared_gpgme_key_t &k, gpgme_user_id_t u, gpgme_key_sig_t s)
    : key(k), uid(verify_uid(k, u)), sig(verify_signature(uid, s))
{
}

bool UserID::Signature::operator<(const Signature &other)
{
    // kept for binary compatibility
    return static_cast<const UserID::Signature *>(this)->operator<(other);
}

bool UserID::Signature::operator<(const Signature &other) const
{
    // based on cmp_signodes() in g10/keylist.c

    // both signatures must belong to the same user ID
    assert(uid == other.uid);

    // self-signatures are ordered first
    const char *primaryKeyId = parent().parent().keyID();
    const bool thisIsSelfSignature = strcmp(signerKeyID(), primaryKeyId) == 0;
    const bool otherIsSelfSignature = strcmp(other.signerKeyID(), primaryKeyId) == 0;
    if (thisIsSelfSignature && !otherIsSelfSignature) {
        return true;
    }
    if (otherIsSelfSignature && !thisIsSelfSignature) {
        return false;
    }

    // then sort by signer key ID (which are or course the same for self-sigs)
    const int keyIdComparison = strcmp(signerKeyID(), other.signerKeyID());
    if (keyIdComparison < 0) {
        return true;
    }
    if (keyIdComparison > 0) {
        return false;
    }

    // followed by creation time
    if (creationTime() < other.creationTime()) {
        return true;
    }
    if (creationTime() > other.creationTime()) {
        return false;
    }

    // followed by the class in a way that a rev comes first
    if (certClass() < other.certClass()) {
        return true;
    }
    if (certClass() > other.certClass()) {
        return false;
    }

    // to make the sort stable we compare the indexes of the signatures as last resort
    return signature_index(uid, sig) < signature_index(uid, other.sig);
}

UserID UserID::Signature::parent() const
{
    return UserID(key, uid);
}

const char *UserID::Signature::signerKeyID() const
{
    return sig ? sig->keyid : nullptr ;
}

const char *UserID::Signature::algorithmAsString() const
{
    return gpgme_pubkey_algo_name(sig ? sig->pubkey_algo : (gpgme_pubkey_algo_t)0);
}

unsigned int UserID::Signature::algorithm() const
{
    return sig ? sig->pubkey_algo : 0 ;
}

time_t UserID::Signature::creationTime() const
{
    return static_cast<time_t>(sig ? sig->timestamp : 0);
}

time_t UserID::Signature::expirationTime() const
{
    return static_cast<time_t>(sig ? sig->expires : 0);
}

bool UserID::Signature::neverExpires() const
{
    return expirationTime() == time_t(0);
}

bool UserID::Signature::isRevokation() const
{
    return sig && sig->revoked;
}

bool UserID::Signature::isInvalid() const
{
    return sig && sig->invalid;
}

bool UserID::Signature::isExpired() const
{
    return sig && sig->expired;
}

bool UserID::Signature::isExportable() const
{
    return sig && sig->exportable;
}

const char *UserID::Signature::signerUserID() const
{
    return sig ? sig->uid : nullptr ;
}

const char *UserID::Signature::signerName() const
{
    return sig ? sig->name : nullptr ;
}

const char *UserID::Signature::signerEmail() const
{
    return sig ? sig->email : nullptr ;
}

const char *UserID::Signature::signerComment() const
{
    return sig ? sig->comment : nullptr ;
}

unsigned int UserID::Signature::certClass() const
{
    return sig ? sig->sig_class : 0 ;
}

UserID::Signature::Status UserID::Signature::status() const
{
    if (!sig) {
        return GeneralError;
    }

    switch (gpgme_err_code(sig->status)) {
    case GPG_ERR_NO_ERROR:      return NoError;
    case GPG_ERR_SIG_EXPIRED:   return SigExpired;
    case GPG_ERR_KEY_EXPIRED:   return KeyExpired;
    case GPG_ERR_BAD_SIGNATURE: return BadSignature;
    case GPG_ERR_NO_PUBKEY:     return NoPublicKey;
    default:
    case GPG_ERR_GENERAL:       return GeneralError;
    }
}

std::string UserID::Signature::statusAsString() const
{
    if (!sig) {
        return std::string();
    }
    char buf[ 1024 ];
    gpgme_strerror_r(sig->status, buf, sizeof buf);
    buf[ sizeof buf - 1 ] = '\0';
    return std::string(buf);
}

GpgME::Notation UserID::Signature::notation(unsigned int idx) const
{
    if (!sig) {
        return GpgME::Notation();
    }
    for (gpgme_sig_notation_t nota = sig->notations ; nota ; nota = nota->next) {
        if (nota->name) {
            if (idx-- == 0) {
                return GpgME::Notation(nota);
            }
        }
    }
    return GpgME::Notation();
}

unsigned int UserID::Signature::numNotations() const
{
    if (!sig) {
        return 0;
    }
    unsigned int count = 0;
    for (gpgme_sig_notation_t nota = sig->notations ; nota ; nota = nota->next) {
        if (nota->name) {
            ++count; // others are policy URLs...
        }
    }
    return count;
}

std::vector<Notation> UserID::Signature::notations() const
{
    if (!sig) {
        return std::vector<GpgME::Notation>();
    }
    std::vector<GpgME::Notation> v;
    v.reserve(numNotations());
    for (gpgme_sig_notation_t nota = sig->notations ; nota ; nota = nota->next) {
        if (nota->name) {
            v.push_back(GpgME::Notation(nota));
        }
    }
    return v;
}

const char *UserID::Signature::policyURL() const
{
    if (!sig) {
        return nullptr;
    }
    for (gpgme_sig_notation_t nota = sig->notations ; nota ; nota = nota->next) {
        if (!nota->name) {
            return nota->value;
        }
    }
    return nullptr;
}

bool UserID::Signature::isTrustSignature() const
{
    return sig && sig->trust_depth > 0;
}

TrustSignatureTrust UserID::Signature::trustValue() const
{
    if (!sig || !isTrustSignature()) {
        return TrustSignatureTrust::None;
    }
    return sig->trust_value >= 120 ? TrustSignatureTrust::Complete : TrustSignatureTrust::Partial;
}

unsigned int UserID::Signature::trustDepth() const
{
    return sig ? sig->trust_depth : 0;
}

const char *UserID::Signature::trustScope() const
{
    return sig ? sig->trust_scope : nullptr;
}

std::string UserID::addrSpecFromString(const char *userid)
{
    if (!userid) {
        return std::string();
    }
    char *normalized = gpgme_addrspec_from_uid (userid);
    if (normalized) {
        std::string ret(normalized);
        gpgme_free(normalized);
        return ret;
    }
    return std::string();
}

std::string UserID::addrSpec() const
{
    if (!uid || !uid->address) {
        return std::string();
    }

    return uid->address;
}

Error UserID::revoke()
{
    if (isNull()) {
        return Error::fromCode(GPG_ERR_GENERAL);
    }
    auto ctx = Context::createForProtocol(parent().protocol());
    if (!ctx) {
        return Error::fromCode(GPG_ERR_INV_ENGINE);
    }
    Error ret = ctx->revUid(key, id());
    delete ctx;
    return ret;
}

static Key::Origin gpgme_origin_to_pp_origin (const unsigned int origin)
{
    switch (origin) {
        case GPGME_KEYORG_KS:
            return Key::OriginKS;
        case GPGME_KEYORG_DANE:
            return Key::OriginDane;
        case GPGME_KEYORG_WKD:
            return Key::OriginWKD;
        case GPGME_KEYORG_URL:
            return Key::OriginURL;
        case GPGME_KEYORG_FILE:
            return Key::OriginFile;
        case GPGME_KEYORG_SELF:
            return Key::OriginSelf;
        case GPGME_KEYORG_OTHER:
            return Key::OriginOther;
        case GPGME_KEYORG_UNKNOWN:
        default:
            return Key::OriginUnknown;
    }
}

Key::Origin UserID::origin() const
{
    if (isNull()) {
        return Key::OriginUnknown;
    }
    return gpgme_origin_to_pp_origin(uid->origin);
}

time_t UserID::lastUpdate() const
{
    return static_cast<time_t>(uid ? uid->last_update : 0);
}

Error Key::addUid(const char *uid)
{
    if (isNull()) {
        return Error::fromCode(GPG_ERR_GENERAL);
    }
    auto ctx = Context::createForProtocol(protocol());
    if (!ctx) {
        return Error::fromCode(GPG_ERR_INV_ENGINE);
    }
    Error ret = ctx->addUid(key, uid);
    delete ctx;
    return ret;
}

Key::Origin Key::origin() const
{
    if (isNull()) {
        return OriginUnknown;
    }
    return gpgme_origin_to_pp_origin(key->origin);
}

time_t Key::lastUpdate() const
{
    return static_cast<time_t>(key ? key->last_update : 0);
}

bool Key::isBad() const
{
    return isNull() || isRevoked() || isExpired() || isDisabled() || isInvalid();
}

bool Subkey::isBad() const
{
    return isNull() || isRevoked() || isExpired() || isDisabled() || isInvalid();
}

bool UserID::isBad() const
{
    return isNull() || isRevoked() || isInvalid();
}

bool UserID::Signature::isBad() const
{
    return isNull() || isExpired() || isInvalid();
}

//
//
// class RevocationKey
//
//

static gpgme_revocation_key_t find_revkey(const shared_gpgme_key_t &key, unsigned int idx)
{
    if (key) {
        for (gpgme_revocation_key_t s = key->revocation_keys; s; s = s->next, --idx) {
            if (idx == 0) {
                return s;
            }
        }
    }
    return nullptr;
}

static gpgme_revocation_key_t verify_revkey(const shared_gpgme_key_t &key, gpgme_revocation_key_t revkey)
{
    if (key) {
        for (gpgme_revocation_key_t s = key->revocation_keys; s; s = s->next) {
            if (s == revkey) {
                return revkey;
            }
        }
    }
    return nullptr;
}

RevocationKey::RevocationKey() : key(), revkey(nullptr) {}

RevocationKey::RevocationKey(const shared_gpgme_key_t &k, unsigned int idx)
    : key(k), revkey(find_revkey(k, idx))
{
}

RevocationKey::RevocationKey(const shared_gpgme_key_t &k, gpgme_revocation_key_t sk)
    : key(k), revkey(verify_revkey(k, sk))
{
}

Key RevocationKey::parent() const
{
    return Key(key);
}

const char *RevocationKey::fingerprint() const
{
    return revkey ? revkey->fpr : nullptr;
}

bool RevocationKey::isSensitive() const
{
    return revkey ? revkey->sensitive : false;
}

int RevocationKey::algorithm() const
{
    return revkey ? revkey->pubkey_algo : 0;
}

std::ostream &operator<<(std::ostream &os, const UserID &uid)
{
    os << "GpgME::UserID(";
    if (!uid.isNull()) {
        os << "\n name:      " << protect(uid.name())
           << "\n email:     " << protect(uid.email())
           << "\n mbox:      " << uid.addrSpec()
           << "\n comment:   " << protect(uid.comment())
           << "\n validity:  " << uid.validityAsString()
           << "\n revoked:   " << uid.isRevoked()
           << "\n invalid:   " << uid.isInvalid()
           << "\n numsigs:   " << uid.numSignatures()
           << "\n origin:    " << uid.origin()
           << "\n updated:   " << uid.lastUpdate()
           << "\n tofuinfo:\n" << uid.tofuInfo();
    }
    return os << ')';
}

std::ostream &operator<<(std::ostream &os, const Subkey &subkey)
{
    os << "GpgME::Subkey(";
    if (!subkey.isNull()) {
        os << "\n fingerprint:   " << protect(subkey.fingerprint())
           << "\n keyGrip:       " << protect(subkey.keyGrip())
           << "\n creationTime:  " << subkey.creationTime()
           << "\n expirationTime:" << subkey.expirationTime()
           << "\n isRevoked:     " << subkey.isRevoked()
           << "\n isExpired:     " << subkey.isExpired()
           << "\n isInvalid:     " << subkey.isInvalid()
           << "\n isDisabled:    " << subkey.isDisabled()
           << "\n canSign:       " << subkey.canSign()
           << "\n canEncrypt:    " << subkey.canEncrypt()
           << "\n canCertify:    " << subkey.canCertify()
           << "\n canAuth:       " << subkey.canAuthenticate()
           << "\n canRenc:       " << subkey.canRenc()
           << "\n canTimestanp:  " << subkey.canTimestamp()
           << "\n isSecret:      " << subkey.isSecret()
           << "\n isGroupOwned:  " << subkey.isGroupOwned()
           << "\n isQualified:   " << subkey.isQualified()
           << "\n isDeVs:        " << subkey.isDeVs()
           << "\n isBetaCompliance:" << subkey.isBetaCompliance()
           << "\n isCardKey:     " << subkey.isCardKey()
           << "\n cardSerialNumber:" << protect(subkey.cardSerialNumber());
    }
    return os << ')';
}

std::ostream &operator<<(std::ostream &os, const Key &key)
{
    os << "GpgME::Key(";
    if (!key.isNull()) {
        os << "\n protocol:   " << protect(key.protocolAsString())
           << "\n ownertrust: " << key.ownerTrustAsString()
           << "\n issuer:     " << protect(key.issuerName())
           << "\n fingerprint:" << protect(key.primaryFingerprint())
           << "\n listmode:   " << key.keyListMode()
           << "\n canSign:    " << key.canSign()
           << "\n canEncrypt: " << key.canEncrypt()
           << "\n canCertify: " << key.canCertify()
           << "\n canAuth:    " << key.canAuthenticate()
           << "\n origin:     " << key.origin()
           << "\n updated:    " << key.lastUpdate()
           << "\n uids:\n";
        const std::vector<UserID> uids = key.userIDs();
        std::copy(uids.begin(), uids.end(),
                  std::ostream_iterator<UserID>(os, "\n"));
        const std::vector<Subkey> subkeys = key.subkeys();
        std::copy(subkeys.begin(), subkeys.end(),
                  std::ostream_iterator<Subkey>(os, "\n"));
        os << " revocationKeys:\n";
        const std::vector<RevocationKey> revkeys = key.revocationKeys();
        std::copy(revkeys.begin(), revkeys.end(),
                  std::ostream_iterator<RevocationKey>(os, "\n"));
    }
    return os << ')';
}

std::ostream &operator<<(std::ostream &os, const RevocationKey &revkey)
{
    os << "GpgME::RevocationKey(";
    if (!revkey.isNull()) {
        os << "\n fingerprint: " << protect(revkey.fingerprint())
           << "\n isSensitive: " << revkey.isSensitive();
    }
    return os << ')';
}

} // namespace GpgME
