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

#include "config-gpgme++.h"

#include <key.h>

#include "util.h"

#include <gpgme.h>

#include <string.h>

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
    return key ? gpgme_get_protocol_name(key->protocol) : 0 ;
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
#ifndef GPGME_CAN_SIGN_ON_SECRET_OPENPGP_KEYLISTING_NOT_BROKEN
    if (key && key->protocol == GPGME_PROTOCOL_OpenPGP) {
        return true;
    }
#endif
    return canReallySign();
}

bool Key::canReallySign() const
{
    return key && key->can_sign;
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
#ifdef HAVE_GPGME_KEY_T_IS_QUALIFIED
    return key && key->is_qualified;
#else
    return false;
#endif
}

const char *Key::issuerSerial() const
{
    return key ? key->issuer_serial : 0 ;
}
const char *Key::issuerName() const
{
    return key ? key->issuer_name : 0 ;
}
const char *Key::chainID() const
{
    return key ? key->chain_id : 0 ;
}

const char *Key::keyID() const
{
    return key && key->subkeys ? key->subkeys->keyid : 0 ;
}

const char *Key::shortKeyID() const
{
    if (!key || !key->subkeys || !key->subkeys->keyid) {
        return 0;
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
    const char *fpr = key && key->subkeys ? key->subkeys->fpr : 0 ;
    if (fpr) {
        return fpr;
    } else {
        return keyID();
    }
}

unsigned int Key::keyListMode() const
{
    return key ? convert_from_gpgme_keylist_mode_t(key->keylist_mode) : 0 ;
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
#ifdef HAVE_GPGME_KEY_T_IS_QUALIFIED
    me->is_qualified     |= him->is_qualified;
#endif
    me->keylist_mode     |= him->keylist_mode;

#ifdef HAVE_GPGME_SUBKEY_T_IS_CARDKEY
    // make sure the gpgme_sub_key_t::is_cardkey flag isn't lost:
    for (gpgme_sub_key_t mysk = me->subkeys ; mysk ; mysk = mysk->next) {
        for (gpgme_sub_key_t hissk = him->subkeys ; hissk ; hissk = hissk->next) {
            if (strcmp(mysk->fpr, hissk->fpr) == 0) {
                mysk->is_cardkey |= hissk->is_cardkey;
                break;
            }
        }
    }
#endif

    return *this;
}

//
//
// class Subkey
//
//

gpgme_sub_key_t find_subkey(const shared_gpgme_key_t &key, unsigned int idx)
{
    if (key) {
        for (gpgme_sub_key_t s = key->subkeys ; s ; s = s->next, --idx) {
            if (idx == 0) {
                return s;
            }
        }
    }
    return 0;
}

gpgme_sub_key_t verify_subkey(const shared_gpgme_key_t &key, gpgme_sub_key_t subkey)
{
    if (key) {
        for (gpgme_sub_key_t s = key->subkeys ; s ; s = s->next) {
            if (s == subkey) {
                return subkey;
            }
        }
    }
    return 0;
}

Subkey::Subkey() : key(), subkey(0) {}

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
    return subkey ? subkey->keyid : 0 ;
}

const char *Subkey::fingerprint() const
{
    return subkey ? subkey->fpr : 0 ;
}

unsigned int Subkey::publicKeyAlgorithm() const
{
    return subkey ? subkey->pubkey_algo : 0 ;
}

const char *Subkey::publicKeyAlgorithmAsString() const
{
    return gpgme_pubkey_algo_name(subkey ? subkey->pubkey_algo : (gpgme_pubkey_algo_t)0);
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

bool Subkey::isQualified() const
{
#ifdef HAVE_GPGME_SUBKEY_T_IS_QUALIFIED
    return subkey && subkey->is_qualified;
#else
    return false;
#endif
}

bool Subkey::isCardKey() const
{
#ifdef HAVE_GPGME_SUBKEY_T_IS_CARDKEY
    return subkey && subkey->is_cardkey;
#else
    return false;
#endif
}

const char *Subkey::cardSerialNumber() const
{
#ifdef HAVE_GPGME_SUBKEY_T_IS_CARDKEY
    return subkey ? subkey->card_number : 0 ;
#else
    return 0;
#endif
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

gpgme_user_id_t find_uid(const shared_gpgme_key_t &key, unsigned int idx)
{
    if (key) {
        for (gpgme_user_id_t u = key->uids ; u ; u = u->next, --idx) {
            if (idx == 0) {
                return u;
            }
        }
    }
    return 0;
}

gpgme_user_id_t verify_uid(const shared_gpgme_key_t &key, gpgme_user_id_t uid)
{
    if (key) {
        for (gpgme_user_id_t u = key->uids ; u ; u = u->next) {
            if (u == uid) {
                return uid;
            }
        }
    }
    return 0;
}

UserID::UserID() : key(), uid(0) {}

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
    return uid ? uid->uid : 0 ;
}

const char *UserID::name() const
{
    return uid ? uid->name : 0 ;
}

const char *UserID::email() const
{
    return uid ? uid->email : 0 ;
}

const char *UserID::comment() const
{
    return uid ? uid->comment : 0 ;
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

//
//
// class Signature
//
//

gpgme_key_sig_t find_signature(gpgme_user_id_t uid, unsigned int idx)
{
    if (uid) {
        for (gpgme_key_sig_t s = uid->signatures ; s ; s = s->next, --idx) {
            if (idx == 0) {
                return s;
            }
        }
    }
    return 0;
}

gpgme_key_sig_t verify_signature(gpgme_user_id_t uid, gpgme_key_sig_t sig)
{
    if (uid) {
        for (gpgme_key_sig_t s = uid->signatures ; s ; s = s->next) {
            if (s == sig) {
                return sig;
            }
        }
    }
    return 0;
}

UserID::Signature::Signature() : key(), uid(0), sig(0) {}

UserID::Signature::Signature(const shared_gpgme_key_t &k, gpgme_user_id_t u, unsigned int idx)
    : key(k), uid(verify_uid(k, u)), sig(find_signature(uid, idx))
{

}

UserID::Signature::Signature(const shared_gpgme_key_t &k, gpgme_user_id_t u, gpgme_key_sig_t s)
    : key(k), uid(verify_uid(k, u)), sig(verify_signature(uid, s))
{

}

UserID UserID::Signature::parent() const
{
    return UserID(key, uid);
}

const char *UserID::Signature::signerKeyID() const
{
    return sig ? sig->keyid : 0 ;
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
    return sig ? sig->uid : 0 ;
}

const char *UserID::Signature::signerName() const
{
    return sig ? sig->name : 0 ;
}

const char *UserID::Signature::signerEmail() const
{
    return sig ? sig->email : 0 ;
}

const char *UserID::Signature::signerComment() const
{
    return sig ? sig->comment : 0 ;
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
#ifdef HAVE_GPGME_KEY_SIG_NOTATIONS
    for (gpgme_sig_notation_t nota = sig->notations ; nota ; nota = nota->next) {
        if (nota->name) {
            if (idx-- == 0) {
                return GpgME::Notation(nota);
            }
        }
    }
#endif
    return GpgME::Notation();
}

unsigned int UserID::Signature::numNotations() const
{
    if (!sig) {
        return 0;
    }
    unsigned int count = 0;
#ifdef HAVE_GPGME_KEY_SIG_NOTATIONS
    for (gpgme_sig_notation_t nota = sig->notations ; nota ; nota = nota->next) {
        if (nota->name) {
            ++count; // others are policy URLs...
        }
    }
#endif
    return count;
}

std::vector<Notation> UserID::Signature::notations() const
{
    if (!sig) {
        return std::vector<GpgME::Notation>();
    }
    std::vector<GpgME::Notation> v;
#ifdef HAVE_GPGME_KEY_SIG_NOTATIONS
    v.reserve(numNotations());
    for (gpgme_sig_notation_t nota = sig->notations ; nota ; nota = nota->next) {
        if (nota->name) {
            v.push_back(GpgME::Notation(nota));
        }
    }
#endif
    return v;
}

const char *UserID::Signature::policyURL() const
{
#ifdef HAVE_GPGME_KEY_SIG_NOTATIONS
    if (!sig) {
        return 0;
    }
    for (gpgme_sig_notation_t nota = sig->notations ; nota ; nota = nota->next) {
        if (!nota->name) {
            return nota->value;
        }
    }
#endif
    return 0;
}

} // namespace GpgME
