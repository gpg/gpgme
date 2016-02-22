/*
  key.h - wraps a gpgme key
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

// -*- c++ -*-
#ifndef __GPGMEPP_KEY_H__
#define __GPGMEPP_KEY_H__

#include "global.h"
#include "notation.h"

#include "gpgmefw.h"

#include <boost/shared_ptr.hpp>
#include <boost/type_traits/remove_pointer.hpp>

#include <sys/time.h>

#include <vector>
#include <algorithm>
#include <string>

namespace GpgME
{

class Context;

class Subkey;
class UserID;

typedef boost::shared_ptr< boost::remove_pointer<gpgme_key_t>::type > shared_gpgme_key_t;

//
// class Key
//

class GPGMEPP_EXPORT Key
{
    friend class ::GpgME::Context;
    struct Null {
		Null() {}
	};
public:
    Key();
    /* implicit */ Key(const Null &);
    Key(const shared_gpgme_key_t &key);
    Key(gpgme_key_t key, bool acquireRef);

    static const Null null;

    const Key &operator=(Key other)
    {
        swap(other);
        return *this;
    }

    const Key &mergeWith(const Key &other);

    void swap(Key &other)
    {
        using std::swap;
        swap(this->key, other.key);
    }

    bool isNull() const
    {
        return !key;
    }

    UserID userID(unsigned int index) const;
    Subkey subkey(unsigned int index) const;

    unsigned int numUserIDs() const;
    unsigned int numSubkeys() const;

    std::vector<UserID> userIDs() const;
    std::vector<Subkey> subkeys() const;

    bool isRevoked() const;
    bool isExpired() const;
    bool isDisabled() const;
    bool isInvalid() const;

    bool canEncrypt() const;
    /*!
      This function contains a workaround for old gpgme's: all secret
      OpenPGP keys canSign() == true, which canReallySign() doesn't
      have. I don't have time to find what breaks when I remove this
      workaround, but since Kleopatra merges secret into public keys,
      the workaround is not necessary there (and actively harms), I've
      added a new function instead.
     */
    bool canSign() const;
    bool canReallySign() const;
    bool canCertify() const;
    bool canAuthenticate() const;
    bool isQualified() const;

    bool hasSecret() const;
    GPGMEPP_DEPRECATED bool isSecret() const
    {
        return hasSecret();
    }

    /*!
      @return true if this is a X.509 root certificate (currently
      equivalent to something like
      strcmp( chainID(), subkey(0).fingerprint() ) == 0 )
    */
    bool isRoot() const;

    enum OwnerTrust { Unknown = 0, Undefined = 1, Never = 2,
                      Marginal = 3, Full = 4, Ultimate = 5
                    };

    OwnerTrust ownerTrust() const;
    char ownerTrustAsString() const;

    Protocol protocol() const;
    const char *protocolAsString() const;

    const char *issuerSerial() const;
    const char *issuerName() const;
    const char *chainID() const;

    const char *keyID() const;
    const char *shortKeyID() const;
    const char *primaryFingerprint() const;

    unsigned int keyListMode() const;

private:
    gpgme_key_t impl() const
    {
        return key.get();
    }
    shared_gpgme_key_t key;
};

//
// class Subkey
//

class GPGMEPP_EXPORT Subkey
{
public:
    Subkey();
    Subkey(const shared_gpgme_key_t &key, gpgme_sub_key_t subkey);
    Subkey(const shared_gpgme_key_t &key, unsigned int idx);

    const Subkey &operator=(Subkey other)
    {
        swap(other);
        return *this;
    }

    void swap(Subkey &other)
    {
        using std::swap;
        swap(this->key, other.key);
        swap(this->subkey, other.subkey);
    }

    bool isNull() const
    {
        return !key || !subkey;
    }

    Key parent() const;

    const char *keyID() const;
    const char *fingerprint() const;

    time_t creationTime() const;
    time_t expirationTime() const;
    bool neverExpires() const;

    bool isRevoked() const;
    bool isExpired() const;
    bool isInvalid() const;
    bool isDisabled() const;

    bool canEncrypt() const;
    bool canSign() const;
    bool canCertify() const;
    bool canAuthenticate() const;
    bool isQualified() const;
    bool isCardKey() const;

    bool isSecret() const;

    unsigned int publicKeyAlgorithm() const;
    const char *publicKeyAlgorithmAsString() const;

    unsigned int length() const;

    const char *cardSerialNumber() const;

private:
    shared_gpgme_key_t key;
    gpgme_sub_key_t subkey;
};

//
// class UserID
//

class GPGMEPP_EXPORT UserID
{
public:
    class Signature;

    UserID();
    UserID(const shared_gpgme_key_t &key, gpgme_user_id_t uid);
    UserID(const shared_gpgme_key_t &key, unsigned int idx);

    const UserID &operator=(UserID other)
    {
        swap(other);
        return *this;
    }

    void swap(UserID &other)
    {
        using std::swap;
        swap(this->key, other.key);
        swap(this->uid, other.uid);
    }

    bool isNull() const
    {
        return !key || !uid;
    }

    Key parent() const;

    unsigned int numSignatures() const;
    Signature signature(unsigned int index) const;
    std::vector<Signature> signatures() const;

    const char *id() const;
    const char *name() const;
    const char *email() const;
    const char *comment() const;

    enum Validity { Unknown = 0, Undefined = 1, Never = 2,
                    Marginal = 3, Full = 4, Ultimate = 5
                  };

    Validity validity() const;
    char validityAsString() const;

    bool isRevoked() const;
    bool isInvalid() const;

private:
    shared_gpgme_key_t key;
    gpgme_user_id_t uid;
};

//
// class UserID::Signature
//

class GPGMEPP_EXPORT UserID::Signature
{
public:
    typedef GPGMEPP_DEPRECATED GpgME::Notation Notation;

    Signature();
    Signature(const shared_gpgme_key_t &key, gpgme_user_id_t uid, gpgme_key_sig_t sig);
    Signature(const shared_gpgme_key_t &key, gpgme_user_id_t uid, unsigned int idx);

    const Signature &operator=(Signature other)
    {
        swap(other);
        return *this;
    }

    void swap(Signature &other)
    {
        using std::swap;
        swap(this->key, other.key);
        swap(this->uid, other.uid);
        swap(this->sig, other.sig);
    }

    bool isNull() const
    {
        return !sig || !uid || !key ;
    }

    UserID parent() const;

    const char *signerKeyID() const;

    const char *algorithmAsString() const;
    unsigned int algorithm() const;
    time_t creationTime() const;
    time_t expirationTime() const;
    bool neverExpires() const;

    bool isRevokation() const;
    bool isInvalid() const;
    bool isExpired() const;
    bool isExportable() const;

    const char *signerUserID() const;
    const char *signerName() const;
    const char *signerEmail() const;
    const char *signerComment() const;

    unsigned int certClass() const;

    enum Status { NoError = 0, SigExpired, KeyExpired,
                  BadSignature, NoPublicKey, GeneralError
                };
    Status status() const;
    std::string statusAsString() const;

    const char *policyURL() const;

    unsigned int numNotations() const;
    GpgME::Notation notation(unsigned int idx) const;
    std::vector<GpgME::Notation> notations() const;

private:
    shared_gpgme_key_t key;
    gpgme_user_id_t uid;
    gpgme_key_sig_t sig;
};

} // namespace GpgME

GPGMEPP_MAKE_STD_SWAP_SPECIALIZATION(Key)
GPGMEPP_MAKE_STD_SWAP_SPECIALIZATION(Subkey)
GPGMEPP_MAKE_STD_SWAP_SPECIALIZATION(UserID)
GPGMEPP_MAKE_STD_SWAP_SPECIALIZATION(UserID::Signature)

#endif // __GPGMEPP_KEY_H__
