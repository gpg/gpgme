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

#include <memory>
#include <sys/time.h>

#include <vector>
#include <algorithm>
#include <string>

namespace GpgME
{

class Context;

class Subkey;
class UserID;
class TofuInfo;

typedef std::shared_ptr< std::remove_pointer<gpgme_key_t>::type > shared_gpgme_key_t;

enum class TrustSignatureTrust : char {
    None = 0,
    Partial,
    Complete,
};

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

    /*! Shorthand for isNull || isRevoked || isExpired ||
     *                          isDisabled || isInvalid */
    bool isBad() const;

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
    bool isDeVs() const;

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

    /*! Update information about this key.
     * Starts a keylisting for this key with validity
     * and tofu information gathering. Blocks for
     * how long the keylisting takes.*/
    void update();

    /**
     * @brief Add a user id to this key.
     *
     * Needs gnupg 2.1.13 and the key needs to be updated
     * afterwards to see the new uid.
     *
     * @param uid should be fully formatted and UTF-8 encoded.
     *
     * @returns a possible error.
     **/
    Error addUid(const char *uid);

    /**
     * @brief try to locate the best pgp key for a given mailbox.
     *
     * Boils down to gpg --locate-key <mbox>
     * This may take some time if remote sources are also
     * used.
     *
     * @param mbox should be a mail address does not need to be normalized.
     *
     * @returns The best key for a mailbox or a null key.
     */
    static Key locate(const char *mbox);

    /* @enum Origin
     * @brief The Origin of the key. */
    enum Origin : unsigned int {
        OriginUnknown = 0,
        OriginKS = 1,
        OriginDane = 3,
        OriginWKD = 4,
        OriginURL = 5,
        OriginFile = 6,
        OriginSelf = 7,
        OriginOther = 31,
    };
    /*! Get the origin of the key.
     *
     * @returns the Origin. */
    Origin origin() const;

    /*! Get the last update time.
     *
     * @returns the last update time. */
    time_t lastUpdate() const;
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

    /*! Shorthand for isNull || isRevoked || isExpired ||
     *                          isDisabled || isInvalid */
    bool isBad() const;

    bool canEncrypt() const;
    bool canSign() const;
    bool canCertify() const;
    bool canAuthenticate() const;
    bool isQualified() const;
    bool isDeVs() const;
    bool isCardKey() const;

    bool isSecret() const;

    /** Same as gpgme_pubkey_algo_t */
    enum PubkeyAlgo {
        AlgoUnknown = 0,
        AlgoRSA     = 1,
        AlgoRSA_E   = 2,
        AlgoRSA_S   = 3,
        AlgoELG_E   = 16,
        AlgoDSA     = 17,
        AlgoECC     = 18,
        AlgoELG     = 20,
        AlgoECDSA   = 301,
        AlgoECDH    = 302,
        AlgoEDDSA   = 303,
        AlgoMax     = 1 << 31
    };

    PubkeyAlgo publicKeyAlgorithm() const;

    /**
      @brief Get the public key algorithm name.

      This only works for the pre 2.1 algorithms for ECC NULL is returned.

      @returns a statically allocated string with the name of the public
               key algorithm, or NULL if that name is not known.
    */
    const char *publicKeyAlgorithmAsString() const;

    /** @brief Same as publicKeyAlgorithmAsString but static. */
    static const char *publicKeyAlgorithmAsString(PubkeyAlgo algo);

    /**
       @brief Get the key algo string like GnuPG 2.1 prints it.

       This returns combinations of size and algorithm. Like
       bp512 or rsa2048. Misnamed because publicKeyAlgorithmAsString
       already used the older pubkey_algo_name.
       Actually uses gpgme_pubkey_algo_string.

       @returns the key algorithm as string. Empty string on error.
    */
    std::string algoName() const;

    unsigned int length() const;

    const char *cardSerialNumber() const;

    const char *keyGrip() const;

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
    const char *uidhash() const;

    enum Validity { Unknown = 0, Undefined = 1, Never = 2,
                    Marginal = 3, Full = 4, Ultimate = 5
                  };

    Validity validity() const;
    char validityAsString() const;

    bool isRevoked() const;
    bool isInvalid() const;

    /*! Shorthand for isNull || isRevoked || isInvalid */
    bool isBad() const;

    /** TOFU info for this userid.
     * @returns The TOFU stats or a null TofuInfo.
     */
    GpgME::TofuInfo tofuInfo() const;

    /*! Wrapper around gpgme_addrspec_from_uid.
     *
     * The input string should match the format of
     * a user id string.
     *
     * @returns a normalized mail address if found
     * or an empty string. */
    static std::string addrSpecFromString(const char *uid);

    /*! Wrapper around gpgme_addrspec_from_uid.
     *
     * @returns a normalized mail address for this userid
     * or an empty string. */
    std::string addrSpec() const;

    /*! Revoke the user id.
     *
     * Key needs update afterwards.
     *
     * @returns an error on error.*/
    Error revoke();

    /*! Get the origin of the key.
     *
     * @returns the Origin. */
    Key::Origin origin() const;

    /*! Get the last update time.
     *
     * @returns the last update time. */
    time_t lastUpdate() const;

    /*! Get a remark made by the key provided.
     * A remark is a signature notation on
     * this user id made by the key with the
     * name "rem@gnupg.org". Returns an error if the
     * parent key of this user id was not listed with the
     * keylist mode flags for signatures and signature notations.
     *
     * @param key The key for which comments should be searched.
     * @param error Set to GPG_ERR_NO_DATA if the keylist did
     *              not include signature notations.
     *
     * @returns The value of the comment or NULL if none exists.
     **/
    const char *remark(const Key &key,
                       Error &error) const;

    /*! Get multiple remarks made by potentially multiple keys. */
    std::vector <std::string> remarks(std::vector<GpgME::Key> remarkers,
                                      Error &error) const;

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

    /*! Defines a canonical sort order for signatures of the same user ID. */
    bool operator<(const Signature &other) const;

    GPGMEPP_DEPRECATED bool operator<(const Signature &other);

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

    /*! Shorthand for isNull || isExpired || isInvalid */
    bool isBad() const;

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

    bool isTrustSignature() const;
    TrustSignatureTrust trustValue() const;
    unsigned int trustDepth() const;
    const char *trustScope() const;

private:
    shared_gpgme_key_t key;
    gpgme_user_id_t uid;
    gpgme_key_sig_t sig;
};

GPGMEPP_EXPORT std::ostream &operator<<(std::ostream &os, const UserID &uid);
GPGMEPP_EXPORT std::ostream &operator<<(std::ostream &os, const Subkey &subkey);
GPGMEPP_EXPORT std::ostream &operator<<(std::ostream &os, const Key &key);

} // namespace GpgME

GPGMEPP_MAKE_STD_SWAP_SPECIALIZATION(Key)
GPGMEPP_MAKE_STD_SWAP_SPECIALIZATION(Subkey)
GPGMEPP_MAKE_STD_SWAP_SPECIALIZATION(UserID)
GPGMEPP_MAKE_STD_SWAP_SPECIALIZATION(UserID::Signature)

GPGMEPP_MAKE_STRCMP(ByFingerprint, .primaryFingerprint());
GPGMEPP_MAKE_STRCMP(ByKeyID, .keyID());
GPGMEPP_MAKE_STRCMP(ByShortKeyID, .shortKeyID());
GPGMEPP_MAKE_STRCMP(ByChainID, .chainID());

#endif // __GPGMEPP_KEY_H__
