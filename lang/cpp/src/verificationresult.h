/*
  verificationresult.h - wraps a gpgme verify result
  Copyright (C) 2004 Klarälvdalens Datakonsult AB

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

#ifndef __GPGMEPP_VERIFICATIONRESULT_H__
#define __GPGMEPP_VERIFICATIONRESULT_H__

#include "gpgmefw.h"
#include "result.h"
#include "gpgmepp_export.h"

#include <time.h>

#include <boost/shared_ptr.hpp>

#include <vector>
#include <iosfwd>

namespace GpgME
{

class Error;
class Signature;
class Notation;

class GPGMEPP_EXPORT VerificationResult : public Result
{
public:
    VerificationResult();
    VerificationResult(gpgme_ctx_t ctx, int error);
    VerificationResult(gpgme_ctx_t ctx, const Error &error);
    explicit VerificationResult(const Error &err);

    const VerificationResult &operator=(VerificationResult other)
    {
        swap(other);
        return *this;
    }

    void swap(VerificationResult &other)
    {
        Result::swap(other);
        using std::swap;
        swap(this->d, other.d);
    }

    bool isNull() const;

    const char *fileName() const;

    unsigned int numSignatures() const;
    Signature signature(unsigned int index) const;
    std::vector<Signature> signatures() const;

    class Private;
private:
    void init(gpgme_ctx_t ctx);
    boost::shared_ptr<Private> d;
};

GPGMEPP_EXPORT std::ostream &operator<<(std::ostream &os, const VerificationResult &result);

class GPGMEPP_EXPORT Signature
{
    friend class ::GpgME::VerificationResult;
    Signature(const boost::shared_ptr<VerificationResult::Private> &parent, unsigned int index);
public:
    typedef GPGMEPP_DEPRECATED GpgME::Notation Notation;

    Signature();

    const Signature &operator=(Signature other)
    {
        swap(other);
        return *this;
    }

    void swap(Signature &other)
    {
        using std::swap;
        swap(this->d, other.d);
        swap(this->idx, other.idx);
    }

    bool isNull() const;

    enum Summary {
        None       = 0x000,
        Valid      = 0x001,
        Green      = 0x002,
        Red        = 0x004,
        KeyRevoked = 0x008,
        KeyExpired = 0x010,
        SigExpired = 0x020,
        KeyMissing = 0x040,
        CrlMissing = 0x080,
        CrlTooOld  = 0x100,
        BadPolicy  = 0x200,
        SysError   = 0x400
    };
    Summary summary() const;

    const char *fingerprint() const;

    Error status() const;

    time_t creationTime() const;
    time_t expirationTime() const;
    bool neverExpires() const;

    GPGMEPP_DEPRECATED bool wrongKeyUsage() const
    {
        return isWrongKeyUsage();
    }
    bool isWrongKeyUsage() const;
    bool isVerifiedUsingChainModel() const;

    enum PKAStatus {
        UnknownPKAStatus, PKAVerificationFailed, PKAVerificationSucceeded
    };
    PKAStatus pkaStatus() const;
    const char *pkaAddress() const;

    enum Validity {
        Unknown, Undefined, Never, Marginal, Full, Ultimate
    };
    Validity validity() const;
    char validityAsString() const;
    Error nonValidityReason() const;

    unsigned int publicKeyAlgorithm() const;
    const char *publicKeyAlgorithmAsString() const;

    unsigned int hashAlgorithm() const;
    const char *hashAlgorithmAsString() const;

    const char *policyURL() const;
    GpgME::Notation notation(unsigned int index) const;
    std::vector<GpgME::Notation> notations() const;

private:
    boost::shared_ptr<VerificationResult::Private> d;
    unsigned int idx;
};

GPGMEPP_EXPORT std::ostream &operator<<(std::ostream &os, const Signature &sig);
GPGMEPP_EXPORT std::ostream &operator<<(std::ostream &os, Signature::PKAStatus pkaStatus);
GPGMEPP_EXPORT std::ostream &operator<<(std::ostream &os, Signature::Summary summary);

}

GPGMEPP_MAKE_STD_SWAP_SPECIALIZATION(VerificationResult)
GPGMEPP_MAKE_STD_SWAP_SPECIALIZATION(Signature)

#endif // __GPGMEPP_VERIFICATIONRESULT_H__
