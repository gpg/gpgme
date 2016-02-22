/*
  signingresult.h - wraps a gpgme sign result
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

#ifndef __GPGMEPP_SIGNINGRESULT_H__
#define __GPGMEPP_SIGNINGRESULT_H__

#include "global.h"
#include "result.h"

#include <time.h>

#include <boost/shared_ptr.hpp>

#include <vector>
#include <iosfwd>

namespace GpgME
{

class Error;
class CreatedSignature;
class InvalidSigningKey;

class GPGMEPP_EXPORT SigningResult : public Result
{
public:
    SigningResult();
    SigningResult(gpgme_ctx_t ctx, int error);
    SigningResult(gpgme_ctx_t ctx, const Error &error);
    explicit SigningResult(const Error &err);

    const SigningResult &operator=(SigningResult other)
    {
        swap(other);
        return *this;
    }

    void swap(SigningResult &other)
    {
        Result::swap(other);
        using std::swap;
        swap(this->d, other.d);
    }

    bool isNull() const;

    CreatedSignature createdSignature(unsigned int index) const;
    std::vector<CreatedSignature> createdSignatures() const;

    InvalidSigningKey invalidSigningKey(unsigned int index) const;
    std::vector<InvalidSigningKey> invalidSigningKeys() const;

    class Private;
private:
    void init(gpgme_ctx_t ctx);
    boost::shared_ptr<Private> d;
};

GPGMEPP_EXPORT std::ostream &operator<<(std::ostream &os, const SigningResult &result);

class GPGMEPP_EXPORT InvalidSigningKey
{
    friend class ::GpgME::SigningResult;
    InvalidSigningKey(const boost::shared_ptr<SigningResult::Private> &parent, unsigned int index);
public:
    InvalidSigningKey();

    const InvalidSigningKey &operator=(InvalidSigningKey other)
    {
        swap(other);
        return *this;
    }

    void swap(InvalidSigningKey &other)
    {
        using std::swap;
        swap(this->d, other.d);
        swap(this->idx, other.idx);
    }

    bool isNull() const;

    const char *fingerprint() const;
    Error reason() const;

private:
    boost::shared_ptr<SigningResult::Private> d;
    unsigned int idx;
};

GPGMEPP_EXPORT std::ostream &operator<<(std::ostream &os, const InvalidSigningKey &key);

class GPGMEPP_EXPORT CreatedSignature
{
    friend class ::GpgME::SigningResult;
    CreatedSignature(const boost::shared_ptr<SigningResult::Private> &parent, unsigned int index);
public:

    CreatedSignature();

    const CreatedSignature &operator=(CreatedSignature other)
    {
        swap(other);
        return *this;
    }

    void swap(CreatedSignature &other)
    {
        using std::swap;
        swap(this->d, other.d);
        swap(this->idx, other.idx);
    }

    bool isNull() const;

    const char *fingerprint() const;

    time_t creationTime() const;

    SignatureMode mode() const;

    unsigned int publicKeyAlgorithm() const;
    const char *publicKeyAlgorithmAsString() const;

    unsigned int hashAlgorithm() const;
    const char *hashAlgorithmAsString() const;

    unsigned int signatureClass() const;

private:
    boost::shared_ptr<SigningResult::Private> d;
    unsigned int idx;
};

GPGMEPP_EXPORT std::ostream &operator<<(std::ostream &os, const CreatedSignature &sig);

}

GPGMEPP_MAKE_STD_SWAP_SPECIALIZATION(SigningResult)
GPGMEPP_MAKE_STD_SWAP_SPECIALIZATION(InvalidSigningKey)
GPGMEPP_MAKE_STD_SWAP_SPECIALIZATION(CreatedSignature)

#endif // __GPGMEPP_SIGNINGRESULT_H__
