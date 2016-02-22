/*
  decryptionresult.h - wraps a gpgme keygen result
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

#ifndef __GPGMEPP_DECRYPTIONRESULT_H__
#define __GPGMEPP_DECRYPTIONRESULT_H__

#include "gpgmefw.h"
#include "result.h"
#include "gpgmepp_export.h"

#include <boost/shared_ptr.hpp>

#include <vector>
#include <algorithm>
#include <iosfwd>

namespace GpgME
{

class Error;

class GPGMEPP_EXPORT DecryptionResult : public Result
{
public:
    DecryptionResult();
    DecryptionResult(gpgme_ctx_t ctx, int error);
    DecryptionResult(gpgme_ctx_t ctx, const Error &err);
    explicit DecryptionResult(const Error &err);

    const DecryptionResult &operator=(DecryptionResult other)
    {
        swap(other);
        return *this;
    }

    void swap(DecryptionResult &other)
    {
        Result::swap(other);
        using std::swap;
        swap(this->d, other.d);
    }

    bool isNull() const;

    GPGMEPP_DEPRECATED const char *unsupportedAlgortihm() const
    {
        return unsupportedAlgorithm();
    }
    const char *unsupportedAlgorithm() const;

    GPGMEPP_DEPRECATED bool wrongKeyUsage() const
    {
        return isWrongKeyUsage();
    }
    bool isWrongKeyUsage() const;

    const char *fileName() const;

    class Recipient;

    unsigned int numRecipients() const;
    Recipient recipient(unsigned int idx) const;
    std::vector<Recipient> recipients() const;

private:
    class Private;
    void init(gpgme_ctx_t ctx);
    boost::shared_ptr<Private> d;
};

GPGMEPP_EXPORT std::ostream &operator<<(std::ostream &os, const DecryptionResult &result);

class GPGMEPP_EXPORT DecryptionResult::Recipient
{
public:
    Recipient();
    explicit Recipient(gpgme_recipient_t reci);

    const Recipient &operator=(Recipient other)
    {
        swap(other);
        return *this;
    }

    void swap(Recipient &other)
    {
        using std::swap;
        swap(this->d, other.d);
    }

    bool isNull() const;

    const char *keyID() const;
    const char *shortKeyID() const;

    unsigned int publicKeyAlgorithm() const;
    const char *publicKeyAlgorithmAsString() const;

    Error status() const;

private:
    class Private;
    boost::shared_ptr<Private> d;
};

GPGMEPP_EXPORT std::ostream &operator<<(std::ostream &os, const DecryptionResult::Recipient &reci);

}

GPGMEPP_MAKE_STD_SWAP_SPECIALIZATION(DecryptionResult)

#endif // __GPGMEPP_DECRYPTIONRESULT_H__
