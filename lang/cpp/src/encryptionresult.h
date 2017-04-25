/*
  encryptionresult.h - wraps a gpgme sign result
  Copyright (C) 2004 Klarälvdalens Datakonsult AB
  2016 Bundesamt für Sicherheit in der Informationstechnik
  Software engineering by Intevation GmbH

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

#ifndef __GPGMEPP_ENCRYPTIONRESULT_H__
#define __GPGMEPP_ENCRYPTIONRESULT_H__

#include "gpgmefw.h"
#include "result.h"
#include "gpgmepp_export.h"

#include <memory>

#include <vector>
#include <iosfwd>

namespace GpgME
{

class Error;
class InvalidRecipient;

class GPGMEPP_EXPORT EncryptionResult : public Result
{
public:
    EncryptionResult();
    EncryptionResult(gpgme_ctx_t ctx, int error);
    EncryptionResult(gpgme_ctx_t ctx, const Error &error);
    EncryptionResult(const Error &err);

    const EncryptionResult &operator=(EncryptionResult other)
    {
        swap(other);
        return *this;
    }

    void swap(EncryptionResult &other)
    {
        Result::swap(other);
        using std::swap;
        swap(this->d, other.d);
    }

    bool isNull() const;

    unsigned int numInvalidRecipients() const;

    InvalidRecipient invalidEncryptionKey(unsigned int index) const;
    std::vector<InvalidRecipient> invalidEncryptionKeys() const;

    class Private;
private:
    void init(gpgme_ctx_t ctx);
    std::shared_ptr<Private> d;
};

GPGMEPP_EXPORT std::ostream &operator<<(std::ostream &os, const EncryptionResult &result);

class GPGMEPP_EXPORT InvalidRecipient
{
    friend class ::GpgME::EncryptionResult;
    InvalidRecipient(const std::shared_ptr<EncryptionResult::Private> &parent, unsigned int index);
public:
    InvalidRecipient();

    const InvalidRecipient &operator=(InvalidRecipient other)
    {
        swap(other);
        return *this;
    }

    void swap(InvalidRecipient &other)
    {
        using std::swap;
        swap(this->d, other.d);
    }

    bool isNull() const;

    const char *fingerprint() const;
    Error reason() const;

private:
    std::shared_ptr<EncryptionResult::Private> d;
    unsigned int idx;
};

GPGMEPP_EXPORT std::ostream &operator<<(std::ostream &os, const InvalidRecipient &recipient);

}

GPGMEPP_MAKE_STD_SWAP_SPECIALIZATION(EncryptionResult)
GPGMEPP_MAKE_STD_SWAP_SPECIALIZATION(InvalidRecipient)

#endif // __GPGMEPP_ENCRYPTIONRESULT_H__
