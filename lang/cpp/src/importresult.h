/*
  importresult.h - wraps a gpgme import result
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

#ifndef __GPGMEPP_IMPORTRESULT_H__
#define __GPGMEPP_IMPORTRESULT_H__

#include "gpgmefw.h"
#include "result.h"
#include "gpgmepp_export.h"

#include <memory>

#include <vector>

namespace GpgME
{

class Error;
class Import;

class GPGMEPP_EXPORT ImportResult : public Result
{
public:
    ImportResult();
    ImportResult(gpgme_ctx_t ctx, int error);
    ImportResult(gpgme_ctx_t ctx, const Error &error);
    explicit ImportResult(const Error &error);

    const ImportResult &operator=(ImportResult other)
    {
        swap(other);
        return *this;
    }

    void swap(ImportResult &other)
    {
        Result::swap(other);
        using std::swap;
        swap(this->d, other.d);
    }

    bool isNull() const;

    int numConsidered() const;
    int numKeysWithoutUserID() const;
    int numImported() const;
    int numRSAImported() const;
    int numUnchanged() const;

    int newUserIDs() const;
    int newSubkeys() const;
    int newSignatures() const;
    int newRevocations() const;

    int numSecretKeysConsidered() const;
    int numSecretKeysImported() const;
    int numSecretKeysUnchanged() const;

    int notImported() const;

    Import import(unsigned int idx) const;
    std::vector<Import> imports() const;

    class Private;
private:
    void init(gpgme_ctx_t ctx);
    std::shared_ptr<Private> d;
};

class GPGMEPP_EXPORT Import
{
    friend class ::GpgME::ImportResult;
    Import(const std::shared_ptr<ImportResult::Private> &parent, unsigned int idx);
public:
    Import();

    const Import &operator=(Import other)
    {
        swap(other);
        return *this;
    }

    void swap(Import &other)
    {
        using std::swap;
        swap(this->d, other.d);
        swap(this->idx, other.idx);
    }

    bool isNull() const;

    const char *fingerprint() const;
    Error error() const;

    enum Status {
        Unknown = 0x0,
        NewKey = 0x1,
        NewUserIDs = 0x2,
        NewSignatures = 0x4,
        NewSubkeys = 0x8,
        ContainedSecretKey = 0x10
    };
    Status status() const;

private:
    std::shared_ptr<ImportResult::Private> d;
    unsigned int idx;
};

}

GPGMEPP_MAKE_STD_SWAP_SPECIALIZATION(ImportResult)
GPGMEPP_MAKE_STD_SWAP_SPECIALIZATION(Import)

#endif // __GPGMEPP_IMPORTRESULT_H__
