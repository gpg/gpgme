/*
  vfsmountresult.h - wraps a gpgme vfs mount result
  Copyright (C) 2009 Klarälvdalens Datakonsult AB <info@kdab.com>
  Author: Marc Mutz <marc@kdab.com>, Volker Krause <volker@kdab.com>

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

#ifndef __GPGMEPP_VFSMOUNTRESULT_H__
#define __GPGMEPP_VFSMOUNTRESULT_H__

#include "gpgmefw.h"
#include "result.h"
#include "gpgmepp_export.h"

#include <memory>

#include <vector>
#include <iosfwd>

namespace GpgME
{

class Error;

class GPGMEPP_EXPORT VfsMountResult : public Result
{
public:
    VfsMountResult();
    VfsMountResult(gpgme_ctx_t ctx, const Error &error, const Error &opError);
    explicit VfsMountResult(const Error &err);

    const VfsMountResult &operator=(VfsMountResult other)
    {
        swap(other);
        return *this;
    }

    void swap(VfsMountResult &other)
    {
        Result::swap(other);
        using std::swap;
        swap(this->d, other.d);
    }

    bool isNull() const;
    const char *mountDir() const;

    class Private;
private:
    void init(gpgme_ctx_t ctx);
    std::shared_ptr<Private> d;
};

GPGMEPP_EXPORT std::ostream &operator<<(std::ostream &os, const VfsMountResult &result);

}

GPGMEPP_MAKE_STD_SWAP_SPECIALIZATION(VfsMountResult)

#endif // __GPGMEPP_VFSMOUNTRESULT_H__
