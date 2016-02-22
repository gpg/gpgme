/*
  assuanresult.h - wraps a gpgme assuan result
  Copyright (C) 2009 Klarälvdalens Datakonsult AB <info@kdab.com>
  Author: Marc Mutz <marc@kdab.com>

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

#ifndef __GPGMEPP_ASSUANRESULT_H__
#define __GPGMEPP_ASSUANRESULT_H__

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

class GPGMEPP_EXPORT AssuanResult : public Result
{
public:
    AssuanResult();
    AssuanResult(gpgme_ctx_t ctx, int error);
    AssuanResult(gpgme_ctx_t ctx, const Error &error);
    explicit AssuanResult(const Error &err);

    const AssuanResult &operator=(AssuanResult other)
    {
        swap(other);
        return *this;
    }

    void swap(AssuanResult &other)
    {
        Result::swap(other);
        using std::swap;
        swap(this->d, other.d);
    }

    bool isNull() const;

    Error assuanError() const;

    class Private;
private:
    void init(gpgme_ctx_t ctx);
    boost::shared_ptr<Private> d;
};

GPGMEPP_EXPORT std::ostream &operator<<(std::ostream &os, const AssuanResult &result);

}

GPGMEPP_MAKE_STD_SWAP_SPECIALIZATION(AssuanResult)

#endif // __GPGMEPP_ASSUANRESULT_H__
