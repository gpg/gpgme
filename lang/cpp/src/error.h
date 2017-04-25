/*
  error.h - wraps a gpgme error
  Copyright (C) 2003, 2007 Klarälvdalens Datakonsult AB
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

// -*- c++ -*-
#ifndef __GPGMEPP_ERROR_H__
#define __GPGMEPP_ERROR_H__

#include "global.h"

#include <string>
#include <iosfwd>

#include <gpg-error.h>

#ifndef GPGMEPP_ERR_SOURCE_DEFAULT
# define GPGMEPP_ERR_SOURCE_DEFAULT GPG_ERR_SOURCE_USER_1
#endif

namespace GpgME
{

class GPGMEPP_EXPORT Error
{
public:
    Error() : mErr(0), mMessage() {}
    explicit Error(unsigned int e) : mErr(e), mMessage() {}

    const char *source() const;
    const char *asString() const;

    int code() const;
    int sourceID() const;

    bool isCanceled() const;

    unsigned int encodedError() const
    {
        return mErr;
    }
    int toErrno() const;

    static bool hasSystemError();
    static Error fromSystemError(unsigned int src = GPGMEPP_ERR_SOURCE_DEFAULT);
    static void setSystemError(gpg_err_code_t err);
    static void setErrno(int err);
    static Error fromErrno(int err, unsigned int src = GPGMEPP_ERR_SOURCE_DEFAULT);
    static Error fromCode(unsigned int err, unsigned int src = GPGMEPP_ERR_SOURCE_DEFAULT);

    GPGMEPP_MAKE_SAFE_BOOL_OPERATOR(mErr  &&!isCanceled())
private:
    unsigned int mErr;
    mutable std::string mMessage;
};

GPGMEPP_EXPORT std::ostream &operator<<(std::ostream &os, const Error &err);

} // namespace GpgME

#endif /* __GPGMEPP_ERROR_H__ */
