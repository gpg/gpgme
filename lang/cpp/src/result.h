/*
  result.h - base class for results
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

#ifndef __GPGMEPP_RESULT_H__
#define __GPGMEPP_RESULT_H__

#include "gpgmefw.h"
#include "error.h"

#include <algorithm> // std::swap

namespace GpgME
{

class GPGMEPP_EXPORT Result
{
protected:
    explicit Result() : mError() {}
    explicit Result(int err) : mError(err) {}
    explicit Result(const Error &err) : mError(err) {}

    void swap(Result &other)
    {
        std::swap(other.mError, mError);
    }

public:
    const Error &error() const
    {
        return mError;
    }

protected:
    Error mError;
};

}

#endif // __GPGMEPP_RESULT_H__
