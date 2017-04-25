/*
  exception.h - exception wrapping a gpgme error
  Copyright (C) 2007 Klarälvdalens Datakonsult AB
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
#ifndef __GPGMEPP_EXCEPTION_H__
#define __GPGMEPP_EXCEPTION_H__

#include "error.h"

#include <stdexcept>
#include <string>

namespace GpgME
{

class GPGMEPP_EXPORT Exception : public std::runtime_error
{
public:
    enum Options {
        NoOptions = 0x0,
        MessageOnly = 0x1,

        AllOptions = MessageOnly
    };

    explicit Exception(const GpgME::Error &err, const std::string &msg = std::string(), Options opt = NoOptions)
        : std::runtime_error(make_message(err, msg, opt)), m_error(err), m_message(msg) {}

    ~Exception() throw();

    Error error() const
    {
        return m_error;
    }
    const std::string &message() const
    {
        return m_message;
    }
private:
    static std::string make_message(const GpgME::Error &err, const std::string &msg);
    static std::string make_message(const GpgME::Error &err, const std::string &msg, Options opt);
private:
    const GpgME::Error m_error;
    const std::string m_message;
};

} // namespace GpgME

#endif /* __GPGMEPP_EXCEPTION_H__ */
