/*
  assuantransaction.h - Interface for ASSUAN transactions
  Copyright (C) 2009 Klarälvdalens Datakonsult AB
  2016 Bundesamt für Sicherheit in der Informationstechnik
  Software engineering by Intevation GmbH <info@kdab.com>
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

#ifndef __GPGMEPP_INTERFACES_ASSUANTRANSACTION_H__
#define __GPGMEPP_INTERFACES_ASSUANTRANSACTION_H__

#include "gpgmepp_export.h"

#include <stddef.h>

namespace GpgME
{

class Error;
class Data;

class GPGMEPP_EXPORT AssuanTransaction
{
public:
    virtual ~AssuanTransaction() {}

    virtual Error data(const char *data, size_t datalen) = 0;
    virtual Data  inquire(const char *name, const char *args, Error &err) = 0;
    virtual Error status(const char *status, const char *args) = 0;
};

} // namespace GpgME

#endif // __GPGMEPP_INTERFACES_ASSUANTRANSACTION_H__
