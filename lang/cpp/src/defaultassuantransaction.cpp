/*
  defaultassuantransaction.cpp - default Assuan Transaction that just stores data and status lines
  Copyright (C) 2009 Klarälvdalens Datakonsult AB

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

#include <config-gpgme++.h>

#include "defaultassuantransaction.h"
#include "error.h"
#include "data.h"

#include <sstream>

using namespace GpgME;
using namespace boost;

DefaultAssuanTransaction::DefaultAssuanTransaction()
    : AssuanTransaction(),
      m_status(),
      m_data()
{

}

DefaultAssuanTransaction::~DefaultAssuanTransaction() {}

Error DefaultAssuanTransaction::data(const char *data, size_t len)
{
    m_data.append(data, len);
    return Error();
}

Data DefaultAssuanTransaction::inquire(const char *name, const char *args, Error &err)
{
    (void)name; (void)args; (void)err;
    return Data::null;
}

Error DefaultAssuanTransaction::status(const char *status, const char *args)
{
    m_status.push_back(std::pair<std::string, std::string>(status, args));
    return Error();
}

std::vector<std::string> DefaultAssuanTransaction::statusLine(const char *tag) const
{
    std::vector<std::string> result;
    for (std::vector< std::pair<std::string, std::string> >::const_iterator it = m_status.begin(), end = m_status.end() ; it != end ; ++it) {
        if (it->first == tag) {
            result.push_back(it->second);
        }
    }
    return result;
}

std::string DefaultAssuanTransaction::firstStatusLine(const char *tag) const
{
    for (std::vector< std::pair<std::string, std::string> >::const_iterator it = m_status.begin(), end = m_status.end() ; it != end ; ++it) {
        if (it->first == tag) {
            return it->second;
        }
    }
    return std::string();
}
