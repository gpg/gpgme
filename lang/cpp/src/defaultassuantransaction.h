/*
  defaultassuantransaction.h - default Assuan Transaction that just stores data and status lines
  Copyright (C) 2009 Klarälvdalens Datakonsult AB
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

#ifndef __GPGMEPP_DEFAULTASSUANTRANSACTION_H__
#define __GPGMEPP_DEFAULTASSUANTRANSACTION_H__

#include <interfaces/assuantransaction.h>

#include <string>
#include <vector>
#include <utility>

namespace GpgME
{

class GPGMEPP_EXPORT DefaultAssuanTransaction : public AssuanTransaction
{
public:
    explicit DefaultAssuanTransaction();
    ~DefaultAssuanTransaction();

    const std::vector< std::pair<std::string, std::string> > &statusLines() const
    {
        return m_status;
    }
    std::vector<std::string> statusLine(const char *tag) const;
    std::string firstStatusLine(const char *tag) const;

    const std::string &data() const
    {
        return m_data;
    }

private:
    Error data(const char *data, size_t datalen) override;
    Data inquire(const char *name, const char *args, Error &err) override;
    Error status(const char *status, const char *args) override;

private:
    std::vector< std::pair<std::string, std::string> > m_status;
    std::string m_data;
};

} // namespace GpgME

#endif // __GPGMEPP_DEFAULTASSUANTRANSACTION_H__
