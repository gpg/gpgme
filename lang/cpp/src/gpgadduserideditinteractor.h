/*
  gpgadduserideditinteractor.h - Edit Interactor to add a new UID to an OpenPGP key
  Copyright (C) 2008 Klarälvdalens Datakonsult AB
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

#ifndef __GPGMEPP_GPGADDUSERIDEDITINTERACTOR_H__
#define __GPGMEPP_GPGADDUSERIDEDITINTERACTOR_H__

#include <editinteractor.h>

#include <string>

namespace GpgME
{

class GPGMEPP_EXPORT GpgAddUserIDEditInteractor : public EditInteractor
{
public:
    explicit GpgAddUserIDEditInteractor();
    ~GpgAddUserIDEditInteractor();

    void setNameUtf8(const std::string &name);
    const std::string &nameUtf8() const
    {
        return m_name;
    }

    void setEmailUtf8(const std::string &email);
    const std::string &emailUtf8() const
    {
        return m_email;
    }

    void setCommentUtf8(const std::string &comment);
    const std::string &commentUtf8() const
    {
        return m_comment;
    }

private:
    const char *action(Error &err) const override;
    unsigned int nextState(unsigned int statusCode, const char *args, Error &err) const override;

private:
    std::string m_name, m_email, m_comment;
};

} // namespace GpgME

#endif // __GPGMEPP_GPGADDUSERIDEDITINTERACTOR_H__
