/*
  gpgsetownertrusteditinteractor.h - Edit Interactor to change the owner trust of an OpenPGP key
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

#ifndef __GPGMEPP_GPGSETOWNERTRUSTEDITINTERACTOR_H__
#define __GPGMEPP_GPGSETOWNERTRUSTEDITINTERACTOR_H__

#include <editinteractor.h>
#include <key.h>

#include <string>

namespace GpgME
{

class GPGMEPP_EXPORT GpgSetOwnerTrustEditInteractor : public EditInteractor
{
public:
    explicit GpgSetOwnerTrustEditInteractor(Key::OwnerTrust ownertrust);
    ~GpgSetOwnerTrustEditInteractor();

private:
    const char *action(Error &err) const override;
    unsigned int nextState(unsigned int statusCode, const char *args, Error &err) const override;

private:
    const Key::OwnerTrust m_ownertrust;
};

} // namespace GpgME

#endif // __GPGMEPP_GPGSETOWNERTRUSTEDITINTERACTOR_H__
