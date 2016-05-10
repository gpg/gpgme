/*
  gpgsetexpirytimeeditinteractor.h - Edit Interactor to change the expiry time of an OpenPGP key
  Copyright (C) 2007 Klarälvdalens Datakonsult AB

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

#ifndef __GPGMEPP_GPGSETEXPIRYTIMEEDITINTERACTOR_H__
#define __GPGMEPP_GPGSETEXPIRYTIMEEDITINTERACTOR_H__

#include <editinteractor.h>

#include <string>

namespace GpgME
{

class GPGMEPP_EXPORT GpgSetExpiryTimeEditInteractor : public EditInteractor
{
public:
    explicit GpgSetExpiryTimeEditInteractor(const std::string &timeString = "0");
    ~GpgSetExpiryTimeEditInteractor();

private:
    /* reimp */ const char *action(Error &err) const;
    /* reimp */ unsigned int nextState(unsigned int statusCode, const char *args, Error &err) const;

private:
    const std::string m_strtime;
};

} // namespace GpgME

#endif // __GPGMEPP_GPGSETEXPIRYTIMEEDITINTERACTOR_H___
