/*
  gpgsignkeyeditinteractor.h - Edit Interactor to change the owner trust of an OpenPGP key
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

#ifndef __GPGMEPP_GPGSIGNKEYEDITINTERACTOR_H__
#define __GPGMEPP_GPGSIGNKEYEDITINTERACTOR_H__

#include <editinteractor.h>

#include <string>
#include <vector>

namespace GpgME
{

class Key;
class UserID;
enum class TrustSignatureTrust : char;

class GPGMEPP_EXPORT GpgSignKeyEditInteractor : public EditInteractor
{
public:
    enum SignOption {
        Exportable = 0x1,
        NonRevocable = 0x2,
        Trust = 0x4
    };

    GpgSignKeyEditInteractor();
    ~GpgSignKeyEditInteractor();

    void setCheckLevel(unsigned int checkLevel);
    void setUserIDsToSign(const std::vector<unsigned int> &userIDsToSign);
    void setKey(const Key &key);
    void setSigningOptions(int options);

    /* Set this if it is ok to overwrite an existing signature. In that
     * case the context has to have the flag "extended-edit" set to 1 through
     * Context::setFlag before calling edit.*/
    void setDupeOk(bool value);

    void setTrustSignatureTrust(TrustSignatureTrust trust);
    void setTrustSignatureDepth(unsigned short depth);
    void setTrustSignatureScope(const std::string &scope);

private:
    const char *action(Error &err) const override;
    unsigned int nextState(unsigned int statusCode, const char *args, Error &err) const override;

private:
    class Private;
    Private *const d;
};

} // namespace GpgME

#endif // __GPGMEPP_GPGSIGNKEYEDITINTERACTOR_H__
