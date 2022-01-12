/*
  gpgaddexistingsubkeyeditinteractor.h - Edit Interactor to add an existing subkey to an OpenPGP key
  Copyright (c) 2022 g10 Code GmbH
  Software engineering by Ingo Klöcker <dev@ingo-kloecker.de>

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

#ifndef __GPGMEPP_GPGADDEXISTINGSUBKEYEDITINTERACTOR_H__
#define __GPGMEPP_GPGADDEXISTINGSUBKEYEDITINTERACTOR_H__

#include "editinteractor.h"

#include <memory>

namespace GpgME
{

class GPGMEPP_EXPORT GpgAddExistingSubkeyEditInteractor : public EditInteractor
{
public:
    /** Edit interactor to add the existing subkey with keygrip \a keygrip
     *  to the key a key edit operation is working on.
     **/
    explicit GpgAddExistingSubkeyEditInteractor(const std::string &keygrip);
    ~GpgAddExistingSubkeyEditInteractor() override;

    /** Sets the validity period of the added subkey. Use "0" for no expiration
     *  or a simplified ISO date string ("yyyymmddThhmmss") for setting an
     *  expiration date. */
    void setExpiry(const std::string &timeString);

private:
    const char *action(Error &err) const override;
    unsigned int nextState(unsigned int statusCode, const char *args, Error &err) const override;

private:
    class Private;
    const std::unique_ptr<Private> d;
};

} // namespace GpgME

#endif // __GPGMEPP_GPGADDEXISTINGSUBKEYEDITINTERACTOR_H__
