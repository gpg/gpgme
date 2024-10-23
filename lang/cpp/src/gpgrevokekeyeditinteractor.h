/*
  gpgrevokekeyeditinteractor.h - Edit Interactor to revoke own OpenPGP keys
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

#ifndef __GPGMEPP_GPGREVOKEKEYEDITINTERACTOR_H__
#define __GPGMEPP_GPGREVOKEKEYEDITINTERACTOR_H__

#include "editinteractor.h"
#include "global.h"

#include <memory>
#include <string>
#include <vector>

namespace GpgME
{

/** Edit interactor to revoke the key a key edit operation is working on.
 *  Supports revocation of own keys only. */
class GPGMEPP_EXPORT GpgRevokeKeyEditInteractor : public EditInteractor
{
public:
    GpgRevokeKeyEditInteractor();
    ~GpgRevokeKeyEditInteractor() override;

    /** Sets the reason for the revocation. The reason defaults to \c Unspecified.
     *  \a description can be used for adding a comment for the revocation. The
     *  individual elements of \a description must be non-empty strings and they
     *  must not contain any endline characters.
     */
    void setReason(RevocationReason reason, const std::vector<std::string> &description = {});

private:
    const char *action(Error &err) const override;
    unsigned int nextState(unsigned int statusCode, const char *args, Error &err) const override;

private:
    class GPGMEPP_NO_EXPORT Private;
    const std::unique_ptr<Private> d;
};

} // namespace GpgME

#endif // __GPGMEPP_GPGREVOKEKEYEDITINTERACTOR_H__
