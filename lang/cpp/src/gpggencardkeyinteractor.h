/*
  gpggencardkeyinteractor.h - Edit Interactor to generate a key on a card
  Copyright (C) 2017 by Bundesamt für Sicherheit in der Informationstechnik
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

#ifndef __GPGMEPP_GPGGENCARDKEYEDITINTERACTOR_H__
#define __GPGMEPP_GPGGENCARDKEYEDITINTERACTOR_H__

#include <editinteractor.h>

#include <string>
#include <memory>

namespace GpgME
{

class GPGMEPP_EXPORT GpgGenCardKeyInteractor: public EditInteractor
{
public:
    /** Edit interactor to generate a key on a smartcard.
     *
     * The \a serialnumber argument is intended to safeguard
     * against accidentally working on the wrong smartcard.
     *
     * The edit interactor will fail if the card did not match.
     *
     * @param serialnumber: Serialnumber of the intended card.
     **/
    explicit GpgGenCardKeyInteractor(const std::string &serialnumber);
    ~GpgGenCardKeyInteractor();

    /** Set the key sizes for the subkeys (default 2048) */
    void setKeySize(int size);

    void setNameUtf8(const std::string &name);
    void setEmailUtf8(const std::string &email);

    void setDoBackup(bool value);
    void setExpiry(const std::string &timeString);

    enum Algo {
        RSA = 1,
        ECC = 2
    };
    void setAlgo(Algo algo);

    std::string backupFileName() const;

private:
    const char *action(Error &err) const override;
    unsigned int nextState(unsigned int statusCode, const char *args, Error &err) const override;

private:
    class Private;
    std::shared_ptr<Private> d;
};

} // namespace GpgME

#endif // __GPGMEPP_GPGGENCARDKEYEDITINTERACTOR_H__
