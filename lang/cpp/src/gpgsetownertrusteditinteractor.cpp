/*
  gpgsetownertrusteditinteractor.cpp - Edit Interactor to change the expiry time of an OpenPGP key
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

#include "gpgsetownertrusteditinteractor.h"
#include "error.h"

#include <gpgme.h>

#include <cstring>

using std::strcmp;

// avoid conflict (msvc)
#ifdef ERROR
# undef ERROR
#endif

using namespace GpgME;

GpgSetOwnerTrustEditInteractor::GpgSetOwnerTrustEditInteractor(Key::OwnerTrust ot)
    : EditInteractor(),
      m_ownertrust(ot)
{

}

GpgSetOwnerTrustEditInteractor::~GpgSetOwnerTrustEditInteractor() {}

// work around --enable-final
namespace GpgSetOwnerTrustEditInteractor_Private
{
enum {
    START = EditInteractor::StartState,
    COMMAND,
    VALUE,
    REALLY_ULTIMATE,
    QUIT,
    SAVE,

    ERROR = EditInteractor::ErrorState
};
}

const char *GpgSetOwnerTrustEditInteractor::action(Error &err) const
{
    static const char truststrings[][2] = { "1", "1", "2", "3", "4", "5" };

    using namespace GpgSetOwnerTrustEditInteractor_Private;

    switch (state()) {
    case COMMAND:
        return "trust";
    case VALUE:
        return truststrings[m_ownertrust];
    case REALLY_ULTIMATE:
        return "Y";
    case QUIT:
        return "quit";
    case SAVE:
        return "Y";
    case START:
    case ERROR:
        return 0;
    default:
        err = Error::fromCode(GPG_ERR_GENERAL);
        return 0;
    }
}

unsigned int GpgSetOwnerTrustEditInteractor::nextState(unsigned int status, const char *args, Error &err) const
{

    static const Error GENERAL_ERROR = Error::fromCode(GPG_ERR_GENERAL);
    //static const Error INV_TIME_ERROR = Error::fromCode( GPG_ERR_INV_TIME );

    if (needsNoResponse(status)) {
        return state();
    }

    using namespace GpgSetOwnerTrustEditInteractor_Private;

    switch (state()) {
    case START:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "keyedit.prompt") == 0) {
            return COMMAND;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case COMMAND:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "edit_ownertrust.value") == 0) {
            return VALUE;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case VALUE:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "keyedit.prompt") == 0) {
            return QUIT;
        } else if (status == GPGME_STATUS_GET_BOOL &&
                   strcmp(args, "edit_ownertrust.set_ultimate.okay") == 0) {
            return REALLY_ULTIMATE;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case REALLY_ULTIMATE:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "keyedit.prompt") == 0) {
            return QUIT;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case QUIT:
        if (status == GPGME_STATUS_GET_BOOL &&
                strcmp(args, "keyedit.save.okay") == 0) {
            return SAVE;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case ERROR:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "keyedit.prompt") == 0) {
            return QUIT;
        }
        err = lastError();
        return ERROR;
    default:
        err = GENERAL_ERROR;
        return ERROR;
    };
}
