/*
  gpgsetexpirytimeeditinteractor.cpp - Edit Interactor to change the expiry time of an OpenPGP key
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

#include "gpgsetexpirytimeeditinteractor.h"
#include "error.h"

#include <gpgme.h>

#include <cstring>

using std::strcmp;

// avoid conflict (msvc)
#ifdef ERROR
# undef ERROR
#endif

using namespace GpgME;

GpgSetExpiryTimeEditInteractor::GpgSetExpiryTimeEditInteractor(const std::string &t)
    : EditInteractor(),
      m_strtime(t)
{

}

GpgSetExpiryTimeEditInteractor::~GpgSetExpiryTimeEditInteractor() {}

// work around --enable-final
namespace GpgSetExpiryTimeEditInteractor_Private
{
enum {
    START = EditInteractor::StartState,
    COMMAND,
    DATE,
    QUIT,
    SAVE,

    ERROR = EditInteractor::ErrorState
};
}

const char *GpgSetExpiryTimeEditInteractor::action(Error &err) const
{

    using namespace GpgSetExpiryTimeEditInteractor_Private;

    switch (state()) {
    case COMMAND:
        return "expire";
    case DATE:
        return m_strtime.c_str();
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

unsigned int GpgSetExpiryTimeEditInteractor::nextState(unsigned int status, const char *args, Error &err) const
{

    static const Error GENERAL_ERROR  = Error::fromCode(GPG_ERR_GENERAL);
    static const Error INV_TIME_ERROR = Error::fromCode(GPG_ERR_INV_TIME);

    if (needsNoResponse(status)) {
        return state();
    }

    using namespace GpgSetExpiryTimeEditInteractor_Private;

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
                strcmp(args, "keygen.valid") == 0) {
            return DATE;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case DATE:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "keyedit.prompt") == 0) {
            return QUIT;
        } else if (status == GPGME_STATUS_GET_LINE &&
                   strcmp(args, "keygen.valid")) {
            err = INV_TIME_ERROR;
            return ERROR;
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
    }
}
