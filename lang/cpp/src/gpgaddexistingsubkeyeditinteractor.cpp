/*
  gpgaddexistingsubkeyeditinteractor.cpp - Edit Interactor to add an existing subkey to an OpenPGP key
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

#include "gpgaddexistingsubkeyeditinteractor.h"

#include "error.h"

#include <gpgme.h>

// avoid conflict (msvc)
#ifdef ERROR
# undef ERROR
#endif

using namespace GpgME;

class GpgAddExistingSubkeyEditInteractor::Private
{
    enum {
        START = EditInteractor::StartState,
        COMMAND,
        ADD_EXISTING_KEY,
        KEYGRIP,
        FLAGS,
        VALID,
        KEY_CREATED,
        QUIT,
        SAVE,

        ERROR = EditInteractor::ErrorState
    };

    GpgAddExistingSubkeyEditInteractor *const q = nullptr;

public:
    Private(GpgAddExistingSubkeyEditInteractor *q, const std::string &keygrip)
        : q{q}
        , keygrip{keygrip}
    {
    }

    const char *action(Error &err) const;
    unsigned int nextState(unsigned int statusCode, const char *args, Error &err) const;

    std::string keygrip;
    std::string expiry;
};

const char *GpgAddExistingSubkeyEditInteractor::Private::action(Error &err) const
{
    switch (q->state()) {
    case COMMAND:
        return "addkey";
    case ADD_EXISTING_KEY:
        return "keygrip";
    case KEYGRIP:
        return keygrip.c_str();
    case FLAGS:
        return "Q"; // do not toggle any usage flags
    case VALID:
        return expiry.empty() ? "0" : expiry.c_str();
    case QUIT:
        return "quit";
    case SAVE:
        return "Y";
    case START:
    case KEY_CREATED:
    case ERROR:
        return nullptr;
    default:
        err = Error::fromCode(GPG_ERR_GENERAL);
        return nullptr;
    }
}

unsigned int GpgAddExistingSubkeyEditInteractor::Private::nextState(unsigned int status, const char *args, Error &err) const
{
    using std::strcmp;

    static const Error GENERAL_ERROR  = Error::fromCode(GPG_ERR_GENERAL);
    static const Error NO_KEY_ERROR = Error::fromCode(GPG_ERR_NO_KEY);
    static const Error INV_TIME_ERROR = Error::fromCode(GPG_ERR_INV_TIME);

    switch (q->state()) {
    case START:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "keyedit.prompt") == 0) {
            return COMMAND;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case COMMAND:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "keygen.algo") == 0) {
            return ADD_EXISTING_KEY;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case ADD_EXISTING_KEY:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "keygen.keygrip") == 0) {
            return KEYGRIP;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case KEYGRIP:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "keygen.flags") == 0) {
            return FLAGS;
        } else if (status == GPGME_STATUS_GET_LINE &&
                   strcmp(args, "keygen.keygrip") == 0) {
            err = NO_KEY_ERROR;
            return ERROR;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case FLAGS:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "keygen.valid") == 0) {
            return VALID;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case VALID:
        if (status == GPGME_STATUS_KEY_CREATED) {
            return KEY_CREATED;
        }
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "keyedit.prompt") == 0) {
            return QUIT;
        } else if (status == GPGME_STATUS_GET_LINE &&
                   strcmp(args, "keygen.valid") == 0) {
            err = INV_TIME_ERROR;
            return ERROR;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case KEY_CREATED:
        return QUIT;
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
        err = q->lastError();
        return ERROR;
    default:
        err = GENERAL_ERROR;
        return ERROR;
    }
}

GpgAddExistingSubkeyEditInteractor::GpgAddExistingSubkeyEditInteractor(const std::string &keygrip)
    : EditInteractor{}
    , d{new Private{this, keygrip}}
{
}

GpgAddExistingSubkeyEditInteractor::~GpgAddExistingSubkeyEditInteractor() = default;

void GpgAddExistingSubkeyEditInteractor::setExpiry(const std::string &timeString)
{
    d->expiry = timeString;
}

const char *GpgAddExistingSubkeyEditInteractor::action(Error &err) const
{
    return d->action(err);
}

unsigned int GpgAddExistingSubkeyEditInteractor::nextState(unsigned int status, const char *args, Error &err) const
{
    return d->nextState(status, args, err);
}
