/*
  gpgrevokekeyeditinteractor.cpp - Edit Interactor to revoke own OpenPGP keys
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

#ifdef HAVE_CONFIG_H
 #include "config.h"
#endif

#include "gpgrevokekeyeditinteractor.h"

#include "error.h"

#include <gpgme.h>

#include <vector>

// avoid conflict (msvc)
#ifdef ERROR
# undef ERROR
#endif

using namespace GpgME;

class GpgRevokeKeyEditInteractor::Private
{
    enum {
        START = EditInteractor::StartState,
        COMMAND,
        CONFIRM_REVOKING_ENTIRE_KEY,
        REASON_CODE,
        REASON_TEXT,
        // all these free slots belong to REASON_TEXT, too; we increase state()
        // by one for each line of text, so that action() is called
        REASON_TEXT_DONE = REASON_TEXT + 1000,
        CONFIRM_REASON,
        QUIT,
        CONFIRM_SAVE,

        ERROR = EditInteractor::ErrorState
    };

    GpgRevokeKeyEditInteractor *const q = nullptr;

public:
    Private(GpgRevokeKeyEditInteractor *q)
        : q{q}
        , reasonCode{"0"}
    {
    }

    const char *action(Error &err) const;
    unsigned int nextState(unsigned int statusCode, const char *args, Error &err);

    std::string reasonCode;
    std::vector<std::string> reasonLines;
    int nextLine = -1;
};

const char *GpgRevokeKeyEditInteractor::Private::action(Error &err) const
{
    switch (const auto state = q->state()) {
    case COMMAND:
        return "revkey";
    case CONFIRM_REVOKING_ENTIRE_KEY:
        return "Y";
    case REASON_CODE:
        return reasonCode.c_str();
    case REASON_TEXT_DONE:
        return "";
    case CONFIRM_REASON:
        return "Y";
    case QUIT:
        return "quit";
    case CONFIRM_SAVE:
        return "Y";
    case START:
        return nullptr;
    default:
        if (state >= REASON_TEXT && state < REASON_TEXT_DONE) {
            return reasonLines[nextLine].c_str();
        }
    // fall through
    case ERROR:
        err = Error::fromCode(GPG_ERR_GENERAL);
        return nullptr;
    }
}

unsigned int GpgRevokeKeyEditInteractor::Private::nextState(unsigned int status, const char *args, Error &err)
{
    using std::strcmp;

    static const Error GENERAL_ERROR = Error::fromCode(GPG_ERR_GENERAL);

    switch (const auto state = q->state()) {
    case START:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "keyedit.prompt") == 0) {
            return COMMAND;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case COMMAND:
        if (status == GPGME_STATUS_GET_BOOL &&
                strcmp(args, "keyedit.revoke.subkey.okay") == 0) {
            return CONFIRM_REVOKING_ENTIRE_KEY;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case CONFIRM_REVOKING_ENTIRE_KEY:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "ask_revocation_reason.code") == 0) {
            return REASON_CODE;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case REASON_CODE:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "ask_revocation_reason.text") == 0) {
            nextLine++;
            return static_cast<std::size_t>(nextLine) < reasonLines.size() ? REASON_TEXT : REASON_TEXT_DONE;
        }
        err = GENERAL_ERROR;
        return ERROR;
    default:
        if (state >= REASON_TEXT && state < REASON_TEXT_DONE) {
            if (status == GPGME_STATUS_GET_LINE &&
                    strcmp(args, "ask_revocation_reason.text") == 0) {
                nextLine++;
                return static_cast<std::size_t>(nextLine) < reasonLines.size() ? state + 1 : REASON_TEXT_DONE;
            }
        }
        err = GENERAL_ERROR;
        return ERROR;
    case REASON_TEXT_DONE:
        if (status == GPGME_STATUS_GET_BOOL &&
                strcmp(args, "ask_revocation_reason.okay") == 0) {
            return CONFIRM_REASON;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case CONFIRM_REASON:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "keyedit.prompt") == 0) {
            return QUIT;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case QUIT:
        if (status == GPGME_STATUS_GET_BOOL &&
                strcmp(args, "keyedit.save.okay") == 0) {
            return CONFIRM_SAVE;
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
    }
}

GpgRevokeKeyEditInteractor::GpgRevokeKeyEditInteractor()
    : EditInteractor{}
    , d{new Private{this}}
{
}

GpgRevokeKeyEditInteractor::~GpgRevokeKeyEditInteractor() = default;

void GpgRevokeKeyEditInteractor::setReason(RevocationReason reason, const std::vector<std::string> &description)
{
    d->reasonCode = std::to_string(static_cast<int>(reason));
    d->reasonLines = description;
}

const char *GpgRevokeKeyEditInteractor::action(Error &err) const
{
    return d->action(err);
}

unsigned int GpgRevokeKeyEditInteractor::nextState(unsigned int status, const char *args, Error &err) const
{
    return d->nextState(status, args, err);
}
