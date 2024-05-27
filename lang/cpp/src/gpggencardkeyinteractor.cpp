/*
  gpggencardkeyinteractor.cpp - Edit Interactor to generate a key on a card
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

#include "gpggencardkeyinteractor.h"

#include "error.h"

#include <gpgme.h>

using namespace GpgME;

class GpgGenCardKeyInteractor::Private
{
public:
    Private() : keysize("2048")
    {
    }

    std::string name, email, backupFileName, expiry, serial, keysize;
    bool backup = false;
    Algo algo = RSA;
    std::string curve;
};

GpgGenCardKeyInteractor::~GpgGenCardKeyInteractor() = default;

GpgGenCardKeyInteractor::GpgGenCardKeyInteractor(const std::string &serial):
    d(new Private)
{
    d->serial = serial;
}

void GpgGenCardKeyInteractor::setNameUtf8(const std::string &name)
{
    d->name = name;
}

void GpgGenCardKeyInteractor::setEmailUtf8(const std::string &email)
{
    d->email = email;
}

void GpgGenCardKeyInteractor::setDoBackup(bool value)
{
    d->backup = value;
}

void GpgGenCardKeyInteractor::setKeySize(int value)
{
    d->keysize = std::to_string(value);
}

void GpgGenCardKeyInteractor::setExpiry(const std::string &timeStr)
{
    d->expiry = timeStr;
}

std::string GpgGenCardKeyInteractor::backupFileName() const
{
    return d->backupFileName;
}

void GpgGenCardKeyInteractor::setAlgo(Algo algo)
{
    d->algo = algo;
}

void GpgGenCardKeyInteractor::setCurve(Curve curve)
{
    if (curve == DefaultCurve) {
        d->curve.clear();
    } else if (curve >= 1 && curve <= LastCurve) {
        d->curve = std::to_string(static_cast<int>(curve));
    }
}

namespace GpgGenCardKeyInteractor_Private
{
enum {
    START = EditInteractor::StartState,
    DO_ADMIN,
    EXPIRE,

    GOT_SERIAL,
    COMMAND,
    NAME,
    EMAIL,
    COMMENT,
    BACKUP,
    REPLACE,
    SIZE,
    SIZE2,
    SIZE3,
    BACKUP_KEY_CREATED,
    KEY_CREATED,
    QUIT,
    SAVE,

    KEY_ATTR,
    KEY_ALGO1,
    KEY_ALGO2,
    KEY_ALGO3,
    KEY_CURVE1,
    KEY_CURVE2,
    KEY_CURVE3,

    ERROR = EditInteractor::ErrorState
};
}

const char *GpgGenCardKeyInteractor::action(Error &err) const
{

    using namespace GpgGenCardKeyInteractor_Private;

    switch (state()) {
    case DO_ADMIN:
        return "admin";
    case COMMAND:
        return "generate";
    case KEY_ATTR:
        return "key-attr";
    case KEY_ALGO1:
    case KEY_ALGO2:
    case KEY_ALGO3:
        return d->algo == RSA ? "1" : "2";
    case KEY_CURVE1:
    case KEY_CURVE2:
    case KEY_CURVE3:
        return d->curve.empty() ? "1" : d->curve.c_str(); // default is Curve25519
    case NAME:
        return d->name.c_str();
    case EMAIL:
        return d->email.c_str();
    case EXPIRE:
        return d->expiry.c_str();
    case BACKUP:
        return d->backup ? "Y" : "N";
    case REPLACE:
        return "Y";
    case SIZE:
    case SIZE2:
    case SIZE3:
        return d->keysize.c_str();
    case COMMENT:
        return "";
    case SAVE:
        return "Y";
    case QUIT:
        return "quit";
    case KEY_CREATED:
    case START:
    case GOT_SERIAL:
    case BACKUP_KEY_CREATED:
    case ERROR:
        return nullptr;
    default:
        err = Error::fromCode(GPG_ERR_GENERAL);
        return nullptr;
    }
}

unsigned int GpgGenCardKeyInteractor::nextState(unsigned int status, const char *args, Error &err) const
{

    static const Error GENERAL_ERROR     = Error::fromCode(GPG_ERR_GENERAL);
    static const Error INV_NAME_ERROR    = Error::fromCode(GPG_ERR_INV_NAME);
    static const Error INV_EMAIL_ERROR   = Error::fromCode(GPG_ERR_INV_USER_ID);
    static const Error INV_COMMENT_ERROR = Error::fromCode(GPG_ERR_INV_USER_ID);

    using namespace GpgGenCardKeyInteractor_Private;

    switch (state()) {
    case START:
        if (status == GPGME_STATUS_CARDCTRL &&
                !d->serial.empty()) {
            const std::string sArgs = args;
            if (sArgs.find(d->serial) == std::string::npos) {
                // Wrong smartcard
                err = Error::fromCode(GPG_ERR_WRONG_CARD);
                return ERROR;
            } else {
                printf("EditInteractor: Confirmed S/N: %s %s\n",
                           d->serial.c_str(), sArgs.c_str());
            }
            return GOT_SERIAL;
        } else if (d->serial.empty()) {
            return GOT_SERIAL;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case GOT_SERIAL:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "cardedit.prompt") == 0) {
            return DO_ADMIN;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case DO_ADMIN:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "cardedit.prompt") == 0) {
            return KEY_ATTR;
        }
        err = GENERAL_ERROR;
        return ERROR;
    // Handling for key-attr subcommand
    case KEY_ATTR:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "cardedit.prompt") == 0) {
            // Happens if key attr is not yet supported.
            return COMMAND;
        }
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "cardedit.genkeys.algo") == 0) {
            return KEY_ALGO1;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case KEY_ALGO1:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "cardedit.genkeys.size") == 0) {
            return SIZE;
        }
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "keygen.curve") == 0) {
            return KEY_CURVE1;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case KEY_ALGO2:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "cardedit.genkeys.size") == 0) {
            return SIZE2;
        }
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "keygen.curve") == 0) {
            return KEY_CURVE2;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case KEY_ALGO3:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "cardedit.genkeys.size") == 0) {
            return SIZE3;
        }
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "keygen.curve") == 0) {
            return KEY_CURVE3;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case KEY_CURVE1:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "cardedit.genkeys.algo") == 0) {
            return KEY_ALGO2;
        }
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "cardedit.prompt") == 0) {
            return COMMAND;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case KEY_CURVE2:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "cardedit.genkeys.algo") == 0) {
            return KEY_ALGO3;
        }
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "cardedit.prompt") == 0) {
            return COMMAND;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case KEY_CURVE3:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "cardedit.genkeys.algo") == 0) {
            return KEY_ALGO3;
        }
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "cardedit.prompt") == 0) {
            return COMMAND;
        }
        err = GENERAL_ERROR;
        return ERROR;
    // End key-attr handling
    case COMMAND:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "cardedit.genkeys.backup_enc") == 0) {
            return BACKUP;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case BACKUP:
        if (status == GPGME_STATUS_GET_BOOL &&
                strcmp(args, "cardedit.genkeys.replace_keys") == 0) {
            return REPLACE;
        }
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "cardedit.genkeys.size") == 0) {
            return SIZE;
        }
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "keygen.valid") == 0) {
            return EXPIRE;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case REPLACE:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "cardedit.genkeys.size") == 0) {
            return SIZE;
        }
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "keygen.valid") == 0) {
            return EXPIRE;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case SIZE:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "cardedit.genkeys.size") == 0) {
            return SIZE2;
        }
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "keygen.valid") == 0) {
            return EXPIRE;
        }
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "cardedit.genkeys.algo") == 0) {
            return KEY_ALGO2;
        }
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "cardedit.prompt") == 0) {
            return COMMAND;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case SIZE2:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "cardedit.genkeys.size") == 0) {
            return SIZE3;
        }
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "keygen.valid") == 0) {
            return EXPIRE;
        }
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "cardedit.genkeys.algo") == 0) {
            return KEY_ALGO3;
        }
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "cardedit.prompt") == 0) {
            return COMMAND;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case SIZE3:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "keygen.valid") == 0) {
            return EXPIRE;
        }
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "cardedit.prompt") == 0) {
            return COMMAND;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case EXPIRE:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "keygen.name") == 0) {
            return NAME;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case NAME:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "keygen.email") == 0) {
            return EMAIL;
        }
        err = GENERAL_ERROR;
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "keygen.name") == 0) {
            err = INV_NAME_ERROR;
        }
        return ERROR;
    case EMAIL:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "keygen.comment") == 0) {
            return COMMENT;
        }
        err = GENERAL_ERROR;
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "keygen.email") == 0) {
            err = INV_EMAIL_ERROR;
        }
        return ERROR;
    case COMMENT:
        if (status == GPGME_STATUS_BACKUP_KEY_CREATED) {
            std::string sArgs = args;
            const auto pos = sArgs.rfind(" ");
            if (pos != std::string::npos) {
                d->backupFileName = sArgs.substr(pos + 1);
                return BACKUP_KEY_CREATED;
            }
        }
        if (status == GPGME_STATUS_KEY_CREATED) {
            return KEY_CREATED;
        }
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "keyedit.prompt") == 0) {
            return QUIT;
        }
        err = GENERAL_ERROR;
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "keygen.comment") == 0) {
            err = INV_COMMENT_ERROR;
        }
        return ERROR;
    case BACKUP_KEY_CREATED:
        if (status == GPGME_STATUS_KEY_CREATED) {
            return KEY_CREATED;
        }
        err = GENERAL_ERROR;
        return ERROR;
    case KEY_CREATED:
        return QUIT;
    case QUIT:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "cardedit.prompt") == 0) {
            return QUIT;
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
