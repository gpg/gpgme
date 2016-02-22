/*
  gpgadduserideditinteractor.cpp - Edit Interactor to add a new UID to an OpenPGP key
  Copyright (C) 2008 Klarälvdalens Datakonsult AB

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

#include "gpgadduserideditinteractor.h"

#include "error.h"

#include <gpgme.h>

#include <cstring>

using std::strcmp;

// avoid conflict (msvc)
#ifdef ERROR
# undef ERROR
#endif

using namespace GpgME;

GpgAddUserIDEditInteractor::GpgAddUserIDEditInteractor()
    : EditInteractor(),
      m_name(),
      m_email(),
      m_comment()
{

}

GpgAddUserIDEditInteractor::~GpgAddUserIDEditInteractor() {}

void GpgAddUserIDEditInteractor::setNameUtf8(const std::string &name)
{
    m_name = name;
}

void GpgAddUserIDEditInteractor::setEmailUtf8(const std::string &email)
{
    m_email = email;
}

void GpgAddUserIDEditInteractor::setCommentUtf8(const std::string &comment)
{
    m_comment = comment;
}

// work around --enable-final
namespace GpgAddUserIDEditInteractor_Private
{
enum {
    START = EditInteractor::StartState,
    COMMAND,
    NAME,
    EMAIL,
    COMMENT,
    QUIT,
    SAVE,

    ERROR = EditInteractor::ErrorState
};
}

const char *GpgAddUserIDEditInteractor::action(Error &err) const
{

    using namespace GpgAddUserIDEditInteractor_Private;

    switch (state()) {
    case COMMAND:
        return "adduid";
    case NAME:
        return m_name.c_str();
    case EMAIL:
        return m_email.c_str();
    case COMMENT:
        return m_comment.c_str();
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

unsigned int GpgAddUserIDEditInteractor::nextState(unsigned int status, const char *args, Error &err) const
{

    static const Error GENERAL_ERROR     = Error::fromCode(GPG_ERR_GENERAL);
    static const Error INV_NAME_ERROR    = Error::fromCode(GPG_ERR_INV_NAME);
    static const Error INV_EMAIL_ERROR   = Error::fromCode(GPG_ERR_INV_USER_ID);
    static const Error INV_COMMENT_ERROR = Error::fromCode(GPG_ERR_INV_USER_ID);

    if (needsNoResponse(status)) {
        return state();
    }

    using namespace GpgAddUserIDEditInteractor_Private;

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
