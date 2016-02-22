/*
  editinteractor.cpp - Interface for edit interactors
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

#include <config-gpgme++.h>

#include "editinteractor.h"
#include "callbacks.h"
#include "error.h"

#ifdef HAVE_GPGME_GPG_ERROR_WRAPPERS
#include <gpgme.h>
#else
#include <gpg-error.h>
#endif

#ifdef _WIN32
# include <io.h>
#include <windows.h>
#else
# include <unistd.h>
#endif

#include <cerrno>
#include <cstring>

using namespace GpgME;

static const char *status_to_string(unsigned int status);
static Error status_to_error(unsigned int status);

class EditInteractor::Private
{
    friend class ::GpgME::EditInteractor;
    friend class ::GpgME::CallbackHelper;
    EditInteractor *const q;
public:
    explicit Private(EditInteractor *qq);
    ~Private();

private:
    unsigned int state;
    Error error;
    std::FILE *debug;
};

class GpgME::CallbackHelper
{
private:
    static int writeAll(int fd, const void *buf, size_t count)
    {
        size_t toWrite = count;
        while (toWrite > 0) {
#ifdef HAVE_GPGME_IO_READWRITE
            const int n = gpgme_io_write(fd, buf, toWrite);
#else
# ifdef Q_OS_WIN
            DWORD n;
            if (!WriteFile((HANDLE)fd, buf, toWrite, &n, NULL)) {
                return -1;
            }
# else
            const int n = write(fd, buf, toWrite);
# endif
#endif
            if (n < 0) {
                return n;
            }
            toWrite -= n;
        }
        return count;
    }

public:
    static int edit_interactor_callback_impl(void *opaque, gpgme_status_code_t status, const char *args, int fd)
    {
        EditInteractor::Private *ei = (EditInteractor::Private *)opaque;

        Error err = status_to_error(status);

        if (!err) {

            // advance to next state based on input:
            const unsigned int oldState = ei->state;
            ei->state = ei->q->nextState(status, args, err);
            if (ei->debug) {
                std::fprintf(ei->debug, "EditInteractor: %u -> nextState( %s, %s ) -> %u\n",
                             oldState, status_to_string(status), args ? args : "<null>", ei->state);
            }
            if (err) {
                ei->state = oldState;
                goto error;
            }

            if (ei->state != oldState &&
                    // if there was an error from before, we stop here (### this looks weird, can this happen at all?)
                    ei->error.code() == GPG_ERR_NO_ERROR) {

                // successful state change -> call action
                if (const char *const result = ei->q->action(err)) {
                    if (err) {
                        goto error;
                    }
                    if (ei->debug) {
                        std::fprintf(ei->debug, "EditInteractor: action result \"%s\"\n", result);
                    }
                    // if there's a result, write it:
                    if (*result) {
#ifdef HAVE_GPGME_GPG_ERROR_WRAPPERS
                        gpgme_err_set_errno(0);
#else
                        gpg_err_set_errno(0);
#endif
                        const ssize_t len = std::strlen(result);
                        if (writeAll(fd, result, len) != len) {
                            err = Error::fromSystemError();
                            if (ei->debug) {
                                std::fprintf(ei->debug, "EditInteractor: Could not write to fd %d (%s)\n", fd, err.asString());
                            }
                            goto error;
                        }
                    }
#ifdef HAVE_GPGME_GPG_ERROR_WRAPPERS
                    gpgme_err_set_errno(0);
#else
                    gpg_err_set_errno(0);
#endif
                    if (writeAll(fd, "\n", 1) != 1) {
                        err = Error::fromSystemError();
                        if (ei->debug) {
                            std::fprintf(ei->debug, "EditInteractor: Could not write to fd %d (%s)\n", fd, err.asString());
                        }
                        goto error;
                    }
                } else {
                    if (err) {
                        goto error;
                    }
                    if (ei->debug) {
                        std::fprintf(ei->debug, "EditInteractor: no action result\n");
                    }
                }
            } else {
                if (ei->debug) {
                    std::fprintf(ei->debug, "EditInteractor: no action executed\n");
                }
            }
        }

    error:
        if (err) {
            ei->error = err;
            ei->state = EditInteractor::ErrorState;
        }

        if (ei->debug) {
            std::fprintf(ei->debug, "EditInteractor: error now %u (%s)\n",
                         ei->error.encodedError(), gpgme_strerror(ei->error.encodedError()));
        }

        return ei->error.encodedError();
    }
};

static gpgme_error_t edit_interactor_callback(void *opaque, gpgme_status_code_t status, const char *args, int fd)
{
    return CallbackHelper::edit_interactor_callback_impl(opaque, status, args, fd);
}

const gpgme_edit_cb_t GpgME::edit_interactor_callback = ::edit_interactor_callback;

EditInteractor::Private::Private(EditInteractor *qq)
    : q(qq),
      state(StartState),
      error(),
      debug(0)
{

}

EditInteractor::Private::~Private() {}

EditInteractor::EditInteractor()
    : d(new Private(this))
{

}

EditInteractor::~EditInteractor()
{
    delete d;
}

unsigned int EditInteractor::state() const
{
    return d->state;
}

Error EditInteractor::lastError() const
{
    return d->error;
}

bool EditInteractor::needsNoResponse(unsigned int status) const
{
    switch (status) {
    case GPGME_STATUS_EOF:
    case GPGME_STATUS_GOT_IT:
    case GPGME_STATUS_NEED_PASSPHRASE:
    case GPGME_STATUS_NEED_PASSPHRASE_SYM:
    case GPGME_STATUS_GOOD_PASSPHRASE:
    case GPGME_STATUS_BAD_PASSPHRASE:
    case GPGME_STATUS_USERID_HINT:
    case GPGME_STATUS_SIGEXPIRED:
    case GPGME_STATUS_KEYEXPIRED:
        return true;
    default:
        return false;
    }
}

// static
Error status_to_error(unsigned int status)
{
    switch (status) {
    case GPGME_STATUS_MISSING_PASSPHRASE:
        return Error::fromCode(GPG_ERR_NO_PASSPHRASE);
    case GPGME_STATUS_ALREADY_SIGNED:
        return Error::fromCode(GPG_ERR_ALREADY_SIGNED);
    case GPGME_STATUS_KEYEXPIRED:
        return Error::fromCode(GPG_ERR_CERT_EXPIRED);
    case GPGME_STATUS_SIGEXPIRED:
        return Error::fromCode(GPG_ERR_SIG_EXPIRED);
    }
    return Error();
}

void EditInteractor::setDebugChannel(std::FILE *debug)
{
    d->debug = debug;
}

static const char *const status_strings[] = {
    "EOF",
    /* mkstatus processing starts here */
    "ENTER",
    "LEAVE",
    "ABORT",

    "GOODSIG",
    "BADSIG",
    "ERRSIG",

    "BADARMOR",

    "RSA_OR_IDEA",
    "KEYEXPIRED",
    "KEYREVOKED",

    "TRUST_UNDEFINED",
    "TRUST_NEVER",
    "TRUST_MARGINAL",
    "TRUST_FULLY",
    "TRUST_ULTIMATE",

    "SHM_INFO",
    "SHM_GET",
    "SHM_GET_BOOL",
    "SHM_GET_HIDDEN",

    "NEED_PASSPHRASE",
    "VALIDSIG",
    "SIG_ID",
    "ENC_TO",
    "NODATA",
    "BAD_PASSPHRASE",
    "NO_PUBKEY",
    "NO_SECKEY",
    "NEED_PASSPHRASE_SYM",
    "DECRYPTION_FAILED",
    "DECRYPTION_OKAY",
    "MISSING_PASSPHRASE",
    "GOOD_PASSPHRASE",
    "GOODMDC",
    "BADMDC",
    "ERRMDC",
    "IMPORTED",
    "IMPORT_OK",
    "IMPORT_PROBLEM",
    "IMPORT_RES",
    "FILE_START",
    "FILE_DONE",
    "FILE_ERROR",

    "BEGIN_DECRYPTION",
    "END_DECRYPTION",
    "BEGIN_ENCRYPTION",
    "END_ENCRYPTION",

    "DELETE_PROBLEM",
    "GET_BOOL",
    "GET_LINE",
    "GET_HIDDEN",
    "GOT_IT",
    "PROGRESS",
    "SIG_CREATED",
    "SESSION_KEY",
    "NOTATION_NAME",
    "NOTATION_DATA",
    "POLICY_URL",
    "BEGIN_STREAM",
    "END_STREAM",
    "KEY_CREATED",
    "USERID_HINT",
    "UNEXPECTED",
    "INV_RECP",
    "NO_RECP",
    "ALREADY_SIGNED",
    "SIGEXPIRED",
    "EXPSIG",
    "EXPKEYSIG",
    "TRUNCATED",
    "ERROR",
    "NEWSIG",
    "REVKEYSIG",
    "SIG_SUBPACKET",
    "NEED_PASSPHRASE_PIN",
    "SC_OP_FAILURE",
    "SC_OP_SUCCESS",
    "CARDCTRL",
    "BACKUP_KEY_CREATED",
    "PKA_TRUST_BAD",
    "PKA_TRUST_GOOD",

    "PLAINTEXT",
};
static const unsigned int num_status_strings = sizeof status_strings / sizeof * status_strings ;

const char *status_to_string(unsigned int idx)
{
    if (idx < num_status_strings) {
        return status_strings[idx];
    } else {
        return "(unknown)";
    }
}
