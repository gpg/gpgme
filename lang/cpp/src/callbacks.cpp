/*
  callbacks.cpp - callback targets for internal use:
  Copyright (C) 2003,2004 Klarälvdalens Datakonsult AB
  2016 Bundesamt für Sicherheit in der Informationstechnik
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

#include "callbacks.h"
#include "util.h"

#include <interfaces/progressprovider.h>
#include <interfaces/passphraseprovider.h>
#include <interfaces/dataprovider.h>
#include <error.h>

#include <gpgme.h>
#include <gpg-error.h>

#include <cassert>
#include <cerrno>
#include <cstring>
#include <unistd.h>
#include <stdlib.h>

static inline gpgme_error_t make_err_from_syserror()
{
    return gpgme_error_from_syserror();
}

using GpgME::ProgressProvider;
using GpgME::PassphraseProvider;
using GpgME::DataProvider;

void progress_callback(void *opaque, const char *what,
                       int type, int current, int total)
{
    ProgressProvider *provider = static_cast<ProgressProvider *>(opaque);
    if (provider) {
        provider->showProgress(what, type, current, total);
    }
}

/* To avoid that a compiler optimizes certain memset calls away, these
   macros may be used instead. */
#define wipememory2(_ptr,_set,_len) do { \
        volatile char *_vptr=(volatile char *)(_ptr); \
        size_t _vlen=(_len); \
        while(_vlen) { *_vptr=(_set); _vptr++; _vlen--; } \
    } while(0)
#define wipememory(_ptr,_len) wipememory2(_ptr,0,_len)

gpgme_error_t passphrase_callback(void *opaque, const char *uid_hint, const char *desc,
                                  int prev_was_bad, int fd)
{
    PassphraseProvider *provider = static_cast<PassphraseProvider *>(opaque);
    bool canceled = false;
    gpgme_error_t err = GPG_ERR_NO_ERROR;
    char *passphrase = provider ? provider->getPassphrase(uid_hint, desc, prev_was_bad, canceled) : nullptr ;
    if (canceled) {
        err = make_error(GPG_ERR_CANCELED);
    } else {
        if (passphrase && *passphrase) {
            size_t passphrase_length = std::strlen(passphrase);
            size_t written = 0;
            do {
                ssize_t now_written = gpgme_io_write(fd, passphrase + written, passphrase_length - written);
                if (now_written < 0) {
                    err = make_err_from_syserror();
                    break;
                }
                written += now_written;
            } while (written < passphrase_length);
        }
    }

    if (passphrase && *passphrase) {
        wipememory(passphrase, std::strlen(passphrase));
    }
    free(passphrase);
    gpgme_io_write(fd, "\n", 1);
    return err;
}

static gpgme_ssize_t
data_read_callback(void *opaque, void *buf, size_t buflen)
{
    DataProvider *provider = static_cast<DataProvider *>(opaque);
    if (!provider) {
        gpgme_err_set_errno(gpgme_err_code_to_errno(GPG_ERR_EINVAL));
        return -1;
    }
    return (gpgme_ssize_t)provider->read(buf, buflen);
}

static gpgme_ssize_t
data_write_callback(void *opaque, const void *buf, size_t buflen)
{
    DataProvider *provider = static_cast<DataProvider *>(opaque);
    if (!provider) {
        gpgme_err_set_errno(gpgme_err_code_to_errno(GPG_ERR_EINVAL));
        return -1;
    }
    return (gpgme_ssize_t)provider->write(buf, buflen);
}

static gpgme_off_t
data_seek_callback(void *opaque, gpgme_off_t offset, int whence)
{
    DataProvider *provider = static_cast<DataProvider *>(opaque);
    if (!provider) {
        gpgme_err_set_errno(gpgme_err_code_to_errno(GPG_ERR_EINVAL));
        return -1;
    }
    if (whence != SEEK_SET && whence != SEEK_CUR && whence != SEEK_END) {
        gpgme_err_set_errno(gpgme_err_code_to_errno(GPG_ERR_EINVAL));
        return -1;
    }
    return provider->seek((off_t)offset, whence);
}

static void data_release_callback(void *opaque)
{
    DataProvider *provider = static_cast<DataProvider *>(opaque);
    if (provider) {
        provider->release();
    }
}

const gpgme_data_cbs GpgME::data_provider_callbacks = {
    &data_read_callback,
    &data_write_callback,
    &data_seek_callback,
    &data_release_callback
};
