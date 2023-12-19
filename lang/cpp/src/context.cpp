/*
  context.cpp - wraps a gpgme key context
  Copyright (C) 2003, 2007 Klarälvdalens Datakonsult AB
                2017, 2018 Intevation GmbH

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

#include <context.h>
#include <eventloopinteractor.h>
#include <trustitem.h>
#include <keylistresult.h>
#include <keygenerationresult.h>
#include <importresult.h>
#include <decryptionresult.h>
#include <verificationresult.h>
#include <signingresult.h>
#include <encryptionresult.h>
#include <engineinfo.h>
#include <editinteractor.h>
#include <vfsmountresult.h>

#include <interfaces/assuantransaction.h>
#include <defaultassuantransaction.h>

#include "callbacks.h"
#include "data_p.h"
#include "context_p.h"
#include "util.h"
#include "tofuinfo.h"

#include <gpgme.h>

#include <functional>
#include <istream>
#include <numeric>
#ifndef NDEBUG
#include <iostream>
using std::cerr;
using std::endl;
#endif

#include <cassert>

namespace GpgME
{

static inline unsigned int xtoi_1(const char *str)
{
    const unsigned int ch = *str;
    const unsigned int result =
        ch <= '9' ? ch - '0' :
        ch <= 'F' ? ch - 'A' + 10 :
        /* else */  ch - 'a' + 10 ;
    return result < 16 ? result : 0 ;
}
static inline int xtoi_2(const char *str)
{
    return xtoi_1(str) * 16U + xtoi_1(str + 1);
}

static void percent_unescape(std::string &s, bool plus2space)
{
    std::string::iterator src = s.begin(), dest = s.begin(), end = s.end();
    while (src != end) {
        if (*src == '%' && end - src > 2) {
            *dest++ = xtoi_2(&*++src);
            src += 2;
        } else if (*src == '+' && plus2space) {
            *dest++ = ' ';
            ++src;
        } else {
            *dest++ = *src++;
        }
    }
    s.erase(dest, end);
}

void initializeLibrary()
{
    gpgme_check_version(nullptr);
}

Error initializeLibrary(int)
{
    if (gpgme_check_version(GPGME_VERSION)) {
        return Error();
    } else {
        return Error::fromCode(GPG_ERR_USER_1);
    }
}

static void format_error(gpgme_error_t err, std::string &str)
{
    char buffer[ 1024 ];
    gpgme_strerror_r(err, buffer, sizeof buffer);
    buffer[ sizeof buffer - 1 ] = '\0';
    str = buffer;
}

const char *Error::source() const
{
    return gpgme_strsource((gpgme_error_t)mErr);
}

const char *Error::asString() const
{
    if (mMessage.empty()) {
        format_error(static_cast<gpgme_error_t>(mErr), mMessage);
    }
    return mMessage.c_str();
}

int Error::code() const
{
    return gpgme_err_code(mErr);
}

int Error::sourceID() const
{
    return gpgme_err_source(mErr);
}

bool Error::isCanceled() const
{
    return code() == GPG_ERR_CANCELED || code() == GPG_ERR_FULLY_CANCELED;
}

int Error::toErrno() const
{
//#ifdef HAVE_GPGME_GPG_ERROR_WRAPPERS
    return gpgme_err_code_to_errno(static_cast<gpgme_err_code_t>(code()));
//#else
//    return gpg_err_code_to_errno( static_cast<gpg_err_code_t>( code() ) );
//#endif
}

// static
bool Error::hasSystemError()
{
    return gpgme_err_code_from_syserror() != GPG_ERR_MISSING_ERRNO ;
}

// static
void Error::setSystemError(gpg_err_code_t err)
{
    setErrno(gpgme_err_code_to_errno(err));
}

// static
void Error::setErrno(int err)
{
    gpgme_err_set_errno(err);
}

// static
Error Error::fromSystemError(unsigned int src)
{
    return Error(gpgme_err_make(static_cast<gpgme_err_source_t>(src), gpgme_err_code_from_syserror()));
}

// static
Error Error::fromErrno(int err, unsigned int src)
{
    return Error(gpgme_err_make(static_cast<gpgme_err_source_t>(src), gpgme_err_code_from_errno(err)));
}

// static
Error Error::fromCode(unsigned int err, unsigned int src)
{
    return Error(gpgme_err_make(static_cast<gpgme_err_source_t>(src), static_cast<gpgme_err_code_t>(err)));
}

std::ostream &operator<<(std::ostream &os, const Error &err)
{
    return os << "GpgME::Error(" << err.encodedError() << " (" << err.asString() << "))";
}

Context::KeyListModeSaver::KeyListModeSaver(Context *ctx)
    : mCtx{ctx}
    , mKeyListMode{ctx ? ctx->keyListMode() : 0}
{
}

Context::KeyListModeSaver::~KeyListModeSaver()
{
    if (mCtx) {
        mCtx->setKeyListMode(mKeyListMode);
    }
}

Context::Context(gpgme_ctx_t ctx) : d(new Private(ctx))
{
}

Context::~Context()
{
    delete d;
}

Context *Context::createForProtocol(Protocol proto)
{
    gpgme_ctx_t ctx = nullptr;
    if (gpgme_new(&ctx) != 0) {
        return nullptr;
    }

    switch (proto) {
    case OpenPGP:
        if (gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP) != 0) {
            gpgme_release(ctx);
            return nullptr;
        }
        break;
    case CMS:
        if (gpgme_set_protocol(ctx, GPGME_PROTOCOL_CMS) != 0) {
            gpgme_release(ctx);
            return nullptr;
        }
        break;
    default:
        return nullptr;
    }

    return new Context(ctx);
}

std::unique_ptr<Context> Context::create(Protocol proto)
{
  return std::unique_ptr <Context> (createForProtocol(proto));
}

std::unique_ptr<Context> Context::createForEngine(Engine eng, Error *error)
{
    gpgme_ctx_t ctx = nullptr;
    if (const gpgme_error_t err = gpgme_new(&ctx)) {
        if (error) {
            *error = Error(err);
        }
        return std::unique_ptr<Context>();
    }

    switch (eng) {
    case AssuanEngine:
        if (const gpgme_error_t err = gpgme_set_protocol(ctx, GPGME_PROTOCOL_ASSUAN)) {
            gpgme_release(ctx);
            if (error) {
                *error = Error(err);
            }
            return std::unique_ptr<Context>();
        }
        break;
    case G13Engine:
        if (const gpgme_error_t err = gpgme_set_protocol(ctx, GPGME_PROTOCOL_G13)) {
            gpgme_release(ctx);
            if (error) {
                *error = Error(err);
            }
            return std::unique_ptr<Context>();
        }
        break;
    case SpawnEngine:
        if (const gpgme_error_t err = gpgme_set_protocol(ctx, GPGME_PROTOCOL_SPAWN)) {
            gpgme_release(ctx);
            if (error) {
                *error = Error(err);
            }
            return std::unique_ptr<Context>();
        }
        break;
    default:
        if (error) {
            *error = Error::fromCode(GPG_ERR_INV_ARG);
        }
        return std::unique_ptr<Context>();
    }

    if (error) {
        *error = Error();
    }

    return std::unique_ptr<Context>(new Context(ctx));
}

void Context::setDecryptionFlags(DecryptionFlags flags)
{
    d->decryptFlags = flags;
}

//
//
// Context::Private
//
//

Context::Private::Private(gpgme_ctx_t c)
    : ctx(c),
      iocbs(nullptr),
      lastop(None),
      lasterr(GPG_ERR_NO_ERROR),
      lastAssuanInquireData(Data::null),
      lastAssuanTransaction(),
      lastEditInteractor(),
      lastCardEditInteractor(),
      decryptFlags(DecryptNone)
{

}

Context::Private::~Private()
{
    if (ctx) {
        gpgme_release(ctx);
    }
    ctx = nullptr;
    delete iocbs;
}

//
//
// Context attributes:
//
//

Protocol Context::protocol() const
{
    gpgme_protocol_t p = gpgme_get_protocol(d->ctx);
    switch (p) {
    case GPGME_PROTOCOL_OpenPGP: return OpenPGP;
    case GPGME_PROTOCOL_CMS:     return CMS;
    default:                     return UnknownProtocol;
    }
}

void Context::setArmor(bool useArmor)
{
    gpgme_set_armor(d->ctx, int(useArmor));
}
bool Context::armor() const
{
    return gpgme_get_armor(d->ctx);
}

void Context::setTextMode(bool useTextMode)
{
    gpgme_set_textmode(d->ctx, int(useTextMode));
}
bool Context::textMode() const
{
    return gpgme_get_textmode(d->ctx);
}

void Context::setOffline(bool useOfflineMode)
{
    gpgme_set_offline(d->ctx, int(useOfflineMode));
}
bool Context::offline() const
{
    return gpgme_get_offline(d->ctx);
}

void Context::setIncludeCertificates(int which)
{
    if (which == DefaultCertificates) {
        which = GPGME_INCLUDE_CERTS_DEFAULT;
    }
    gpgme_set_include_certs(d->ctx, which);
}

int Context::includeCertificates() const
{
    return gpgme_get_include_certs(d->ctx);
}

void Context::setKeyListMode(unsigned int mode)
{
    gpgme_set_keylist_mode(d->ctx, add_to_gpgme_keylist_mode_t(0, mode));
}

void Context::addKeyListMode(unsigned int mode)
{
    const unsigned int cur = gpgme_get_keylist_mode(d->ctx);
    gpgme_set_keylist_mode(d->ctx, add_to_gpgme_keylist_mode_t(cur, mode));
}

unsigned int Context::keyListMode() const
{
    return convert_from_gpgme_keylist_mode_t(gpgme_get_keylist_mode(d->ctx));
}

void Context::setProgressProvider(ProgressProvider *provider)
{
    gpgme_set_progress_cb(d->ctx, provider ? &progress_callback : nullptr, provider);
}
ProgressProvider *Context::progressProvider() const
{
    void *pp = nullptr;
    gpgme_progress_cb_t pcb = &progress_callback;
    gpgme_get_progress_cb(d->ctx, &pcb, &pp);
    return static_cast<ProgressProvider *>(pp);
}

void Context::setPassphraseProvider(PassphraseProvider *provider)
{
    gpgme_set_passphrase_cb(d->ctx, provider ? &passphrase_callback : nullptr, provider);
}

PassphraseProvider *Context::passphraseProvider() const
{
    void *pp = nullptr;
    gpgme_passphrase_cb_t pcb = &passphrase_callback;
    gpgme_get_passphrase_cb(d->ctx, &pcb, &pp);
    return static_cast<PassphraseProvider *>(pp);
}

void Context::setManagedByEventLoopInteractor(bool manage)
{
    if (!EventLoopInteractor::instance()) {
#ifndef NDEBUG
        cerr << "Context::setManagedByEventLoopInteractor(): "
             "You must create an instance of EventLoopInteractor "
             "before using anything that needs one." << endl;
#endif
        return;
    }
    if (manage) {
        EventLoopInteractor::instance()->manage(this);
    } else {
        EventLoopInteractor::instance()->unmanage(this);
    }
}
bool Context::managedByEventLoopInteractor() const
{
    return d->iocbs != nullptr;
}

void Context::installIOCallbacks(gpgme_io_cbs *iocbs)
{
    if (!iocbs) {
        uninstallIOCallbacks();
        return;
    }
    gpgme_set_io_cbs(d->ctx, iocbs);
    delete d->iocbs; d->iocbs = iocbs;
}

void Context::uninstallIOCallbacks()
{
    static gpgme_io_cbs noiocbs = { nullptr, nullptr, nullptr, nullptr, nullptr };
    // io.add == 0 means disable io callbacks:
    gpgme_set_io_cbs(d->ctx, &noiocbs);
    delete d->iocbs; d->iocbs = nullptr;
}

Error Context::setLocale(int cat, const char *val)
{
    return Error(d->lasterr = gpgme_set_locale(d->ctx, cat, val));
}

static GpgME::EngineInfo get_engine_info(gpgme_engine_info_t engineInfos, gpgme_protocol_t protocol)
{
    if (!engineInfos) {
        return EngineInfo{};
    }

    for (gpgme_engine_info_t i = engineInfos ; i ; i = i->next) {
        if (i->protocol == protocol) {
            return EngineInfo{i};
        }
    }

    return EngineInfo{};
}

static GpgME::EngineInfo get_static_engine_info(gpgme_protocol_t protocol)
{
    gpgme_engine_info_t ei = nullptr;
    if (gpgme_get_engine_info(&ei)) {
        return EngineInfo{};
    }
    return get_engine_info(ei, protocol);
}

EngineInfo Context::engineInfo() const
{
    return get_engine_info(gpgme_ctx_get_engine_info(d->ctx), gpgme_get_protocol(d->ctx));
}

Error Context::setEngineFileName(const char *filename)
{
    const char *const home_dir = engineInfo().homeDirectory();
    return Error(gpgme_ctx_set_engine_info(d->ctx, gpgme_get_protocol(d->ctx), filename, home_dir));
}

Error Context::setEngineHomeDirectory(const char *home_dir)
{
    const char *const filename = engineInfo().fileName();
    return Error(gpgme_ctx_set_engine_info(d->ctx, gpgme_get_protocol(d->ctx), filename, home_dir));
}

Error Context::setSender (const char *sender)
{
    return Error(gpgme_set_sender(d->ctx, sender));
}

const char *Context::getSender ()
{
    return gpgme_get_sender(d->ctx);
}

//
//
// Key Management
//
//

Error Context::startKeyListing(const char *pattern, bool secretOnly)
{
    d->lastop = (((keyListMode() & GpgME::Locate) == GpgME::Locate)
                 ? Private::KeyListWithImport
                 : Private::KeyList);
    return Error(d->lasterr = gpgme_op_keylist_start(d->ctx, pattern, int(secretOnly)));
}

Error Context::startKeyListing(const char *patterns[], bool secretOnly)
{
    d->lastop = (((keyListMode() & GpgME::Locate) == GpgME::Locate)
                 ? Private::KeyListWithImport
                 : Private::KeyList);
    return Error(d->lasterr = gpgme_op_keylist_ext_start(d->ctx, patterns, int(secretOnly), 0));
}

Key Context::nextKey(GpgME::Error &e)
{
    d->lastop = (((keyListMode() & GpgME::Locate) == GpgME::Locate)
                 ? Private::KeyListWithImport
                 : Private::KeyList);
    gpgme_key_t key = nullptr;
    e = Error(d->lasterr = gpgme_op_keylist_next(d->ctx, &key));
    return Key(key, false);
}

KeyListResult Context::endKeyListing()
{
    d->lasterr = gpgme_op_keylist_end(d->ctx);
    return keyListResult();
}

KeyListResult Context::keyListResult() const
{
    return KeyListResult(d->ctx, Error(d->lasterr));
}

Key Context::key(const char *fingerprint, GpgME::Error &e , bool secret /*, bool forceUpdate*/)
{
    d->lastop = Private::KeyList;
    gpgme_key_t key = nullptr;
    e = Error(d->lasterr = gpgme_get_key(d->ctx, fingerprint, &key, int(secret)/*, int( forceUpdate )*/));
    return Key(key, false);
}

KeyGenerationResult Context::generateKey(const char *parameters, Data &pubKey)
{
    d->lastop = Private::KeyGen;
    Data::Private *const dp = pubKey.impl();
    d->lasterr = gpgme_op_genkey(d->ctx, parameters, dp ? dp->data : nullptr, nullptr);
    return KeyGenerationResult(d->ctx, Error(d->lasterr));
}

Error Context::startKeyGeneration(const char *parameters, Data &pubKey)
{
    d->lastop = Private::KeyGen;
    Data::Private *const dp = pubKey.impl();
    return Error(d->lasterr = gpgme_op_genkey_start(d->ctx, parameters, dp ? dp->data : nullptr, nullptr));
}

KeyGenerationResult Context::keyGenerationResult() const
{
    if (d->lastop & Private::KeyGen) {
        return KeyGenerationResult(d->ctx, Error(d->lasterr));
    } else {
        return KeyGenerationResult();
    }
}

Error Context::exportKeys(const char *pattern, Data &keyData, unsigned int mode)
{
    d->lastop = Private::Export;
    Data::Private *const dp = keyData.impl();
    return Error(d->lasterr = gpgme_op_export(d->ctx, pattern, mode, dp ? dp->data : nullptr));
}

Error Context::exportKeys(const char *patterns[], Data &keyData, unsigned int mode)
{
    d->lastop = Private::Export;
    Data::Private *const dp = keyData.impl();
    return Error(d->lasterr = gpgme_op_export_ext(d->ctx, patterns, mode, dp ? dp->data : nullptr));
}

Error Context::startKeyExport(const char *pattern, Data &keyData, unsigned int mode)
{
    d->lastop = Private::Export;
    Data::Private *const dp = keyData.impl();
    return Error(d->lasterr = gpgme_op_export_start(d->ctx, pattern, mode, dp ? dp->data : nullptr));
}

Error Context::startKeyExport(const char *patterns[], Data &keyData, unsigned int mode)
{
    d->lastop = Private::Export;
    Data::Private *const dp = keyData.impl();
    return Error(d->lasterr = gpgme_op_export_ext_start(d->ctx, patterns, mode, dp ? dp->data : nullptr));
}

Error Context::exportPublicKeys(const char *pattern, Data &keyData, unsigned int mode)
{
    if (mode & (ExportSecret | ExportSecretSubkey)) {
        return Error::fromCode(GPG_ERR_INV_FLAG);
    }
    return exportKeys(pattern, keyData, mode);
}

Error Context::exportPublicKeys(const char *patterns[], Data &keyData, unsigned int mode)
{
    if (mode & (ExportSecret | ExportSecretSubkey)) {
        return Error::fromCode(GPG_ERR_INV_FLAG);
    }
    return exportKeys(patterns, keyData, mode);
}

Error Context::startPublicKeyExport(const char *pattern, Data &keyData, unsigned int mode)
{
    if (mode & (ExportSecret | ExportSecretSubkey)) {
        return Error::fromCode(GPG_ERR_INV_FLAG);
    }
    return startKeyExport(pattern, keyData, mode);
}

Error Context::startPublicKeyExport(const char *patterns[], Data &keyData, unsigned int mode)
{
    if (mode & (ExportSecret | ExportSecretSubkey)) {
        return Error::fromCode(GPG_ERR_INV_FLAG);
    }
    return startKeyExport(patterns, keyData, mode);
}

/* Same as above but without mode  */
Error Context::exportPublicKeys(const char *pattern, Data &keyData)
{
    return exportPublicKeys(pattern, keyData, 0);
}

Error Context::exportPublicKeys(const char *patterns[], Data &keyData)
{
    return exportPublicKeys(patterns, keyData, 0);
}

Error Context::startPublicKeyExport(const char *pattern, Data &keyData)
{
    return startPublicKeyExport(pattern, keyData, 0);
}

Error Context::startPublicKeyExport(const char *patterns[], Data &keyData)
{
    return startPublicKeyExport(patterns, keyData, 0);
}

Error Context::exportSecretKeys(const char *pattern, Data &keyData, unsigned int mode)
{
    if (mode & ExportSecretSubkey) {
        return Error::fromCode(GPG_ERR_INV_FLAG);
    }
    return exportKeys(pattern, keyData, mode|ExportSecret);
}

Error Context::exportSecretKeys(const char *patterns[], Data &keyData, unsigned int mode)
{
    if (mode & ExportSecretSubkey) {
        return Error::fromCode(GPG_ERR_INV_FLAG);
    }
    return exportKeys(patterns, keyData, mode|ExportSecret);
}

Error Context::startSecretKeyExport(const char *pattern, Data &keyData, unsigned int mode)
{
    if (mode & ExportSecretSubkey) {
        return Error::fromCode(GPG_ERR_INV_FLAG);
    }
    return startKeyExport(pattern, keyData, mode|ExportSecret);
}

Error Context::startSecretKeyExport(const char *patterns[], Data &keyData, unsigned int mode)
{
    if (mode & ExportSecretSubkey) {
        return Error::fromCode(GPG_ERR_INV_FLAG);
    }
    return startKeyExport(patterns, keyData, mode|ExportSecret);
}

Error Context::exportSecretSubkeys(const char *pattern, Data &keyData, unsigned int mode)
{
    return exportKeys(pattern, keyData, mode|ExportSecretSubkey);
}

Error Context::exportSecretSubkeys(const char *patterns[], Data &keyData, unsigned int mode)
{
    return exportKeys(patterns, keyData, mode|ExportSecretSubkey);
}

Error Context::startSecretSubkeyExport(const char *pattern, Data &keyData, unsigned int mode)
{
    return startKeyExport(pattern, keyData, mode|ExportSecretSubkey);
}

Error Context::startSecretSubkeyExport(const char *patterns[], Data &keyData, unsigned int mode)
{
    return startKeyExport(patterns, keyData, mode|ExportSecretSubkey);
}

ImportResult Context::importKeys(const Data &data)
{
    d->lastop = Private::Import;
    const Data::Private *const dp = data.impl();
    d->lasterr = gpgme_op_import(d->ctx, dp ? dp->data : nullptr);
    return ImportResult(d->ctx, Error(d->lasterr));
}

ImportResult Context::importKeys(const std::vector<Key> &kk)
{
    d->lastop = Private::Import;
    d->lasterr = make_error(GPG_ERR_NOT_IMPLEMENTED);

    bool shouldHaveResult = false;
    gpgme_key_t * const keys = new gpgme_key_t[ kk.size() + 1 ];
    gpgme_key_t *keys_it = &keys[0];
    for (std::vector<Key>::const_iterator it = kk.begin(), end = kk.end() ; it != end ; ++it) {
        if (it->impl()) {
            *keys_it++ = it->impl();
        }
    }
    *keys_it++ = nullptr;
    d->lasterr = gpgme_op_import_keys(d->ctx, keys);
    shouldHaveResult = true;
    if ((gpgme_err_code(d->lasterr) == GPG_ERR_NOT_IMPLEMENTED ||
            gpgme_err_code(d->lasterr) == GPG_ERR_NOT_SUPPORTED) &&
            protocol() == CMS) {
        // ok, try the workaround (export+import):
        std::vector<const char *> fprs;
        for (std::vector<Key>::const_iterator it = kk.begin(), end = kk.end() ; it != end ; ++it) {
            if (const char *fpr = it->primaryFingerprint()) {
                if (*fpr) {
                    fprs.push_back(fpr);
                }
            } else if (const char *keyid = it->keyID()) {
                if (*keyid) {
                    fprs.push_back(keyid);
                }
            }
        }
        fprs.push_back(nullptr);
        Data data;
        Data::Private *const dp = data.impl();
        const gpgme_keylist_mode_t oldMode = gpgme_get_keylist_mode(d->ctx);
        gpgme_set_keylist_mode(d->ctx, GPGME_KEYLIST_MODE_EXTERN);
        d->lasterr = gpgme_op_export_ext(d->ctx, &fprs[0], 0, dp ? dp->data : nullptr);
        gpgme_set_keylist_mode(d->ctx, oldMode);
        if (!d->lasterr) {
            data.seek(0, SEEK_SET);
            d->lasterr = gpgme_op_import(d->ctx, dp ? dp->data : nullptr);
            shouldHaveResult = true;
        }
    }
    delete[] keys;
    if (shouldHaveResult) {
        return ImportResult(d->ctx, Error(d->lasterr));
    } else {
        return ImportResult(Error(d->lasterr));
    }
}

Error Context::startKeyImport(const Data &data)
{
    d->lastop = Private::Import;
    const Data::Private *const dp = data.impl();
    return Error(d->lasterr = gpgme_op_import_start(d->ctx, dp ? dp->data : nullptr));
}

Error Context::startKeyImport(const std::vector<Key> &kk)
{
    d->lastop = Private::Import;
    gpgme_key_t * const keys = new gpgme_key_t[ kk.size() + 1 ];
    gpgme_key_t *keys_it = &keys[0];
    for (std::vector<Key>::const_iterator it = kk.begin(), end = kk.end() ; it != end ; ++it) {
        if (it->impl()) {
            *keys_it++ = it->impl();
        }
    }
    *keys_it++ = nullptr;
    Error err = Error(d->lasterr = gpgme_op_import_keys_start(d->ctx, keys));
    delete[] keys;
    return err;
}

ImportResult Context::importKeys(const std::vector<std::string> &keyIds)
{
    d->lastop = Private::Import;
    const StringsToCStrings keyids{keyIds};
    d->lasterr = gpgme_op_receive_keys(d->ctx, keyids.c_strs());
    return ImportResult(d->ctx, Error(d->lasterr));
}

Error Context::startKeyImport(const std::vector<std::string> &keyIds)
{
    d->lastop = Private::Import;
    const StringsToCStrings keyids{keyIds};
    d->lasterr = gpgme_op_receive_keys_start(d->ctx, keyids.c_strs());
    return Error(d->lasterr);
}

ImportResult Context::importResult() const
{
    if (d->lastop & Private::Import) {
        return ImportResult(d->ctx, Error(d->lasterr));
    } else {
        return ImportResult();
    }
}

Error Context::deleteKey(const Key &key, bool allowSecretKeyDeletion)
{
    d->lastop = Private::Delete;
    return Error(d->lasterr = gpgme_op_delete(d->ctx, key.impl(), int(allowSecretKeyDeletion)));
}

Error Context::startKeyDeletion(const Key &key, bool allowSecretKeyDeletion)
{
    d->lastop = Private::Delete;
    return Error(d->lasterr = gpgme_op_delete_start(d->ctx, key.impl(), int(allowSecretKeyDeletion)));
}

Error Context::passwd(const Key &key)
{
    d->lastop = Private::Passwd;
    return Error(d->lasterr = gpgme_op_passwd(d->ctx, key.impl(), 0U));
}

Error Context::startPasswd(const Key &key)
{
    d->lastop = Private::Passwd;
    return Error(d->lasterr = gpgme_op_passwd_start(d->ctx, key.impl(), 0U));
}


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

Error Context::edit(const Key &key, std::unique_ptr<EditInteractor> func, Data &data)
{
    d->lastop = Private::Edit;
    d->lastEditInteractor = std::move(func);
    Data::Private *const dp = data.impl();
    return Error(d->lasterr = gpgme_op_edit(d->ctx, key.impl(),
                                            d->lastEditInteractor.get() ? edit_interactor_callback : nullptr,
                                            d->lastEditInteractor.get() ? d->lastEditInteractor->d : nullptr,
                                            dp ? dp->data : nullptr));
}


Error Context::startEditing(const Key &key, std::unique_ptr<EditInteractor> func, Data &data)
{
    d->lastop = Private::Edit;
    d->lastEditInteractor = std::move(func);
    Data::Private *const dp = data.impl();
    return Error(d->lasterr = gpgme_op_edit_start(d->ctx, key.impl(),
                              d->lastEditInteractor.get() ? edit_interactor_callback : nullptr,
                              d->lastEditInteractor.get() ? d->lastEditInteractor->d : nullptr,
                              dp ? dp->data : nullptr));
}


EditInteractor *Context::lastEditInteractor() const
{
    return d->lastEditInteractor.get();
}

std::unique_ptr<EditInteractor> Context::takeLastEditInteractor()
{
    return std::move(d->lastEditInteractor);
}


Error Context::cardEdit(const Key &key, std::unique_ptr<EditInteractor> func, Data &data)
{
    d->lastop = Private::CardEdit;
    d->lastCardEditInteractor = std::move(func);
    Data::Private *const dp = data.impl();
    return Error(d->lasterr = gpgme_op_card_edit(d->ctx, key.impl(),
                              d->lastCardEditInteractor.get() ? edit_interactor_callback : nullptr,
                              d->lastCardEditInteractor.get() ? d->lastCardEditInteractor->d : nullptr,
                              dp ? dp->data : nullptr));
}

Error Context::startCardEditing(const Key &key, std::unique_ptr<EditInteractor> func, Data &data)
{
    d->lastop = Private::CardEdit;
    d->lastCardEditInteractor = std::move(func);
    Data::Private *const dp = data.impl();
    return Error(d->lasterr = gpgme_op_card_edit_start(d->ctx, key.impl(),
                              d->lastCardEditInteractor.get() ? edit_interactor_callback : nullptr,
                              d->lastCardEditInteractor.get() ? d->lastCardEditInteractor->d : nullptr,
                              dp ? dp->data : nullptr));
}

#pragma GCC diagnostic pop

EditInteractor *Context::lastCardEditInteractor() const
{
    return d->lastCardEditInteractor.get();
}

std::unique_ptr<EditInteractor> Context::takeLastCardEditInteractor()
{
    return std::move(d->lastCardEditInteractor);
}

Error Context::startTrustItemListing(const char *pattern, int maxLevel)
{
    d->lastop = Private::TrustList;
    return Error(d->lasterr = gpgme_op_trustlist_start(d->ctx, pattern, maxLevel));
}

TrustItem Context::nextTrustItem(Error &e)
{
    gpgme_trust_item_t ti = nullptr;
    e = Error(d->lasterr = gpgme_op_trustlist_next(d->ctx, &ti));
    return TrustItem(ti);
}

Error Context::endTrustItemListing()
{
    return Error(d->lasterr = gpgme_op_trustlist_end(d->ctx));
}

static gpgme_error_t assuan_transaction_data_callback(void *opaque, const void *data, size_t datalen)
{
    assert(opaque);
    AssuanTransaction *t = static_cast<AssuanTransaction *>(opaque);
    return t->data(static_cast<const char *>(data), datalen).encodedError();
}

static gpgme_error_t assuan_transaction_inquire_callback(void *opaque, const char *name, const char *args, gpgme_data_t *r_data)
{
    assert(opaque);
    Context::Private *p = static_cast<Context::Private *>(opaque);
    AssuanTransaction *t = p->lastAssuanTransaction.get();
    assert(t);
    Error err;
    if (name) {
        p->lastAssuanInquireData = t->inquire(name, args, err);
    } else {
        p->lastAssuanInquireData = Data::null;
    }
    if (!p->lastAssuanInquireData.isNull()) {
        *r_data = p->lastAssuanInquireData.impl()->data;
    }
    return err.encodedError();
}

static gpgme_error_t assuan_transaction_status_callback(void *opaque, const char *status, const char *args)
{
    assert(opaque);
    AssuanTransaction *t = static_cast<AssuanTransaction *>(opaque);
    std::string a = args;
    percent_unescape(a, true);   // ### why doesn't gpgme do this??
    return t->status(status, a.c_str()).encodedError();
}

Error Context::assuanTransact(const char *command)
{
    return assuanTransact(command, std::unique_ptr<AssuanTransaction>(new DefaultAssuanTransaction));
}

Error Context::assuanTransact(const char *command, std::unique_ptr<AssuanTransaction> transaction)
{
    gpgme_error_t err, operr;

    d->lastop = Private::AssuanTransact;
    d->lastAssuanTransaction = std::move(transaction);
    if (!d->lastAssuanTransaction.get()) {
        return Error(d->lasterr = make_error(GPG_ERR_INV_ARG));
    }
    err = gpgme_op_assuan_transact_ext
      (d->ctx,
       command,
       assuan_transaction_data_callback,
       d->lastAssuanTransaction.get(),
       assuan_transaction_inquire_callback,
       d,
       assuan_transaction_status_callback,
       d->lastAssuanTransaction.get(),
       &operr);

    if (!err)
      err = operr;
    d->lasterr = err;

    return Error(d->lasterr);
}

Error Context::startAssuanTransaction(const char *command)
{
    return startAssuanTransaction(command, std::unique_ptr<AssuanTransaction>(new DefaultAssuanTransaction));
}

Error Context::startAssuanTransaction(const char *command, std::unique_ptr<AssuanTransaction> transaction)
{
    gpgme_error_t err;

    d->lastop = Private::AssuanTransact;
    d->lastAssuanTransaction = std::move(transaction);
    if (!d->lastAssuanTransaction.get()) {
        return Error(d->lasterr = make_error(GPG_ERR_INV_ARG));
    }
    err = gpgme_op_assuan_transact_start
      (d->ctx,
       command,
       assuan_transaction_data_callback,
       d->lastAssuanTransaction.get(),
       assuan_transaction_inquire_callback,
       d,
       assuan_transaction_status_callback,
       d->lastAssuanTransaction.get());

    d->lasterr = err;

    return Error(d->lasterr);
}

AssuanTransaction *Context::lastAssuanTransaction() const
{
    return d->lastAssuanTransaction.get();
}

std::unique_ptr<AssuanTransaction> Context::takeLastAssuanTransaction()
{
    return std::move(d->lastAssuanTransaction);
}

DecryptionResult Context::decrypt(const Data &cipherText, Data &plainText, const DecryptionFlags flags)
{
    d->lastop = Private::Decrypt;
    const Data::Private *const cdp = cipherText.impl();
    Data::Private *const pdp = plainText.impl();
    d->lasterr = gpgme_op_decrypt_ext(d->ctx, static_cast<gpgme_decrypt_flags_t> (d->decryptFlags | flags), cdp ? cdp->data : nullptr, pdp ? pdp->data : nullptr);
    return decryptionResult();
}

DecryptionResult Context::decrypt(const Data &cipherText, Data &plainText)
{
    return decrypt(cipherText, plainText, DecryptNone);
}

Error Context::startDecryption(const Data &cipherText, Data &plainText, const DecryptionFlags flags)
{
    d->lastop = Private::Decrypt;
    const Data::Private *const cdp = cipherText.impl();
    Data::Private *const pdp = plainText.impl();
    return Error(d->lasterr = gpgme_op_decrypt_ext_start(d->ctx, static_cast<gpgme_decrypt_flags_t> (d->decryptFlags | flags),
                 cdp ? cdp->data : nullptr, pdp ? pdp->data : nullptr));
}

Error Context::startDecryption(const Data &cipherText, Data &plainText)
{
    return startDecryption(cipherText, plainText, DecryptNone);
}

DecryptionResult Context::decryptionResult() const
{
    if (d->lastop & Private::Decrypt) {
        return DecryptionResult(d->ctx, Error(d->lasterr));
    } else {
        return DecryptionResult();
    }
}

VerificationResult Context::verifyDetachedSignature(const Data &signature, const Data &signedText)
{
    d->lastop = Private::Verify;
    const Data::Private *const sdp = signature.impl();
    const Data::Private *const tdp = signedText.impl();
    d->lasterr = gpgme_op_verify(d->ctx, sdp ? sdp->data : nullptr, tdp ? tdp->data : nullptr, nullptr);
    return verificationResult();
}

VerificationResult Context::verifyOpaqueSignature(const Data &signedData, Data &plainText)
{
    d->lastop = Private::Verify;
    const Data::Private *const sdp = signedData.impl();
    Data::Private *const pdp = plainText.impl();
    d->lasterr = gpgme_op_verify(d->ctx, sdp ? sdp->data : nullptr, nullptr, pdp ? pdp->data : nullptr);
    return verificationResult();
}

Error Context::startDetachedSignatureVerification(const Data &signature, const Data &signedText)
{
    d->lastop = Private::Verify;
    const Data::Private *const sdp = signature.impl();
    const Data::Private *const tdp = signedText.impl();
    return Error(d->lasterr = gpgme_op_verify_start(d->ctx, sdp ? sdp->data : nullptr, tdp ? tdp->data : nullptr, nullptr));
}

Error Context::startOpaqueSignatureVerification(const Data &signedData, Data &plainText)
{
    d->lastop = Private::Verify;
    const Data::Private *const sdp = signedData.impl();
    Data::Private *const pdp = plainText.impl();
    return Error(d->lasterr = gpgme_op_verify_start(d->ctx, sdp ? sdp->data : nullptr, nullptr, pdp ? pdp->data : nullptr));
}

VerificationResult Context::verificationResult() const
{
    if (d->lastop & Private::Verify) {
        const auto res = VerificationResult{d->ctx, Error(d->lasterr)};
        if ((d->lastop == Private::DecryptAndVerify)
            && (res.error().code() == GPG_ERR_NO_DATA)
            && (res.numSignatures() > 0)) {
            // ignore "no data" error for verification if there are signatures and
            // the operation was a combined (tentative) decryption and verification
            // because then "no data" just indicates that there was nothing to decrypt
            return VerificationResult{d->ctx, Error{}};
        }
        return res;
    } else {
        return {};
    }
}

std::pair<DecryptionResult, VerificationResult> Context::decryptAndVerify(const Data &cipherText, Data &plainText, DecryptionFlags flags)
{
    d->lastop = Private::DecryptAndVerify;
    const Data::Private *const cdp = cipherText.impl();
    Data::Private *const pdp = plainText.impl();
    d->lasterr = gpgme_op_decrypt_ext(d->ctx, static_cast<gpgme_decrypt_flags_t> (d->decryptFlags | flags | DecryptVerify),
                                      cdp ? cdp->data : nullptr, pdp ? pdp->data : nullptr);
    return std::make_pair(decryptionResult(), verificationResult());
}

std::pair<DecryptionResult, VerificationResult> Context::decryptAndVerify(const Data &cipherText, Data &plainText)
{
    return decryptAndVerify(cipherText, plainText, DecryptNone);
}

Error Context::startCombinedDecryptionAndVerification(const Data &cipherText, Data &plainText, DecryptionFlags flags)
{
    d->lastop = Private::DecryptAndVerify;
    const Data::Private *const cdp = cipherText.impl();
    Data::Private *const pdp = plainText.impl();
    return Error(d->lasterr = gpgme_op_decrypt_ext_start(d->ctx, static_cast<gpgme_decrypt_flags_t> (d->decryptFlags | flags | DecryptVerify), cdp ? cdp->data : nullptr, pdp ? pdp->data : nullptr));
}

Error Context::startCombinedDecryptionAndVerification(const Data &cipherText, Data &plainText)
{
    return startCombinedDecryptionAndVerification(cipherText, plainText, DecryptNone);
}

namespace {
unsigned int to_auditlog_flags(unsigned int flags)
{
    unsigned int result = 0;
    if (flags & Context::HtmlAuditLog) {
        result |= GPGME_AUDITLOG_HTML;
    }
    if (flags & Context::AuditLogWithHelp) {
        result |= GPGME_AUDITLOG_WITH_HELP;
    }
    if (flags & Context::DiagnosticAuditLog) {
        result |= GPGME_AUDITLOG_DIAG;
    }
    return result;
}
}

Error Context::startGetAuditLog(Data &output, unsigned int flags)
{
    d->lastop = Private::GetAuditLog;
    Data::Private *const odp = output.impl();
    return Error(d->lasterr = gpgme_op_getauditlog_start(d->ctx, odp ? odp->data : nullptr, to_auditlog_flags(flags)));
}

Error Context::getAuditLog(Data &output, unsigned int flags)
{
    d->lastop = Private::GetAuditLog;
    Data::Private *const odp = output.impl();
    return Error(d->lasterr = gpgme_op_getauditlog(d->ctx, odp ? odp->data : nullptr, to_auditlog_flags(flags)));
}

void Context::clearSigningKeys()
{
    gpgme_signers_clear(d->ctx);
}

Error Context::addSigningKey(const Key &key)
{
    return Error(d->lasterr = gpgme_signers_add(d->ctx, key.impl()));
}

Key Context::signingKey(unsigned int idx) const
{
    gpgme_key_t key = gpgme_signers_enum(d->ctx, idx);
    return Key(key, false);
}

std::vector<Key> Context::signingKeys() const
{
    std::vector<Key> result;
    gpgme_key_t key = nullptr;
    for (unsigned int i = 0 ; (key = gpgme_signers_enum(d->ctx, i)) ; ++i) {
        result.push_back(Key(key, false));
    }
    return result;
}

void Context::clearSignatureNotations()
{
    gpgme_sig_notation_clear(d->ctx);
}

GpgME::Error Context::addSignatureNotation(const char *name, const char *value, unsigned int flags)
{
    return Error(gpgme_sig_notation_add(d->ctx, name, value, add_to_gpgme_sig_notation_flags_t(0, flags)));
}

GpgME::Error Context::addSignaturePolicyURL(const char *url, bool critical)
{
    return Error(gpgme_sig_notation_add(d->ctx, nullptr, url, critical ? GPGME_SIG_NOTATION_CRITICAL : 0));
}

const char *Context::signaturePolicyURL() const
{
    for (gpgme_sig_notation_t n = gpgme_sig_notation_get(d->ctx) ; n ; n = n->next) {
        if (!n->name) {
            return n->value;
        }
    }
    return nullptr;
}

Notation Context::signatureNotation(unsigned int idx) const
{
    for (gpgme_sig_notation_t n = gpgme_sig_notation_get(d->ctx) ; n ; n = n->next) {
        if (n->name) {
            if (idx-- == 0) {
                return Notation(n);
            }
        }
    }
    return Notation();
}

std::vector<Notation> Context::signatureNotations() const
{
    std::vector<Notation> result;
    for (gpgme_sig_notation_t n = gpgme_sig_notation_get(d->ctx) ; n ; n = n->next) {
        if (n->name) {
            result.push_back(Notation(n));
        }
    }
    return result;
}

static gpgme_sig_mode_t sigflags2sigflags(SignatureMode flags)
{
    unsigned int result = 0;
    if (flags & SignatureMode::NormalSignatureMode) {
        result |= GPGME_SIG_MODE_NORMAL;
    }
    if (flags & SignatureMode::Detached) {
        result |= GPGME_SIG_MODE_DETACH;
    }
    if (flags & SignatureMode::Clearsigned) {
        result |= GPGME_SIG_MODE_CLEAR;
    }
    if (flags & SignatureMode::SignArchive) {
        result |= GPGME_SIG_MODE_ARCHIVE;
    }
    if (flags & SignatureMode::SignFile) {
        result |= GPGME_SIG_MODE_FILE;
    }
    return static_cast<gpgme_sig_mode_t>(result);
}

SigningResult Context::sign(const Data &plainText, Data &signature, SignatureMode mode)
{
    d->lastop = Private::Sign;
    const Data::Private *const pdp = plainText.impl();
    Data::Private *const sdp = signature.impl();
    d->lasterr = gpgme_op_sign(d->ctx, pdp ? pdp->data : nullptr, sdp ? sdp->data : nullptr, sigflags2sigflags(mode));
    return SigningResult(d->ctx, Error(d->lasterr));
}

Error Context::startSigning(const Data &plainText, Data &signature, SignatureMode mode)
{
    d->lastop = Private::Sign;
    const Data::Private *const pdp = plainText.impl();
    Data::Private *const sdp = signature.impl();
    return Error(d->lasterr = gpgme_op_sign_start(d->ctx, pdp ? pdp->data : nullptr, sdp ? sdp->data : nullptr, sigflags2sigflags(mode)));
}

SigningResult Context::signingResult() const
{
    if (d->lastop & Private::Sign) {
        return SigningResult(d->ctx, Error(d->lasterr));
    } else {
        return SigningResult();
    }
}

static gpgme_encrypt_flags_t encryptflags2encryptflags(Context::EncryptionFlags flags)
{
    unsigned int result = 0;
    if (flags & Context::AlwaysTrust) {
        result |= GPGME_ENCRYPT_ALWAYS_TRUST;
    }
    if (flags & Context::NoEncryptTo) {
        result |= GPGME_ENCRYPT_NO_ENCRYPT_TO;
    }
    if (flags & Context::Prepare) {
        result |= GPGME_ENCRYPT_PREPARE;
    }
    if (flags & Context::ExpectSign) {
        result |= GPGME_ENCRYPT_EXPECT_SIGN;
    }
    if (flags & Context::NoCompress) {
        result |= GPGME_ENCRYPT_NO_COMPRESS;
    }
    if (flags & Context::Symmetric) {
        result |= GPGME_ENCRYPT_SYMMETRIC;
    }
    if (flags & Context::ThrowKeyIds) {
        result |= GPGME_ENCRYPT_THROW_KEYIDS;
    }
    if (flags & Context::EncryptWrap) {
        result |= GPGME_ENCRYPT_WRAP;
    }
    if (flags & Context::WantAddress) {
        result |= GPGME_ENCRYPT_WANT_ADDRESS;
    }
    if (flags & Context::EncryptArchive) {
        result |= GPGME_ENCRYPT_ARCHIVE;
    }
    if (flags & Context::EncryptFile) {
        result |= GPGME_ENCRYPT_FILE;
    }
    return static_cast<gpgme_encrypt_flags_t>(result);
}

gpgme_key_t *Context::getKeysFromRecipients(const std::vector<Key> &recipients)
{
    if (recipients.empty()) {
        return nullptr;
    }
    gpgme_key_t *ret = new gpgme_key_t[ recipients.size() + 1 ];
    gpgme_key_t *keys_it = ret;
    for (std::vector<Key>::const_iterator it = recipients.begin() ; it != recipients.end() ; ++it) {
        if (it->impl()) {
            *keys_it++ = it->impl();
        }
    }
    *keys_it++ = nullptr;
    return ret;
}

EncryptionResult Context::encrypt(const std::vector<Key> &recipients, const Data &plainText, Data &cipherText, EncryptionFlags flags)
{
    d->lastop = Private::Encrypt;
    if (flags & NoEncryptTo) {
        return EncryptionResult(Error(d->lasterr = make_error(GPG_ERR_NOT_IMPLEMENTED)));
    }
    const Data::Private *const pdp = plainText.impl();
    Data::Private *const cdp = cipherText.impl();
    gpgme_key_t *const keys = getKeysFromRecipients(recipients);
    d->lasterr = gpgme_op_encrypt(d->ctx, keys, encryptflags2encryptflags(flags),
                                  pdp ? pdp->data : nullptr, cdp ? cdp->data : nullptr);
    if (keys) {
        delete[] keys;
    }
    return EncryptionResult(d->ctx, Error(d->lasterr));
}

Error Context::encryptSymmetrically(const Data &plainText, Data &cipherText)
{
    d->lastop = Private::Encrypt;
    const Data::Private *const pdp = plainText.impl();
    Data::Private *const cdp = cipherText.impl();
    return Error(d->lasterr = gpgme_op_encrypt(d->ctx, nullptr, (gpgme_encrypt_flags_t)0,
                              pdp ? pdp->data : nullptr, cdp ? cdp->data : nullptr));
}

Error Context::startEncryption(const std::vector<Key> &recipients, const Data &plainText, Data &cipherText, EncryptionFlags flags)
{
    d->lastop = Private::Encrypt;
    if (flags & NoEncryptTo) {
        return Error(d->lasterr = make_error(GPG_ERR_NOT_IMPLEMENTED));
    }
    const Data::Private *const pdp = plainText.impl();
    Data::Private *const cdp = cipherText.impl();
    gpgme_key_t *const keys = getKeysFromRecipients(recipients);
    d->lasterr = gpgme_op_encrypt_start(d->ctx, keys, encryptflags2encryptflags(flags),
                                        pdp ? pdp->data : nullptr, cdp ? cdp->data : nullptr);
    if (keys) {
        delete[] keys;
    }
    return Error(d->lasterr);
}

EncryptionResult Context::encryptionResult() const
{
    if (d->lastop & Private::Encrypt) {
        return EncryptionResult(d->ctx, Error(d->lasterr));
    } else {
        return EncryptionResult();
    }
}

std::pair<SigningResult, EncryptionResult> Context::signAndEncrypt(const std::vector<Key> &recipients, const Data &plainText, Data &cipherText, EncryptionFlags flags)
{
    d->lastop = Private::SignAndEncrypt;
    const Data::Private *const pdp = plainText.impl();
    Data::Private *const cdp = cipherText.impl();
    gpgme_key_t *const keys = getKeysFromRecipients(recipients);
    d->lasterr = gpgme_op_encrypt_sign(d->ctx, keys, encryptflags2encryptflags(flags),
                                       pdp ? pdp->data : nullptr, cdp ? cdp->data : nullptr);
    if (keys) {
        delete[] keys;
    }
    return std::make_pair(SigningResult(d->ctx, Error(d->lasterr)),
                          EncryptionResult(d->ctx, Error(d->lasterr)));
}

Error Context::startCombinedSigningAndEncryption(const std::vector<Key> &recipients, const Data &plainText, Data &cipherText, EncryptionFlags flags)
{
    d->lastop = Private::SignAndEncrypt;
    const Data::Private *const pdp = plainText.impl();
    Data::Private *const cdp = cipherText.impl();
    gpgme_key_t *const keys = getKeysFromRecipients(recipients);
    d->lasterr = gpgme_op_encrypt_sign_start(d->ctx, keys, encryptflags2encryptflags(flags),
                 pdp ? pdp->data : nullptr, cdp ? cdp->data : nullptr);
    if (keys) {
        delete[] keys;
    }
    return Error(d->lasterr);
}

Error Context::createVFS(const char *containerFile, const std::vector< Key > &recipients)
{
    d->lastop = Private::CreateVFS;
    gpgme_key_t *const keys = new gpgme_key_t[ recipients.size() + 1 ];
    gpgme_key_t *keys_it = keys;
    for (std::vector<Key>::const_iterator it = recipients.begin() ; it != recipients.end() ; ++it) {
        if (it->impl()) {
            *keys_it++ = it->impl();
        }
    }
    *keys_it++ = nullptr;

    gpgme_error_t op_err;
    d->lasterr = gpgme_op_vfs_create(d->ctx, keys, containerFile, 0, &op_err);
    delete[] keys;
    Error error(d->lasterr);
    if (error) {
        return error;
    }
    return Error(d->lasterr = op_err);
}

VfsMountResult Context::mountVFS(const char *containerFile, const char *mountDir)
{
    d->lastop = Private::MountVFS;
    gpgme_error_t op_err;
    d->lasterr = gpgme_op_vfs_mount(d->ctx, containerFile, mountDir, 0, &op_err);
    return VfsMountResult(d->ctx, Error(d->lasterr), Error(op_err));
}

Error Context::cancelPendingOperation()
{
    return Error(gpgme_cancel_async(d->ctx));
}

Error Context::cancelPendingOperationImmediately()
{
    return Error(gpgme_cancel(d->ctx));
}

bool Context::poll()
{
    gpgme_error_t e = GPG_ERR_NO_ERROR;
    const bool finished = gpgme_wait(d->ctx, &e, 0);
    if (finished) {
        d->lasterr = e;
    }
    return finished;
}

Error Context::wait()
{
    gpgme_error_t e = GPG_ERR_NO_ERROR;
    gpgme_wait(d->ctx, &e, 1);
    return Error(d->lasterr = e);
}

Error Context::lastError() const
{
    return Error(d->lasterr);
}

Context::PinentryMode Context::pinentryMode() const
{
    switch (gpgme_get_pinentry_mode (d->ctx)) {
        case GPGME_PINENTRY_MODE_ASK:
            return PinentryAsk;
        case GPGME_PINENTRY_MODE_CANCEL:
            return PinentryCancel;
        case GPGME_PINENTRY_MODE_ERROR:
            return PinentryError;
        case GPGME_PINENTRY_MODE_LOOPBACK:
            return PinentryLoopback;
        case GPGME_PINENTRY_MODE_DEFAULT:
        default:
            return PinentryDefault;
    }
}

Error Context::setPinentryMode(PinentryMode which)
{
    gpgme_pinentry_mode_t mode;
    switch (which) {
        case PinentryAsk:
            mode = GPGME_PINENTRY_MODE_ASK;
            break;
        case PinentryCancel:
            mode = GPGME_PINENTRY_MODE_CANCEL;
            break;
        case PinentryError:
            mode = GPGME_PINENTRY_MODE_ERROR;
            break;
        case PinentryLoopback:
            mode = GPGME_PINENTRY_MODE_LOOPBACK;
            break;
        case PinentryDefault:
        default:
            mode = GPGME_PINENTRY_MODE_DEFAULT;
    }
    return Error(d->lasterr = gpgme_set_pinentry_mode(d->ctx, mode));
}

static gpgme_tofu_policy_t to_tofu_policy_t(unsigned int policy)
{
    switch (policy) {
        case TofuInfo::PolicyNone:
            return GPGME_TOFU_POLICY_NONE;
        case TofuInfo::PolicyAuto:
            return GPGME_TOFU_POLICY_AUTO;
        case TofuInfo::PolicyGood:
            return GPGME_TOFU_POLICY_GOOD;
        case TofuInfo::PolicyBad:
            return GPGME_TOFU_POLICY_BAD;
        case TofuInfo::PolicyAsk:
            return GPGME_TOFU_POLICY_ASK;
        case TofuInfo::PolicyUnknown:
        default:
            return GPGME_TOFU_POLICY_UNKNOWN;
    }
}

Error Context::setTofuPolicy(const Key &k, unsigned int policy)
{
    return Error(d->lasterr = gpgme_op_tofu_policy(d->ctx,
                 k.impl(), to_tofu_policy_t(policy)));
}

Error Context::setTofuPolicyStart(const Key &k, unsigned int policy)
{
    return Error(d->lasterr = gpgme_op_tofu_policy_start(d->ctx,
                 k.impl(), to_tofu_policy_t(policy)));
}

Error Context::startCreateKey (const char *userid,
                               const char *algo,
                               unsigned long reserved,
                               unsigned long expires,
                               const Key &certkey,
                               unsigned int flags)
{
    return Error(d->lasterr = gpgme_op_createkey_start(d->ctx,
                 userid,
                 algo,
                 reserved,
                 expires,
                 certkey.impl(),
                 flags));
}

Error Context::createKey (const char *userid,
                          const char *algo,
                          unsigned long reserved,
                          unsigned long expires,
                          const Key &certkey,
                          unsigned int flags)
{
    return Error(d->lasterr = gpgme_op_createkey(d->ctx,
                 userid,
                 algo,
                 reserved,
                 expires,
                 certkey.impl(),
                 flags));
}

KeyGenerationResult Context::createKeyEx (const char *userid,
                                          const char *algo,
                                          unsigned long reserved,
                                          unsigned long expires,
                                          const Key &certkey,
                                          unsigned int flags)
{
    d->lasterr = gpgme_op_createkey(d->ctx,
                 userid,
                 algo,
                 reserved,
                 expires,
                 certkey.impl(),
                 flags);
    return KeyGenerationResult(d->ctx, Error(d->lasterr));
}

Error Context::addUid(const Key &k, const char *userid)
{
    return Error(d->lasterr = gpgme_op_adduid(d->ctx,
                 k.impl(), userid, 0));
}

Error Context::startAddUid(const Key &k, const char *userid)
{
    return Error(d->lasterr = gpgme_op_adduid_start(d->ctx,
                 k.impl(), userid, 0));
}

Error Context::revUid(const Key &k, const char *userid)
{
    return Error(d->lasterr = gpgme_op_revuid(d->ctx,
                 k.impl(), userid, 0));
}

Error Context::startRevUid(const Key &k, const char *userid)
{
    return Error(d->lasterr = gpgme_op_revuid_start(d->ctx,
                 k.impl(), userid, 0));
}

Error Context::setPrimaryUid(const Key &k, const char *userid)
{
    return Error(d->lasterr = gpgme_op_set_uid_flag(d->ctx, k.impl(), userid, "primary", nullptr));
}

Error Context::startSetPrimaryUid(const Key &k, const char *userid)
{
    return Error(d->lasterr = gpgme_op_set_uid_flag_start(d->ctx, k.impl(), userid, "primary", nullptr));
}

Error Context::createSubkey(const Key &k, const char *algo,
                            unsigned long reserved,
                            unsigned long expires,
                            unsigned int flags)
{
    return Error(d->lasterr = gpgme_op_createsubkey(d->ctx,
                 k.impl(), algo, reserved, expires, flags));
}

Error Context::startCreateSubkey(const Key &k, const char *algo,
                                 unsigned long reserved,
                                 unsigned long expires,
                                 unsigned int flags)
{
    return Error(d->lasterr = gpgme_op_createsubkey_start(d->ctx,
                 k.impl(), algo, reserved, expires, flags));
}

static std::string getLFSeparatedListOfStrings(const std::vector<std::string> &strings)
{
    if (strings.empty()) {
        return std::string();
    }

    return std::accumulate(
        std::next(strings.begin()),
        strings.end(),
        strings[0],
        [](const std::string &a, const std::string &b) {
            return a + '\n' + b;
        }
    );
}

static std::string getLFSeparatedListOfFingerprintsFromSubkeys(const std::vector<Subkey> &subkeys)
{
    if (subkeys.empty()) {
        return std::string();
    }

    std::vector<std::string> fprs;
    fprs.reserve(subkeys.size());
    for (auto &it : subkeys) {
        if (it.fingerprint()) {
            fprs.push_back(std::string(it.fingerprint()));
        }
    }

    return getLFSeparatedListOfStrings(fprs);
}

Error Context::setExpire(const Key &k, unsigned long expires,
                         const std::vector<Subkey> &subkeys,
                         const Context::SetExpireFlags flags)
{
    std::string subfprs;
    if (flags & Context::SetExpireAllSubkeys) {
        subfprs = "*";
    } else {
        subfprs = getLFSeparatedListOfFingerprintsFromSubkeys(subkeys);
    }
    return Error(d->lasterr = gpgme_op_setexpire(d->ctx,
                 k.impl(), expires, subfprs.c_str(), 0));
}

Error Context::startSetExpire(const Key &k, unsigned long expires,
                              const std::vector<Subkey> &subkeys,
                              const Context::SetExpireFlags flags)
{
    std::string subfprs;
    if (flags & Context::SetExpireAllSubkeys) {
        subfprs = "*";
    } else {
        subfprs = getLFSeparatedListOfFingerprintsFromSubkeys(subkeys);
    }
    return Error(d->lasterr = gpgme_op_setexpire_start(d->ctx,
                 k.impl(), expires, subfprs.c_str(), 0));
}

static std::string getLFSeparatedListOfUserIds(const std::vector<UserID> &userIds)
{
    if (userIds.empty()) {
        return std::string();
    }

    std::vector<std::string> uids;
    uids.reserve(userIds.size());
    for (auto &userId : userIds) {
        if (userId.id()) {
            uids.push_back(std::string(userId.id()));
        }
    }

    return getLFSeparatedListOfStrings(uids);
}

Error Context::revokeSignature(const Key &key, const Key &signingKey,
                               const std::vector<UserID> &userIds)
{
    const unsigned int flags = userIds.size() > 1 ? GPGME_REVSIG_LFSEP : 0;
    const std::string uids = getLFSeparatedListOfUserIds(userIds);
    return Error(d->lasterr = gpgme_op_revsig(d->ctx,
                 key.impl(), signingKey.impl(), uids.c_str(), flags));
}

Error Context::startRevokeSignature(const Key &key, const Key &signingKey,
                                    const std::vector<UserID> &userIds)
{
    const unsigned int flags = userIds.size() > 1 ? GPGME_REVSIG_LFSEP : 0;
    const std::string uids = getLFSeparatedListOfUserIds(userIds);
    return Error(d->lasterr = gpgme_op_revsig_start(d->ctx,
                 key.impl(), signingKey.impl(), uids.c_str(), flags));
}

Error Context::setFlag(const char *name, const char *value)
{
  return Error(d->lasterr = gpgme_set_ctx_flag(d->ctx, name, value));
}

const char *Context::getFlag(const char *name) const
{
  return gpgme_get_ctx_flag(d->ctx, name);
}

// Engine Spawn stuff
Error Context::spawn(const char *file, const char *argv[],
                     Data &input, Data &output, Data &err,
                     SpawnFlags flags)
{
    return Error(d->lasterr = gpgme_op_spawn (d->ctx, file, argv,
        input.impl() ? input.impl()->data : nullptr,
        output.impl() ? output.impl()->data : nullptr,
        err.impl() ? err.impl()->data : nullptr,
        static_cast<int>(flags)));
}

Error Context::spawnAsync(const char *file, const char *argv[],
                          Data &input, Data &output, Data &err,
                          SpawnFlags flags)
{
    return Error(d->lasterr = gpgme_op_spawn_start (d->ctx, file, argv,
        input.impl() ? input.impl()->data : nullptr,
        output.impl() ? output.impl()->data : nullptr,
        err.impl() ? err.impl()->data : nullptr,
        static_cast<int>(flags)));
}

std::ostream &operator<<(std::ostream &os, Protocol proto)
{
    os << "GpgME::Protocol(";
    switch (proto) {
    case OpenPGP:
        os << "OpenPGP";
        break;
    case CMS:
        os << "CMS";
        break;
    default:
    case UnknownProtocol:
        os << "UnknownProtocol";
        break;
    }
    return os << ')';
}

std::ostream &operator<<(std::ostream &os, Engine eng)
{
    os << "GpgME::Engine(";
    switch (eng) {
    case GpgEngine:
        os << "GpgEngine";
        break;
    case GpgSMEngine:
        os << "GpgSMEngine";
        break;
    case GpgConfEngine:
        os << "GpgConfEngine";
        break;
    case AssuanEngine:
        os << "AssuanEngine";
        break;
    case SpawnEngine:
        os << "SpawnEngine";
        break;
    default:
    case UnknownEngine:
        os << "UnknownEngine";
        break;
    }
    return os << ')';
}

std::ostream &operator<<(std::ostream &os, Context::CertificateInclusion incl)
{
    os << "GpgME::Context::CertificateInclusion(" << static_cast<int>(incl);
    switch (incl) {
    case Context::DefaultCertificates:
        os << "(DefaultCertificates)";
        break;
    case Context::AllCertificatesExceptRoot:
        os << "(AllCertificatesExceptRoot)";
        break;
    case Context::AllCertificates:
        os << "(AllCertificates)";
        break;
    case Context::NoCertificates:
        os << "(NoCertificates)";
        break;
    case Context::OnlySenderCertificate:
        os << "(OnlySenderCertificate)";
        break;
    }
    return os << ')';
}

std::ostream &operator<<(std::ostream &os, KeyListMode mode)
{
    os << "GpgME::KeyListMode(";
#define CHECK( x ) if ( !(mode & (x)) ) {} else do { os << #x " "; } while (0)
    CHECK(Local);
    CHECK(Extern);
    CHECK(Signatures);
    CHECK(Validate);
    CHECK(Ephemeral);
    CHECK(WithTofu);
    CHECK(WithKeygrip);
    CHECK(WithSecret);
    CHECK(ForceExtern);
#undef CHECK
    return os << ')';
}

std::ostream &operator<<(std::ostream &os, SignatureMode mode)
{
    os << "GpgME::SignatureMode(";
#undef CHECK
    switch (mode & (NormalSignatureMode|Detached|Clearsigned)) {
#define CHECK( x ) case x: os << #x; break
        CHECK(NormalSignatureMode);
        CHECK(Detached);
        CHECK(Clearsigned);
#undef CHECK
    default:
        os << "???" "(" << static_cast<int>(mode) << ')';
        break;
    }
#define CHECK( x ) if ( !(mode & (x)) ) {} else do { os << #x " "; } while (0)
        CHECK(SignArchive);
        CHECK(SignFile);
#undef CHECK
    return os << ')';
}

std::ostream &operator<<(std::ostream &os, Context::EncryptionFlags flags)
{
    os << "GpgME::Context::EncryptionFlags(";
#define CHECK( x ) if ( !(flags & (Context::x)) ) {} else do { os << #x " "; } while (0)
    CHECK(AlwaysTrust);
    CHECK(NoEncryptTo);
    CHECK(Prepare);
    CHECK(ExpectSign);
    CHECK(NoCompress);
    CHECK(Symmetric);
    CHECK(ThrowKeyIds);
    CHECK(EncryptWrap);
    CHECK(WantAddress);
    CHECK(EncryptArchive);
    CHECK(EncryptFile);
#undef CHECK
    return os << ')';
}

std::ostream &operator<<(std::ostream &os, Context::AuditLogFlags flags)
{
    os << "GpgME::Context::AuditLogFlags(";
#define CHECK( x ) if ( !(flags & (Context::x)) ) {} else do { os << #x " "; } while (0)
    CHECK(HtmlAuditLog);
    CHECK(AuditLogWithHelp);
#undef CHECK
    return os << ')';
}

} // namespace GpgME

GpgME::Error GpgME::setDefaultLocale(int cat, const char *val)
{
    return Error(gpgme_set_locale(nullptr, cat, val));
}

GpgME::EngineInfo GpgME::engineInfo(GpgME::Protocol proto)
{
    return get_static_engine_info(proto == CMS ? GPGME_PROTOCOL_CMS : GPGME_PROTOCOL_OpenPGP);
}

const char *GpgME::dirInfo(const char *what)
{
    return gpgme_get_dirinfo(what);
}

GpgME::Error GpgME::checkEngine(GpgME::Protocol proto)
{
    const gpgme_protocol_t p = proto == CMS ? GPGME_PROTOCOL_CMS : GPGME_PROTOCOL_OpenPGP ;

    return Error(gpgme_engine_check_version(p));
}

static const gpgme_protocol_t UNKNOWN_PROTOCOL = static_cast<gpgme_protocol_t>(255);

static gpgme_protocol_t engine2protocol(const GpgME::Engine engine)
{
    switch (engine) {
    case GpgME::GpgEngine:   return GPGME_PROTOCOL_OpenPGP;
    case GpgME::GpgSMEngine: return GPGME_PROTOCOL_CMS;
    case GpgME::GpgConfEngine:
        return GPGME_PROTOCOL_GPGCONF;
    case GpgME::AssuanEngine:
        return GPGME_PROTOCOL_ASSUAN;
    case GpgME::G13Engine:
        return GPGME_PROTOCOL_G13;
    case GpgME::SpawnEngine:
        return GPGME_PROTOCOL_SPAWN;
    case GpgME::UnknownEngine:
        ;
    }
    return UNKNOWN_PROTOCOL;
}

GpgME::EngineInfo GpgME::engineInfo(GpgME::Engine engine)
{
    return get_static_engine_info(engine2protocol(engine));
}

GpgME::Error GpgME::checkEngine(GpgME::Engine engine)
{
    const gpgme_protocol_t p = engine2protocol(engine);

    return Error(gpgme_engine_check_version(p));
}

static const unsigned long supported_features = 0
        | GpgME::ValidatingKeylistModeFeature
        | GpgME::CancelOperationFeature
        | GpgME::WrongKeyUsageFeature
        | GpgME::DefaultCertificateInclusionFeature
        | GpgME::GetSetEngineInfoFeature
        | GpgME::ClearAddGetSignatureNotationsFeature
        | GpgME::SetDataFileNameFeeature
        | GpgME::SignatureNotationsKeylistModeFeature
        | GpgME::KeySignatureNotationsFeature
        | GpgME::KeyIsQualifiedFeature
        | GpgME::SignatureNotationsCriticalFlagFeature
        | GpgME::SignatureNotationsFlagsFeature
        | GpgME::SignatureNotationsHumanReadableFlagFeature
        | GpgME::SubkeyIsQualifiedFeature
        | GpgME::EngineInfoHomeDirFeature
        | GpgME::DecryptionResultFileNameFeature
        | GpgME::DecryptionResultRecipientsFeature
        | GpgME::VerificationResultFileNameFeature
        | GpgME::SignaturePkaFieldsFeature
        | GpgME::SignatureAlgorithmFieldsFeature
        | GpgME::FdPointerFeature
        | GpgME::AuditLogFeature
        | GpgME::GpgConfEngineFeature
        | GpgME::CancelOperationAsyncFeature
        | GpgME::NoEncryptToEncryptionFlagFeature
        | GpgME::CardKeyFeature
        | GpgME::AssuanEngineFeature
        | GpgME::EphemeralKeylistModeFeature
        | GpgME::ImportFromKeyserverFeature
        | GpgME::G13VFSFeature
        | GpgME::PasswdFeature
        ;

static const unsigned long supported_features2 = 0
        | GpgME::BinaryAndFineGrainedIdentify
        ;

bool GpgME::hasFeature(unsigned long features)
{
    return features == (features & supported_features);
}

bool GpgME::hasFeature(unsigned long features, unsigned long features2)
{
    return features  == (features  & supported_features)
           && features2 == (features2 & supported_features2)
           ;
}

int GpgME::setGlobalFlag(const char *name, const char *value)
{
    return gpgme_set_global_flag(name, value);
}
