/*
    qgpgmewkdlookupjob.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2021 g10 Code GmbH
    Software engineering by Ingo Klöcker <dev@ingo-kloecker.de>

    QGpgME is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation; either version 2 of the
    License, or (at your option) any later version.

    QGpgME is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

    In addition, as a special exception, the copyright holders give
    permission to link the code of this program with any edition of
    the Qt library by Trolltech AS, Norway (or with modified versions
    of Qt that use the same license as Qt), and distribute linked
    combinations including the two.  You must obey the GNU General
    Public License in all respects for all of the code used other than
    Qt.  If you modify this file, you may extend this exception to
    your version of the file, but you are not obligated to do so.  If
    you do not wish to do so, delete this exception statement from
    your version.
*/

#ifdef HAVE_CONFIG_H
 #include "config.h"
#endif

#include "qgpgmewkdlookupjob.h"

#include "qgpgme_debug.h"

#include <context.h>
#include <data.h>
#include <defaultassuantransaction.h>

#include <gpg-error.h>

using namespace QGpgME;
using namespace GpgME;

QGpgMEWKDLookupJob::QGpgMEWKDLookupJob(Context *context)
    : mixin_type{context}
{
    lateInitialization();
}

QGpgMEWKDLookupJob::~QGpgMEWKDLookupJob() = default;

static GpgME::Error startDirmngr(Context *assuanCtx)
{
    Error err;

    auto spawnCtx = std::unique_ptr<Context>{Context::createForEngine(SpawnEngine, &err)};
    if (err) {
        qCDebug(QGPGME_LOG) << "Error: Failed to get context for spawn engine (" << err.asString() << ")";
    }
    const auto gpgconfProgram = GpgME::dirInfo("gpgconf-name");
    // replace backslashes with forward slashes in homedir to work around bug T6833
    std::string homedir{GpgME::dirInfo("homedir")};
    std::replace(homedir.begin(), homedir.end(), '\\', '/');
    const char *argv[] = {
        gpgconfProgram,
        "--homedir",
        homedir.c_str(),
        "--launch",
        "dirmngr",
        NULL
    };
    auto ignoreIO = Data{Data::null};
    if (!err) {
        qCDebug(QGPGME_LOG) << "Starting dirmngr ...";
        err = spawnCtx->spawn(gpgconfProgram, argv,
                              ignoreIO, ignoreIO, ignoreIO,
                              Context::SpawnDetached);
    }

    if (!err) {
        // wait for socket to become available
        int cnt = 0;
        do {
            ++cnt;
            qCDebug(QGPGME_LOG) << "Waiting for dirmngr to start ...";
            QThread::msleep(250 * cnt);
            err = assuanCtx->assuanTransact("GETINFO version");
        } while (err.code() == GPG_ERR_ASS_CONNECT_FAILED && cnt < 5);
    }

    return err;
}

static GpgME::Error setUpDirmngrAssuanConnection(Context *ctx)
{
    Error err;

    const std::string dirmngrSocket = GpgME::dirInfo("dirmngr-socket");
    err = ctx->setEngineFileName(dirmngrSocket.c_str());

    if (!err) {
        err = ctx->setEngineHomeDirectory("");
    }

    if (!err) {
        // try do connect to dirmngr
        err = ctx->assuanTransact("GETINFO version");
        if (err.code() == GPG_ERR_ASS_CONNECT_FAILED) {
            err = startDirmngr(ctx);
        }
    }

    return err;
}

static GpgME::Error run_wkd_get(Context *ctx, const std::string &email)
{
    Error err;

    const auto cmd = std::string{"WKD_GET "} + email;
    err = ctx->assuanTransact(cmd.c_str());
    if (err.code() == GPG_ERR_NO_NAME || err.code() == GPG_ERR_NO_DATA) {
        // ignore those benign errors; GPG_ERR_NO_NAME indicates that the domain
        // doesn't exist (on first request); GPG_ERR_NO_DATA indicates that
        // no key for email is available via WKD or that the domain doesn't
        // support WKD or that the domain doesn't exist (on subsequent requests
        // using dirmngr's internal cache)
        qCDebug(QGPGME_LOG) << "WKD_GET returned" << err.asString() << "; ignoring...";
        err = {};
    }
    if (err) {
        qCDebug(QGPGME_LOG) << "WKD_GET failed with" << err.asString();
    }

    return err;
}

static QGpgMEWKDLookupJob::result_type lookup_keys(Context *ctx, const QString &email)
{
    WKDLookupResult result;

    Error err = setUpDirmngrAssuanConnection(ctx);

    const auto pattern = email.toUtf8().toStdString();
    if (!err) {
        err = run_wkd_get(ctx, pattern);
    }

    if (!err) {
        const auto transaction = std::unique_ptr<DefaultAssuanTransaction>(dynamic_cast<DefaultAssuanTransaction*>(ctx->takeLastAssuanTransaction().release()));
        const auto source = transaction->firstStatusLine("SOURCE");
        const auto rawData = transaction->data();
        if (rawData.size() == 0) {
            qCDebug(QGPGME_LOG) << "No key found for" << email;
            result = WKDLookupResult{pattern, GpgME::Data::null, {}, {}};
        } else {
            qCDebug(QGPGME_LOG) << "Found key for" << email << "at" << source.c_str();
            result = WKDLookupResult{pattern, GpgME::Data{rawData.c_str(), rawData.size()}, source, {}};
        }
    }

    return std::make_tuple(err ? WKDLookupResult{pattern, err} : result, QString{}, Error{});
}

Error QGpgMEWKDLookupJob::start(const QString &email)
{
    run(std::bind(&lookup_keys, std::placeholders::_1, email));
    return Error();
}

WKDLookupResult QGpgMEWKDLookupJob::exec(const QString &email)
{
    const result_type r = lookup_keys(context(), email);
    return std::get<0>(r);
}

#include "qgpgmewkdlookupjob.moc"
