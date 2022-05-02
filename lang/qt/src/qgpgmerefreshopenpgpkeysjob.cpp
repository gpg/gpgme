/*
    qgpgmerefreshopenpgpkeysjob.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2022 g10 Code GmbH
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

#include "qgpgmerefreshopenpgpkeysjob.h"

#include "qgpgmekeylistjob.h"
#include "qgpgmereceivekeysjob.h"
#include "util.h"

#include <context.h>
#include <key.h>

#include <memory>

#include "qgpgme_debug.h"

using namespace QGpgME;
using namespace GpgME;

QStringList toEmailAddresses(const std::vector<GpgME::Key> &keys)
{
    const auto numUserIDs = std::accumulate(std::begin(keys), std::end(keys), 0, [](auto num, const auto &key) {
        return num + key.numUserIDs();
    });

    QStringList emails;
    emails.reserve(numUserIDs);
    emails = std::accumulate(std::begin(keys), std::end(keys), emails, [](auto &emails, const auto &key) {
        const auto userIDs = key.userIDs();
        emails = std::accumulate(std::begin(userIDs), std::end(userIDs), emails, [](auto &emails, const auto &userID) {
            if (!userID.isRevoked() && !userID.addrSpec().empty()) {
                emails.push_back(QString::fromStdString(userID.addrSpec()));
            }
            return emails;
        });
        return emails;
    });
    return emails;
}

QGpgMERefreshOpenPGPKeysJob::QGpgMERefreshOpenPGPKeysJob(Context *context)
    : mixin_type{context}
{
    lateInitialization();
}

QGpgMERefreshOpenPGPKeysJob::~QGpgMERefreshOpenPGPKeysJob() = default;

static Error locate_external_keys(Context *ctx, const std::vector<Key> &keys)
{
    Context::KeyListModeSaver saver{ctx};
    ctx->setKeyListMode(GpgME::LocateExternal);

    const auto emails = toEmailAddresses(keys);
    std::vector<Key> dummy;
    auto job = std::unique_ptr<KeyListJob>{new QGpgMEKeyListJob{ctx}};
    const auto result = job->exec(emails, false, dummy);
    job.release();

    return result.error();
}

static Error receive_keys(Context *ctx, const std::vector<Key> &keys)
{
    const auto fprs = toFingerprints(keys);

    auto job = std::unique_ptr<ReceiveKeysJob>{new QGpgMEReceiveKeysJob{ctx}};
    const auto result = job->exec(fprs);
    job.release();

    return result.error();
}

static QGpgMERefreshOpenPGPKeysJob::result_type refresh_keys(Context *ctx, const std::vector<Key> &keys)
{
    Error err;

    err = locate_external_keys(ctx, keys);
    if (!err) {
        err = receive_keys(ctx, keys);
    }

    return std::make_tuple(err, /*err ? WKDLookupResult{pattern, err} : result,*/ QString{}, Error{});
}

GpgME::Error QGpgMERefreshOpenPGPKeysJob::start(const QStringList &patterns)
{
    Q_UNUSED(patterns);
    return GpgME::Error::fromCode(GPG_ERR_NOT_IMPLEMENTED);
}

GpgME::Error QGpgMERefreshOpenPGPKeysJob::start(const std::vector<GpgME::Key> &keys)
{
    run(std::bind(&refresh_keys, std::placeholders::_1, keys));
    return Error{};
}

#include "qgpgmerefreshopenpgpkeysjob.moc"
