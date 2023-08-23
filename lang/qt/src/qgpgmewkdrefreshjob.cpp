/*
    qgpgmewkdrefreshjob.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2023 g10 Code GmbH
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

#include "qgpgmewkdrefreshjob.h"

#include "debug.h"
#include "qgpgme_debug.h"
#include "qgpgmekeylistjob.h"
#include "wkdrefreshjob_p.h"

#include <context.h>

#include <memory>

using namespace QGpgME;
using namespace GpgME;

namespace
{

class QGpgMEWKDRefreshJobPrivate : public WKDRefreshJobPrivate
{
    QGpgMEWKDRefreshJob *q = nullptr;

public:
    QGpgMEWKDRefreshJobPrivate(QGpgMEWKDRefreshJob *qq)
        : q{qq}
    {
    }

    ~QGpgMEWKDRefreshJobPrivate() override = default;

private:
    GpgME::Error startIt() override;

    void startNow() override
    {
        q->run();
    }
};

static QStringList toEmailAddressesOriginatingFromWKD(const std::vector<GpgME::Key> &keys)
{
    const QStringList emails = std::accumulate(keys.begin(), keys.end(), QStringList{}, [](QStringList &emails, const Key &key) {
        const auto userIDs = key.userIDs();
        emails = std::accumulate(std::begin(userIDs), std::end(userIDs), emails, [](QStringList &emails, const UserID &userID) {
            if (!userID.isRevoked() && !userID.addrSpec().empty() && userID.origin() == Key::OriginWKD) {
                emails.push_back(QString::fromStdString(userID.addrSpec()));
            }
            return emails;
        });
        return emails;
    });
    return emails;
}

static QStringList toEmailAddresses(const std::vector<GpgME::UserID> &userIds)
{
    const QStringList emails = std::accumulate(
        std::begin(userIds),
        std::end(userIds),
        QStringList{},
        [](QStringList &emails, const UserID &userId) {
            if (!userId.isRevoked() && !userId.addrSpec().empty()) {
                emails.push_back(QString::fromStdString(userId.addrSpec()));
            }
            return emails;
        });
    return emails;
}

}

QGpgMEWKDRefreshJob::QGpgMEWKDRefreshJob(Context *context)
    : mixin_type{context}
{
    setJobPrivate(this, std::unique_ptr<QGpgMEWKDRefreshJobPrivate>{new QGpgMEWKDRefreshJobPrivate{this}});
    lateInitialization();
}

QGpgMEWKDRefreshJob::~QGpgMEWKDRefreshJob() = default;

static QGpgMEWKDRefreshJob::result_type locate_external_keys(Context *ctx, const QStringList &emails)
{
    qCDebug(QGPGME_LOG) << __func__ << "locating external keys for" << emails;
    if (emails.empty()) {
        return std::make_tuple(ImportResult{}, QString{}, Error{});
    }

    Context::KeyListModeSaver saver{ctx};
    ctx->setKeyListMode(GpgME::LocateExternal);
    ctx->setFlag("auto-key-locate", "clear,wkd");
    std::vector<Key> dummy;
    auto job = std::unique_ptr<KeyListJob>{new QGpgMEKeyListJob{ctx}};
    (void) job->exec(emails, false, dummy);
    qCDebug(QGPGME_LOG) << __func__ << "number of keys:" << dummy.size();
    std::for_each(dummy.cbegin(), dummy.cend(), [](const Key &k) {
        qCDebug(QGPGME_LOG) << __func__ << toLogString(k).c_str();
    });
    const auto result = ctx->importResult();
    qCDebug(QGPGME_LOG) << __func__ << "result:" << toLogString(result).c_str();
    job.release();

    return std::make_tuple(result, QString{}, Error{});
}

GpgME::Error QGpgMEWKDRefreshJobPrivate::startIt()
{
    QStringList emails;
    if (!m_keys.empty()) {
        emails = toEmailAddressesOriginatingFromWKD(m_keys);
    } else {
        emails = toEmailAddresses(m_userIds);
    }
    std::sort(emails.begin(), emails.end());
    emails.erase(std::unique(emails.begin(), emails.end()), emails.end());

    q->run([emails](Context *ctx) {
        return locate_external_keys(ctx, emails);
    });

    return {};
}

#include "qgpgmewkdrefreshjob.moc"
