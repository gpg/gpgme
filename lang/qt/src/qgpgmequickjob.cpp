/*  qgpgmequickjob.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2017 Intevation GmbH
    Copyright (c) 2020 g10 Code GmbH
    Software engineering by Ingo Klöcker <dev@ingo-kloecker.de>

    QGpgME is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation; either version 2 of the
    License, or (at your option) any later version.

    QGpgME is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

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

#include "qgpgmequickjob.h"

#include "qgpgme_debug.h"
#include "quickjob_p.h"
#include "util.h"

#include <gpgme++/context.h>
#include <gpgme++/key.h>


using namespace QGpgME;
using namespace GpgME;

namespace
{

class QGpgMEQuickJobPrivate : public QuickJobPrivate
{
    QGpgMEQuickJob *q = nullptr;

public:
    QGpgMEQuickJobPrivate(QGpgMEQuickJob *qq)
        : q{qq}
    {
    }

    ~QGpgMEQuickJobPrivate() override = default;

private:
    GpgME::Error startIt() override
    {
        Q_ASSERT(!"Not supported by this Job class.");
        return Error::fromCode(GPG_ERR_NOT_SUPPORTED);
    }

    void startNow() override
    {
        Q_ASSERT(!"Not supported by this Job class.");
        q->run();
    }

    GpgME::Error startSetKeyEnabled(const GpgME::Key &key, bool enable) override;
};

}

QGpgMEQuickJob::QGpgMEQuickJob(Context *context)
    : mixin_type(context)
{
    setJobPrivate(this, std::unique_ptr<QGpgMEQuickJobPrivate>{new QGpgMEQuickJobPrivate{this}});
    lateInitialization();
}

QGpgMEQuickJob::~QGpgMEQuickJob() = default;

static QGpgMEQuickJob::result_type createWorker(GpgME::Context *ctx,
                                                const QString &uid,
                                                const char *algo,
                                                const QDateTime &expires,
                                                const GpgME::Key &key,
                                                unsigned int flags)
{
    auto err = ctx->createKey(uid.toUtf8().constData(),
                              algo,
                              0,
                              expires.isValid() ? (unsigned long) (expires.toMSecsSinceEpoch() / 1000
                                  - QDateTime::currentSecsSinceEpoch()) : 0,
                              key,
                              flags);
    return std::make_tuple(err, QString(), Error());
}

static QGpgMEQuickJob::result_type addSubkeyWorker(GpgME::Context *ctx,
                                                    const GpgME::Key &key,
                                                    const char *algo,
                                                    const QDateTime &expires,
                                                    unsigned int flags)
{
    auto err = ctx->createSubkey(key, algo,  0,
                                 expires.isValid() ? (unsigned long) (expires.toMSecsSinceEpoch() / 1000
                                     - QDateTime::currentSecsSinceEpoch()): 0,
                                 flags);
    return std::make_tuple(err, QString(), Error());
}

static QGpgMEQuickJob::result_type addUidWorker(GpgME::Context *ctx,
                                                const GpgME::Key &key,
                                                const QString &uid)
{
    auto err = ctx->addUid(key, uid.toUtf8().constData());
    return std::make_tuple(err, QString(), Error());
}

static QGpgMEQuickJob::result_type revUidWorker(GpgME::Context *ctx,
                                                const GpgME::Key &key,
                                                const QString &uid)
{
    auto err = ctx->revUid(key, uid.toUtf8().constData());
    return std::make_tuple(err, QString(), Error());
}

static QGpgMEQuickJob::result_type revokeSignatureWorker(Context *ctx,
                                                         const Key &key,
                                                         const Key &signingKey,
                                                         const std::vector<UserID> &userIds)
{
    const auto err = ctx->revokeSignature(key, signingKey, userIds);
    return std::make_tuple(err, QString(), Error());
}

static QGpgMEQuickJob::result_type addAdskWorker(Context *ctx, const Key &key, const char *adsk)
{
    const auto err = ctx->addAdsk(key, adsk);
    return std::make_tuple(err, QString(), Error());
}

void QGpgMEQuickJob::startCreate(const QString &uid,
                 const char *algo,
                 const QDateTime &expires,
                 const GpgME::Key &key,
                 unsigned int flags)
{
    run(std::bind(&createWorker, std::placeholders::_1, uid, algo,
                  expires, key, flags));
}

void QGpgMEQuickJob::startAddUid(const GpgME::Key &key, const QString &uid)
{
    run(std::bind(&addUidWorker, std::placeholders::_1, key, uid));
}

void QGpgMEQuickJob::startRevUid(const GpgME::Key &key, const QString &uid)
{
    run(std::bind(&revUidWorker, std::placeholders::_1, key, uid));
}

void QGpgMEQuickJob::startAddSubkey(const GpgME::Key &key, const char *algo,
                                    const QDateTime &expires,
                                    unsigned int flags)
{
    run(std::bind(&addSubkeyWorker, std::placeholders::_1, key, algo,
                  expires, flags));
}

void QGpgMEQuickJob::startRevokeSignature(const Key &key, const Key &signingKey, const std::vector<UserID> &userIds)
{
    run(std::bind(&revokeSignatureWorker, std::placeholders::_1, key, signingKey, userIds));
}

void QGpgMEQuickJob::startAddAdsk(const GpgME::Key &key, const char *adsk)
{
    run(std::bind(&addAdskWorker, std::placeholders::_1, key, adsk));
}

static QGpgMEQuickJob::result_type set_key_enabled(Context *ctx, const Key &key, bool enabled)
{
    const auto err = ctx->setKeyEnabled(key, enabled);
    return std::make_tuple(err, QString(), Error());
}

Error QGpgMEQuickJobPrivate::startSetKeyEnabled(const Key &key, bool enabled)
{
    if (key.isNull()) {
        return Error::fromCode(GPG_ERR_INV_VALUE);
    }

    q->run([=](Context *ctx) {
        return set_key_enabled(ctx, key, enabled);
    });

    return {};
}

#include "qgpgmequickjob.moc"
