/*
    qgpgmechangeexpiryjob.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2008 Klarälvdalens Datakonsult AB
    Copyright (c) 2016 by Bundesamt für Sicherheit in der Informationstechnik
    Software engineering by Intevation GmbH
    Copyright (c) 2021,2023 g10 Code GmbH
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

#include "qgpgmechangeexpiryjob.h"

#include "changeexpiryjob_p.h"

#include <gpgme++/context.h>
#include <gpgme++/key.h>

#include <QDateTime>

using namespace QGpgME;
using namespace GpgME;

namespace
{

class QGpgMEChangeExpiryJobPrivate : public ChangeExpiryJobPrivate
{
    QGpgMEChangeExpiryJob *q = nullptr;

public:
    QGpgMEChangeExpiryJobPrivate(QGpgMEChangeExpiryJob *qq)
        : q{qq}
    {
    }

    ~QGpgMEChangeExpiryJobPrivate() override = default;

private:
    GpgME::Error startIt() override
    {
        Q_ASSERT(!"Not supported by this Job class.");
        return Error::fromCode(GPG_ERR_NOT_SUPPORTED);
    }

    void startNow() override
    {
        q->run();
    }
};

}

QGpgMEChangeExpiryJob::QGpgMEChangeExpiryJob(Context *context)
    : mixin_type(context)
{
    setJobPrivate(this, std::unique_ptr<QGpgMEChangeExpiryJobPrivate>{new QGpgMEChangeExpiryJobPrivate{this}});
    lateInitialization();
}

QGpgMEChangeExpiryJob::~QGpgMEChangeExpiryJob() {}

static QGpgMEChangeExpiryJob::result_type change_expiry(Context *ctx, const Key &key, const QDateTime &expiry,
    const std::vector<Subkey> &subkeys, ChangeExpiryJob::Options options)
{
    // convert expiry to "seconds from now"; use 1 second from now if expiry is before the current datetime
    const unsigned long expires = expiry.isValid()
       ? std::max<qint64>(QDateTime::currentDateTime().secsTo(expiry), 1)
       : 0;

    // updating the expiration date of the primary key and the subkeys needs to be done in two steps
    // because --quick-set-expire does not support updating the expiration date of both at the same time

    if (subkeys.empty() || (options & ChangeExpiryJob::UpdatePrimaryKey)) {
        // update the expiration date of the primary key
        auto err = ctx->setExpire(key, expires);
        if (err || err.isCanceled()) {
            return std::make_tuple(err, QString(), Error());
        }
    }

    GpgME::Error err;
    if (!subkeys.empty()) {
        // update the expiration date of the specified subkeys
        err = ctx->setExpire(key, expires, subkeys);
    } else if (options & ChangeExpiryJob::UpdateAllSubkeys) {
        // update the expiration date of all subkeys
        err = ctx->setExpire(key, expires, {}, Context::SetExpireAllSubkeys);
    }
    return std::make_tuple(err, QString(), Error());
}

Error QGpgMEChangeExpiryJob::start(const Key &key, const QDateTime &expiry)
{
    return start(key, expiry, std::vector<Subkey>());
}

Error QGpgMEChangeExpiryJob::start(const Key &key, const QDateTime &expiry, const std::vector<Subkey> &subkeys)
{
    run(std::bind(&change_expiry, std::placeholders::_1, key, expiry, subkeys, options()));
    return Error();
}

#include "qgpgmechangeexpiryjob.moc"
