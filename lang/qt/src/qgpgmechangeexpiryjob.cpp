/*
    qgpgmechangeexpiryjob.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2008 Klarälvdalens Datakonsult AB
    Copyright (c) 2016 Intevation GmbH

    Libkleopatra is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation; either version 2 of the
    License, or (at your option) any later version.

    Libkleopatra is distributed in the hope that it will be useful,
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

#include "dataprovider.h"

#include "context.h"
#include "data.h"
#include "gpgsetexpirytimeeditinteractor.h"
#include "key.h"

#include <QDateTime>

#include <cassert>
#include <memory>
#include <string>

using namespace QGpgME;
using namespace GpgME;
using namespace boost;

QGpgMEChangeExpiryJob::QGpgMEChangeExpiryJob(Context *context)
    : mixin_type(context)
{
    lateInitialization();
}

QGpgMEChangeExpiryJob::~QGpgMEChangeExpiryJob() {}

static QGpgMEChangeExpiryJob::result_type change_expiry(Context *ctx, const Key &key, const QDateTime &expiry)
{
    std::auto_ptr<EditInteractor>
    ei(expiry.isValid()
       ? new GpgSetExpiryTimeEditInteractor(expiry.date().toString(Qt::ISODate).toStdString())
       : new GpgSetExpiryTimeEditInteractor());

    QGpgME::QByteArrayDataProvider dp;
    Data data(&dp);
    assert(!data.isNull());
    const Error err = ctx->edit(key, ei, data);
    Error ae;
    const QString log = _detail::audit_log_as_html(ctx, ae);
    return make_tuple(err, log, ae);
}

Error QGpgMEChangeExpiryJob::start(const Key &key, const QDateTime &expiry)
{
    run(bind(&change_expiry, _1, key, expiry));
    return Error();
}
#include "qgpgmechangeexpiryjob.moc"
