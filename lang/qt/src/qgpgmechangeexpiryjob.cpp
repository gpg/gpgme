/*
    qgpgmechangeexpiryjob.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2008 Klarälvdalens Datakonsult AB
    Copyright (c) 2016 by Bundesamt für Sicherheit in der Informationstechnik
    Software engineering by Intevation GmbH

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

#include "qgpgmechangeexpiryjob.h"

#include "context.h"
#include "key.h"

#include <QDateTime>

using namespace QGpgME;
using namespace GpgME;

QGpgMEChangeExpiryJob::QGpgMEChangeExpiryJob(Context *context)
    : mixin_type(context)
{
    lateInitialization();
}

QGpgMEChangeExpiryJob::~QGpgMEChangeExpiryJob() {}

static QGpgMEChangeExpiryJob::result_type change_expiry(Context *ctx, const Key &key, const QDateTime &expiry)
{
    // convert expiry to "seconds from now"; use 1 second from now if expiry is before the current datetime
    const unsigned long expires = expiry.isValid()
       ? std::max<qint64>(QDateTime::currentDateTime().secsTo(expiry), 1)
       : 0;

    auto err = ctx->setExpire(key, expires);
    return std::make_tuple(err, QString(), Error());
}

Error QGpgMEChangeExpiryJob::start(const Key &key, const QDateTime &expiry)
{
    run(std::bind(&change_expiry, std::placeholders::_1, key, expiry));
    return Error();
}
#include "qgpgmechangeexpiryjob.moc"
