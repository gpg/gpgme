/*
    qgpgmeadduseridjob.cpp

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

#include "qgpgmeadduseridjob.h"

#include "dataprovider.h"

#include <gpgme++/context.h>
#include <gpgme++/data.h>
#include <gpgme++/gpgadduserideditinteractor.h>
#include <gpgme++/key.h>

#include <cassert>
#include <memory>

using namespace QGpgME;
using namespace GpgME;

QGpgMEAddUserIDJob::QGpgMEAddUserIDJob(Context *context)
    : mixin_type(context)
{
    lateInitialization();
}

QGpgMEAddUserIDJob::~QGpgMEAddUserIDJob() {}

static QGpgMEAddUserIDJob::result_type add_user_id(Context *ctx, const Key &key, const QString &name, const QString &email, const QString &comment)
{

    GpgAddUserIDEditInteractor *gau = new GpgAddUserIDEditInteractor;

    gau->setNameUtf8(name.toUtf8().constData());
    gau->setEmailUtf8(email.toUtf8().constData());
    gau->setCommentUtf8(comment.toUtf8().constData());

    QGpgME::QByteArrayDataProvider dp;
    Data data(&dp);
    assert(!data.isNull());
    const Error err = ctx->edit(key, std::unique_ptr<EditInteractor> (gau), data);
    Error ae;
    const QString log = _detail::audit_log_as_html(ctx, ae);
    return std::make_tuple(err, log, ae);
}

Error QGpgMEAddUserIDJob::start(const Key &key, const QString &name, const QString &email, const QString &comment)
{
    run(std::bind(&add_user_id, std::placeholders::_1, key, name, email, comment));
    return Error();
}
#include "qgpgmeadduseridjob.moc"
