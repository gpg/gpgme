/*
    qgpgmedownloadjob.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004,2008 Klarälvdalens Datakonsult AB
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

#include "qgpgmedownloadjob.h"

#include "dataprovider.h"

#include <gpgme++/context.h>
#include <gpgme++/data.h>

#include <QStringList>

#include <cassert>

using namespace QGpgME;
using namespace GpgME;

QGpgMEDownloadJob::QGpgMEDownloadJob(Context *context)
    : mixin_type(context)
{
    lateInitialization();
}

QGpgMEDownloadJob::~QGpgMEDownloadJob() {}

static QGpgMEDownloadJob::result_type download_qsl(Context *ctx, const QStringList &pats)
{
    QGpgME::QByteArrayDataProvider dp;
    Data data(&dp);

    const _detail::PatternConverter pc(pats);

    const Error err = ctx->exportPublicKeys(pc.patterns(), data);
    Error ae;
    const QString log = _detail::audit_log_as_html(ctx, ae);
    return std::make_tuple(err, dp.data(), log, ae);
}

static QGpgMEDownloadJob::result_type download(Context *ctx, QThread *thread, const QByteArray &fpr, const std::weak_ptr<QIODevice> &keyData_)
{
    const std::shared_ptr<QIODevice> keyData = keyData_.lock();
    if (!keyData) {
        return download_qsl(ctx, QStringList(QString::fromUtf8(fpr)));
    }

    const _detail::ToThreadMover kdMover(keyData, thread);

    QGpgME::QIODeviceDataProvider dp(keyData);
    Data data(&dp);

    const _detail::PatternConverter pc(fpr);

    const Error err = ctx->exportPublicKeys(pc.patterns(), data);
    Error ae;
    const QString log = _detail::audit_log_as_html(ctx, ae);
    return std::make_tuple(err, QByteArray(), log, ae);
}

Error QGpgMEDownloadJob::start(const QStringList &pats)
{
    run(std::bind(&download_qsl, std::placeholders::_1, pats));
    return Error();
}

Error QGpgMEDownloadJob::start(const QByteArray &fpr, const std::shared_ptr<QIODevice> &keyData)
{
    run(std::bind(&download, std::placeholders::_1, std::placeholders::_2, fpr, std::placeholders::_3), keyData);
    return Error();
}
#include "qgpgmedownloadjob.moc"
