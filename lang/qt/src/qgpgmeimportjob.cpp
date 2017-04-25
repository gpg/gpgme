/*
    qgpgmeimportjob.cpp

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

#ifdef HAVE_CONFIG_H
 #include "config.h"
#endif

#include "qgpgmeimportjob.h"

#include "dataprovider.h"

#include "context.h"
#include "data.h"
#include "key.h"

#include <cassert>

using namespace QGpgME;
using namespace GpgME;

QGpgMEImportJob::QGpgMEImportJob(Context *context)
    : mixin_type(context)
{
    lateInitialization();
}

QGpgMEImportJob::~QGpgMEImportJob() {}

static QGpgMEImportJob::result_type import_qba(Context *ctx, const QByteArray &certData)
{
    QGpgME::QByteArrayDataProvider dp(certData);
    Data data(&dp);

    const ImportResult res = ctx->importKeys(data);
    Error ae;
    const QString log = _detail::audit_log_as_html(ctx, ae);
    return std::make_tuple(res, log, ae);
}

Error QGpgMEImportJob::start(const QByteArray &certData)
{
    run(std::bind(&import_qba, std::placeholders::_1, certData));
    return Error();
}

GpgME::ImportResult QGpgME::QGpgMEImportJob::exec(const QByteArray &keyData)
{
    const result_type r = import_qba(context(), keyData);
    resultHook(r);
    return mResult;
}

// PENDING(marc) implement showErrorDialog()

void QGpgME::QGpgMEImportJob::resultHook(const result_type &tuple)
{
    mResult = std::get<0>(tuple);
}
#include "qgpgmeimportjob.moc"
