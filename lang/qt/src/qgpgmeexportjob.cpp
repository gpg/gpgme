/*
    qgpgmeexportjob.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004,2008 Klarälvdalens Datakonsult AB
    Copyright (c) 2016 by Bundesamt für Sicherheit in der Informationstechnik
    Software engineering by Intevation GmbH
    Copyright (c) 2022 by g10 Code GmbH
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

#include "qgpgmeexportjob.h"

#include "dataprovider.h"

#include "context.h"
#include "data.h"
#include "key.h"

#include <QStringList>

#include <cassert>

using namespace QGpgME;
using namespace GpgME;

QGpgMEExportJob::QGpgMEExportJob(Context *context)
    : QGpgMEExportJob{context, 0}
{
}

QGpgMEExportJob::QGpgMEExportJob(Context *context, unsigned int forcedMode)
    : mixin_type{context}
    , m_exportMode{forcedMode}
    , m_additionalExportModeFlags{0}
{
    lateInitialization();
}

QGpgMEExportJob::~QGpgMEExportJob() = default;

static QGpgMEExportJob::result_type export_qba(Context *ctx, const QStringList &patterns, unsigned int mode)
{
    const _detail::PatternConverter pc(patterns);

    QGpgME::QByteArrayDataProvider dp;
    Data data(&dp);

    const Error err = ctx->exportKeys(pc.patterns(), data, mode);
    Error ae;
    const QString log = _detail::audit_log_as_html(ctx, ae);
    return std::make_tuple(err, dp.data(), log, ae);
}

Error QGpgMEExportJob::start(const QStringList &patterns)
{
    auto mode = m_exportMode | m_additionalExportModeFlags;
    run(std::bind(&export_qba, std::placeholders::_1, patterns, mode));
    return Error();
}

Error QGpgMEExportJob::exec(const QStringList &patterns, QByteArray &data)
{
    auto mode = m_exportMode | m_additionalExportModeFlags;
    const result_type r = export_qba(context(), patterns, mode);
    data = std::get<1>(r);
    return std::get<0>(r);
}

void QGpgMEExportJob::setExportFlags(unsigned int flags)
{
    m_additionalExportModeFlags = flags;
}

/* For ABI compat not pure virtual. */
void ExportJob::setExportFlags(unsigned int)
{
}

/* For ABI compat not pure virtual. */
GpgME::Error ExportJob::exec(const QStringList &patterns, QByteArray &data)
{
}

#include "qgpgmeexportjob.moc"
