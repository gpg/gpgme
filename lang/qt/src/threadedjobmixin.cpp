/*
    threadedjobmixin.cpp

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

#include "threadedjobmixin.h"

#include "dataprovider.h"

#include <gpgme++/data.h>

#include <QString>
#include <QStringList>
#include <QByteArray>


#include <algorithm>
#include <iterator>

using namespace QGpgME;
using namespace GpgME;

static QString stringFromGpgOutput(const QByteArray &ba)
{
#ifdef Q_OS_WIN
    return QString::fromUtf8(ba);
#else
    return QString::fromLocal8Bit(ba);
#endif
}

static QString markupDiagnostics(const QString &data)
{
    // First ensure that we don't have html in the diag.
    QString ret = QStringLiteral("<pre>%1</pre>").arg(data.toHtmlEscaped());

    return ret;
}

static const unsigned int CMSAuditLogFlags = Context::AuditLogWithHelp | Context::HtmlAuditLog;
static const unsigned int OpenPGPAuditLogFlags = Context::DiagnosticAuditLog;

QString _detail::audit_log_as_html(Context *ctx, GpgME::Error &err)
{
    assert(ctx);
    QGpgME::QByteArrayDataProvider dp;
    Data data(&dp);
    assert(!data.isNull());

    if (ctx->protocol() == OpenPGP) {
        if ((err = ctx->getAuditLog(data, OpenPGPAuditLogFlags))) {
            return QString::fromLocal8Bit(err.asString());
        }
        const QByteArray ba = dp.data();
        return markupDiagnostics(stringFromGpgOutput(ba));
    }

    if (ctx->protocol() == CMS) {
        if ((err = ctx->lastError())) {
            if ((err = ctx->getAuditLog(data, Context::DiagnosticAuditLog))) {
                return QString::fromLocal8Bit(err.asString());
            }
            const QByteArray ba = dp.data();
            return markupDiagnostics(stringFromGpgOutput(ba));
        } else if ((err = ctx->getAuditLog(data, CMSAuditLogFlags))) {
            return QString::fromLocal8Bit(err.asString());
        }
        return QString::fromUtf8(dp.data());
    }

    return QStringLiteral("Unsupported protocol for Audit Log");
}

static QList<QByteArray> from_sl(const QStringList &sl)
{
    QList<QByteArray> result;
    for (const QString &str : sl) {
        result.append(str.toUtf8());
    }

#if 0
    std::transform(sl.begin(), sl.end(), std::back_inserter(result),
                   mem_fn(static_cast<QByteArray()const>(&QString::toUtf8)));
#endif
    return result;
}

static QList<QByteArray> single(const QByteArray &ba)
{
    QList<QByteArray> result;
    result.push_back(ba);
    return result;
}

_detail::PatternConverter::PatternConverter(const QByteArray &ba)
    : m_list(single(ba)), m_patterns(nullptr) {}
_detail::PatternConverter::PatternConverter(const QString &s)
    : m_list(single(s.toUtf8())), m_patterns(nullptr) {}
_detail::PatternConverter::PatternConverter(const QList<QByteArray> &lba)
    : m_list(lba), m_patterns(nullptr) {}
_detail::PatternConverter::PatternConverter(const QStringList &sl)
    :  m_list(from_sl(sl)), m_patterns(nullptr) {}

const char **_detail::PatternConverter::patterns() const
{
    if (!m_patterns) {
        m_patterns = new const char *[ m_list.size() + 1 ];
        const char **end = std::transform(m_list.begin(), m_list.end(), m_patterns,
                                          std::mem_fn(&QByteArray::constData));
        *end = nullptr;
    }
    return m_patterns;
}

_detail::PatternConverter::~PatternConverter()
{
    delete [] m_patterns;
}
