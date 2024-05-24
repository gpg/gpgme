/*
    importjob.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2021 g10 Code GmbH
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

#include "importjob.h"
#include "importjob_p.h"

#include <gpgme++/context.h>

using namespace GpgME;
using namespace QGpgME;

void QGpgME::ImportJob::setImportFilter(const QString &filter)
{
    const auto d = jobPrivate<ImportJobPrivate>(this);
    d->m_importFilter = filter;
}

QString QGpgME::ImportJob::importFilter() const
{
    const auto d = jobPrivate<ImportJobPrivate>(this);
    return d->m_importFilter;
}

void ImportJob::setKeyOrigin(GpgME::Key::Origin origin, const QString &url)
{
    const auto d = jobPrivate<ImportJobPrivate>(this);
    d->m_keyOrigin = origin;
    d->m_keyOriginUrl = url;
}

GpgME::Key::Origin ImportJob::keyOrigin() const
{
    const auto d = jobPrivate<ImportJobPrivate>(this);
    return d->m_keyOrigin;
}

QString ImportJob::keyOriginUrl() const
{
    const auto d = jobPrivate<ImportJobPrivate>(this);
    return d->m_keyOriginUrl;
}
