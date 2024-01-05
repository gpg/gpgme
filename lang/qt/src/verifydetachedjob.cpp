/*
    verifydetachedjob.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2024 g10 Code GmbH
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

#include "verifydetachedjob.h"
#include "verifydetachedjob_p.h"

using namespace QGpgME;

VerifyDetachedJob::VerifyDetachedJob(QObject *parent)
    : Job{parent}
{
}

VerifyDetachedJob::~VerifyDetachedJob() = default;

void VerifyDetachedJob::setSignatureFile(const QString &path)
{
    auto d = jobPrivate<VerifyDetachedJobPrivate>(this);
    d->m_signatureFilePath = path;
}

QString VerifyDetachedJob::signatureFile() const
{
    auto d = jobPrivate<VerifyDetachedJobPrivate>(this);
    return d->m_signatureFilePath;
}

void VerifyDetachedJob::setSignedFile(const QString &path)
{
    auto d = jobPrivate<VerifyDetachedJobPrivate>(this);
    d->m_signedFilePath = path;
}

QString VerifyDetachedJob::signedFile() const
{
    auto d = jobPrivate<VerifyDetachedJobPrivate>(this);
    return d->m_signedFilePath;
}

#include "verifydetachedjob.moc"
