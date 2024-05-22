/*
    encryptjob.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2022 g10 Code GmbH
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

#include "encryptjob.h"
#include "encryptjob_p.h"

using namespace QGpgME;

EncryptJob::EncryptJob(QObject *parent)
    : Job{parent}
{
}

EncryptJob::~EncryptJob() = default;

void EncryptJob::setFileName(const QString &fileName)
{
    auto d = jobPrivate<EncryptJobPrivate>(this);
    d->m_fileName = fileName;
}

QString EncryptJob::fileName() const
{
    auto d = jobPrivate<EncryptJobPrivate>(this);
    return d->m_fileName;
}

void EncryptJob::setInputEncoding(GpgME::Data::Encoding inputEncoding)
{
    auto d = jobPrivate<EncryptJobPrivate>(this);
    d->m_inputEncoding = inputEncoding;
}

GpgME::Data::Encoding EncryptJob::inputEncoding() const
{
    auto d = jobPrivate<EncryptJobPrivate>(this);
    return d->m_inputEncoding;
}

void EncryptJob::setRecipients(const std::vector<GpgME::Key> &recipients)
{
    auto d = jobPrivate<EncryptJobPrivate>(this);
    d->m_recipients = recipients;
}

std::vector<GpgME::Key> EncryptJob::recipients() const
{
    auto d = jobPrivate<EncryptJobPrivate>(this);
    return d->m_recipients;
}

void EncryptJob::setInputFile(const QString &path)
{
    auto d = jobPrivate<EncryptJobPrivate>(this);
    d->m_inputFilePath = path;
}

QString EncryptJob::inputFile() const
{
    auto d = jobPrivate<EncryptJobPrivate>(this);
    return d->m_inputFilePath;
}

void EncryptJob::setOutputFile(const QString &path)
{
    auto d = jobPrivate<EncryptJobPrivate>(this);
    d->m_outputFilePath = path;
}

QString EncryptJob::outputFile() const
{
    auto d = jobPrivate<EncryptJobPrivate>(this);
    return d->m_outputFilePath;
}

void EncryptJob::setEncryptionFlags(GpgME::Context::EncryptionFlags flags)
{
    auto d = jobPrivate<EncryptJobPrivate>(this);
    d->m_encryptionFlags = static_cast<GpgME::Context::EncryptionFlags>(flags | GpgME::Context::EncryptFile);
}

GpgME::Context::EncryptionFlags EncryptJob::encryptionFlags() const
{
    auto d = jobPrivate<EncryptJobPrivate>(this);
    return d->m_encryptionFlags;
}

#include "encryptjob.moc"
