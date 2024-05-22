/*
    signencryptjob.cpp

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

#include "signencryptjob.h"
#include "signencryptjob_p.h"

using namespace QGpgME;

SignEncryptJob::SignEncryptJob(QObject *parent)
    : Job{parent}
{
}

SignEncryptJob::~SignEncryptJob() = default;

void SignEncryptJob::setFileName(const QString &fileName)
{
    auto d = jobPrivate<SignEncryptJobPrivate>(this);
    d->m_fileName = fileName;
}

QString SignEncryptJob::fileName() const
{
    auto d = jobPrivate<SignEncryptJobPrivate>(this);
    return d->m_fileName;
}

void SignEncryptJob::setSigners(const std::vector<GpgME::Key> &signers)
{
    auto d = jobPrivate<SignEncryptJobPrivate>(this);
    d->m_signers = signers;
}

std::vector<GpgME::Key> SignEncryptJob::signers() const
{
    auto d = jobPrivate<SignEncryptJobPrivate>(this);
    return d->m_signers;
}

void SignEncryptJob::setRecipients(const std::vector<GpgME::Key> &recipients)
{
    auto d = jobPrivate<SignEncryptJobPrivate>(this);
    d->m_recipients = recipients;
}

std::vector<GpgME::Key> SignEncryptJob::recipients() const
{
    auto d = jobPrivate<SignEncryptJobPrivate>(this);
    return d->m_recipients;
}

void SignEncryptJob::setInputFile(const QString &path)
{
    auto d = jobPrivate<SignEncryptJobPrivate>(this);
    d->m_inputFilePath = path;
}

QString SignEncryptJob::inputFile() const
{
    auto d = jobPrivate<SignEncryptJobPrivate>(this);
    return d->m_inputFilePath;
}

void SignEncryptJob::setOutputFile(const QString &path)
{
    auto d = jobPrivate<SignEncryptJobPrivate>(this);
    d->m_outputFilePath = path;
}

QString SignEncryptJob::outputFile() const
{
    auto d = jobPrivate<SignEncryptJobPrivate>(this);
    return d->m_outputFilePath;
}

void SignEncryptJob::setEncryptionFlags(GpgME::Context::EncryptionFlags flags)
{
    auto d = jobPrivate<SignEncryptJobPrivate>(this);
    d->m_encryptionFlags = static_cast<GpgME::Context::EncryptionFlags>(flags | GpgME::Context::EncryptFile);
}

GpgME::Context::EncryptionFlags SignEncryptJob::encryptionFlags() const
{
    auto d = jobPrivate<SignEncryptJobPrivate>(this);
    return d->m_encryptionFlags;
}

#include "signencryptjob.moc"
