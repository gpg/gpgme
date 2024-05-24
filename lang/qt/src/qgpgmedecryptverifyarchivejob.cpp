/*
    qgpgmedecryptverifyarchivejob.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004,2008 Klarälvdalens Datakonsult AB
    Copyright (c) 2016 by Bundesamt für Sicherheit in der Informationstechnik
    Software engineering by Intevation GmbH
    Copyright (c) 2023 g10 Code GmbH
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

#include "qgpgmedecryptverifyarchivejob.h"

#include "dataprovider.h"
#include "decryptverifyarchivejob_p.h"

#include <QFile>

#include <gpgme++/data.h>

using namespace QGpgME;
using namespace GpgME;

namespace
{

class QGpgMEDecryptVerifyArchiveJobPrivate : public DecryptVerifyArchiveJobPrivate
{
    QGpgMEDecryptVerifyArchiveJob *q = nullptr;

public:
    QGpgMEDecryptVerifyArchiveJobPrivate(QGpgMEDecryptVerifyArchiveJob *qq)
        : q{qq}
    {
    }

    ~QGpgMEDecryptVerifyArchiveJobPrivate() override = default;

private:
    GpgME::Error startIt() override;

    void startNow() override
    {
        q->run();
    }
};

}

QGpgMEDecryptVerifyArchiveJob::QGpgMEDecryptVerifyArchiveJob(Context *context)
    : mixin_type{context}
{
    setJobPrivate(this, std::unique_ptr<QGpgMEDecryptVerifyArchiveJobPrivate>{new QGpgMEDecryptVerifyArchiveJobPrivate{this}});
    lateInitialization();
    connect(this, &Job::rawProgress, this, [this](const QString &what, int type, int current, int total) {
        emitArchiveProgressSignals(this, what, type, current, total);
    });
}

static QGpgMEDecryptVerifyArchiveJob::result_type decrypt_verify(Context *ctx,
                                                                 const GpgME::Data &indata,
                                                                 const QString &outputDirectory)
{
    Data outdata;
    if (!outputDirectory.isEmpty()) {
        outdata.setFileName(outputDirectory.toStdString());
    }

    const auto res = ctx->decryptAndVerify(indata, outdata, Context::DecryptArchive);
    Error ae;
    const QString log = _detail::audit_log_as_html(ctx, ae);
    return std::make_tuple(res.first, res.second, log, ae);
}

static QGpgMEDecryptVerifyArchiveJob::result_type decrypt_verify_from_io_device(Context *ctx,
                                                                                QThread *thread,
                                                                                const std::weak_ptr<QIODevice> &cipherText_,
                                                                                const QString &outputDirectory)
{
    const std::shared_ptr<QIODevice> cipherText = cipherText_.lock();
    const _detail::ToThreadMover ctMover(cipherText, thread);
    QGpgME::QIODeviceDataProvider in{cipherText};
    Data indata(&in);
    if (!cipherText->isSequential()) {
        indata.setSizeHint(cipherText->size());
    }

    return decrypt_verify(ctx, indata, outputDirectory);
}

static QGpgMEDecryptVerifyArchiveJob::result_type decrypt_verify_from_file_name(Context *ctx,
                                                                                const QString &inputFile,
                                                                                const QString &outputDirectory)
{
    Data indata;
#ifdef Q_OS_WIN
    indata.setFileName(inputFile.toUtf8().constData());
#else
    indata.setFileName(QFile::encodeName(inputFile).constData());
#endif

    return decrypt_verify(ctx, indata, outputDirectory);
}

GpgME::Error QGpgMEDecryptVerifyArchiveJob::start(const std::shared_ptr<QIODevice> &cipherText)
{
    if (!cipherText) {
        return Error::fromCode(GPG_ERR_INV_VALUE);
    }

    run(std::bind(&decrypt_verify_from_io_device,
                  std::placeholders::_1,
                  std::placeholders::_2,
                  std::placeholders::_3,
                  outputDirectory()),
        cipherText);
    return {};
}

GpgME::Error QGpgMEDecryptVerifyArchiveJobPrivate::startIt()
{
    if (m_inputFilePath.isEmpty()) {
        return Error::fromCode(GPG_ERR_INV_VALUE);
    }

    q->run([=](Context *ctx) {
        return decrypt_verify_from_file_name(ctx, m_inputFilePath, m_outputDirectory);
    });

    return {};
}

#include "qgpgmedecryptverifyarchivejob.moc"
