/*
    qgpgmeencryptarchivejob.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004,2007,2008 Klarälvdalens Datakonsult AB
    Copyright (c) 2016 by Bundesamt für Sicherheit in der Informationstechnik
    Software engineering by Intevation GmbH
    Copyright (c) 2022,2023 g10 Code GmbH
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

#include "qgpgmeencryptarchivejob.h"

#include "dataprovider.h"
#include "encryptarchivejob_p.h"
#include "filelistdataprovider.h"
#include "qgpgme_debug.h"

#include <QFile>

#include <data.h>

using namespace QGpgME;
using namespace GpgME;

namespace
{

class QGpgMEEncryptArchiveJobPrivate : public EncryptArchiveJobPrivate
{
    QGpgMEEncryptArchiveJob *q = nullptr;

public:
    QGpgMEEncryptArchiveJobPrivate(QGpgMEEncryptArchiveJob *qq)
        : q{qq}
    {
    }

    ~QGpgMEEncryptArchiveJobPrivate() override = default;

private:
    GpgME::Error startIt() override;

    void startNow() override
    {
        q->run();
    }
};

}

QGpgMEEncryptArchiveJob::QGpgMEEncryptArchiveJob(Context *context)
    : mixin_type{context}
{
    setJobPrivate(this, std::unique_ptr<QGpgMEEncryptArchiveJobPrivate>{new QGpgMEEncryptArchiveJobPrivate{this}});
    lateInitialization();
    connect(this, &Job::rawProgress, this, [this](const QString &what, int type, int current, int total) {
        emitArchiveProgressSignals(this, what, type, current, total);
    });
}

static QGpgMEEncryptArchiveJob::result_type encrypt(Context *ctx,
                                                    const std::vector<Key> &recipients,
                                                    const std::vector<QString> &paths,
                                                    GpgME::Data &outdata,
                                                    Context::EncryptionFlags flags,
                                                    const QString &baseDirectory)
{
    QGpgME::FileListDataProvider in{paths};
    Data indata(&in);
    if (!baseDirectory.isEmpty()) {
        indata.setFileName(baseDirectory.toStdString());
    }

    flags = static_cast<Context::EncryptionFlags>(flags | Context::EncryptArchive);
    const auto encryptionResult = ctx->encrypt(recipients, indata, outdata, flags);

#ifdef Q_OS_WIN
    const auto outputFileName = QString::fromUtf8(outdata.fileName());
#else
    const auto outputFileName = QFile::decodeName(outdata.fileName());
#endif
    if (!outputFileName.isEmpty() && encryptionResult.error().code()) {
        // ensure that the output file is removed if the operation was canceled or failed
        if (QFile::exists(outputFileName)) {
            qCDebug(QGPGME_LOG) << __func__ << "Removing output file" << outputFileName << "after error or cancel";
            if (!QFile::remove(outputFileName)) {
                qCDebug(QGPGME_LOG) << __func__ << "Removing output file" << outputFileName << "failed";
            }
        }
    }
    Error ae;
    const QString log = _detail::audit_log_as_html(ctx, ae);
    return std::make_tuple(encryptionResult, log, ae);
}

static QGpgMEEncryptArchiveJob::result_type encrypt_to_io_device(Context *ctx,
                                                                 QThread *thread,
                                                                 const std::vector<Key> &recipients,
                                                                 const std::vector<QString> &paths,
                                                                 const std::weak_ptr<QIODevice> &cipherText_,
                                                                 Context::EncryptionFlags flags,
                                                                 const QString &baseDirectory)
{
    const std::shared_ptr<QIODevice> cipherText = cipherText_.lock();
    const _detail::ToThreadMover ctMover(cipherText, thread);
    QGpgME::QIODeviceDataProvider out{cipherText};
    Data outdata(&out);

    return encrypt(ctx, recipients, paths, outdata, flags, baseDirectory);
}

static QGpgMEEncryptArchiveJob::result_type encrypt_to_filename(Context *ctx,
                                                                const std::vector<Key> &recipients,
                                                                const std::vector<QString> &paths,
                                                                const QString &outputFile,
                                                                Context::EncryptionFlags flags,
                                                                const QString &baseDirectory)
{
    Data outdata;
#ifdef Q_OS_WIN
    outdata.setFileName(outputFile.toUtf8().constData());
#else
    outdata.setFileName(QFile::encodeName(outputFile).constData());
#endif

    return encrypt(ctx, recipients, paths, outdata, flags, baseDirectory);
}

GpgME::Error QGpgMEEncryptArchiveJob::start(const std::vector<GpgME::Key> &recipients,
                                            const std::vector<QString> &paths,
                                            const std::shared_ptr<QIODevice> &cipherText,
                                            const GpgME::Context::EncryptionFlags flags)
{
    if (!cipherText) {
        return Error::fromCode(GPG_ERR_INV_VALUE);
    }

    run(std::bind(&encrypt_to_io_device,
                  std::placeholders::_1,
                  std::placeholders::_2,
                  recipients,
                  paths,
                  std::placeholders::_3,
                  flags,
                  baseDirectory()),
        cipherText);
    return {};
}

GpgME::Error QGpgMEEncryptArchiveJobPrivate::startIt()
{
    if (m_outputFilePath.isEmpty()) {
        return Error::fromCode(GPG_ERR_INV_VALUE);
    }

    q->run([=](Context *ctx) {
        return encrypt_to_filename(ctx, m_recipients, m_inputPaths, m_outputFilePath, m_encryptionFlags, m_baseDirectory);
    });

    return {};
}

#include "qgpgmeencryptarchivejob.moc"
