/*
    qgpgmesignarchivejob.cpp

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

#include "qgpgmesignarchivejob.h"

#include "dataprovider.h"
#include "signarchivejob_p.h"
#include "filelistdataprovider.h"
#include "qgpgme_debug.h"

#include <QFile>

#include <data.h>

using namespace QGpgME;
using namespace GpgME;

namespace
{

class QGpgMESignArchiveJobPrivate : public SignArchiveJobPrivate
{
    QGpgMESignArchiveJob *q = nullptr;

public:
    QGpgMESignArchiveJobPrivate(QGpgMESignArchiveJob *qq)
        : q{qq}
    {
    }

    ~QGpgMESignArchiveJobPrivate() override = default;

private:
    GpgME::Error startIt() override;

    void startNow() override
    {
        q->run();
    }
};

}

QGpgMESignArchiveJob::QGpgMESignArchiveJob(Context *context)
    : mixin_type{context}
{
    setJobPrivate(this, std::unique_ptr<QGpgMESignArchiveJobPrivate>{new QGpgMESignArchiveJobPrivate{this}});
    lateInitialization();
    connect(this, &Job::rawProgress, this, [this](const QString &what, int type, int current, int total) {
        emitArchiveProgressSignals(this, what, type, current, total);
    });
}

static QGpgMESignArchiveJob::result_type sign(Context *ctx,
                                              const std::vector<Key> &signers,
                                              const std::vector<QString> &paths,
                                              GpgME::Data &outdata,
                                              const QString &baseDirectory)
{
    QGpgME::FileListDataProvider in{paths};
    Data indata(&in);
    if (!baseDirectory.isEmpty()) {
        indata.setFileName(baseDirectory.toStdString());
    }

    ctx->clearSigningKeys();
    for (const Key &signer : signers) {
        if (!signer.isNull()) {
            if (const Error err = ctx->addSigningKey(signer)) {
                return std::make_tuple(SigningResult{err}, QString{}, Error{});
            }
        }
    }

    const auto signingResult = ctx->sign(indata, outdata, GpgME::SignArchive);

#ifdef Q_OS_WIN
    const auto outputFileName = QString::fromUtf8(outdata.fileName());
#else
    const auto outputFileName = QFile::decodeName(outdata.fileName());
#endif
    if (!outputFileName.isEmpty() && signingResult.error().code()) {
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
    return std::make_tuple(signingResult, log, ae);
}

static QGpgMESignArchiveJob::result_type sign_to_io_device(Context *ctx,
                                                           QThread *thread,
                                                           const std::vector<Key> &signers,
                                                           const std::vector<QString> &paths,
                                                           const std::weak_ptr<QIODevice> &output_,
                                                           const QString &baseDirectory)
{
    const std::shared_ptr<QIODevice> output = output_.lock();
    const _detail::ToThreadMover ctMover(output, thread);
    QGpgME::QIODeviceDataProvider out{output};
    Data outdata(&out);

    return sign(ctx, signers, paths, outdata, baseDirectory);
}

static QGpgMESignArchiveJob::result_type sign_to_filename(Context *ctx,
                                                          const std::vector<Key> &signers,
                                                          const std::vector<QString> &paths,
                                                          const QString &outputFile,
                                                          const QString &baseDirectory)
{
    Data outdata;
#ifdef Q_OS_WIN
    outdata.setFileName(outputFile.toUtf8().constData());
#else
    outdata.setFileName(QFile::encodeName(outputFile).constData());
#endif

    return sign(ctx, signers, paths, outdata, baseDirectory);
}

GpgME::Error QGpgMESignArchiveJob::start(const std::vector<GpgME::Key> &signers,
                                            const std::vector<QString> &paths,
                                            const std::shared_ptr<QIODevice> &output)
{
    if (!output) {
        return Error::fromCode(GPG_ERR_INV_VALUE);
    }

    run(std::bind(&sign_to_io_device,
                  std::placeholders::_1,
                  std::placeholders::_2,
                  signers,
                  paths,
                  std::placeholders::_3,
                  baseDirectory()),
        output);
    return {};
}


GpgME::Error QGpgMESignArchiveJobPrivate::startIt()
{
    if (m_outputFilePath.isEmpty()) {
        return Error::fromCode(GPG_ERR_INV_VALUE);
    }

    q->run([=](Context *ctx) {
        return sign_to_filename(ctx, m_signers, m_inputPaths, m_outputFilePath, m_baseDirectory);
    });

    return {};
}

#include "qgpgmesignarchivejob.moc"
