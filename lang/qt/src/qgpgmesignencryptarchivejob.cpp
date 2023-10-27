/*
    qgpgmesignencryptarchivejob.cpp

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

#include "qgpgmesignencryptarchivejob.h"

#include "dataprovider.h"
#include "signencryptarchivejob_p.h"
#include "filelistdataprovider.h"
#include "qgpgme_debug.h"
#include "util.h"

#include <QFile>

#include <data.h>

using namespace QGpgME;
using namespace GpgME;

namespace
{

class QGpgMESignEncryptArchiveJobPrivate : public SignEncryptArchiveJobPrivate
{
    QGpgMESignEncryptArchiveJob *q = nullptr;

public:
    QGpgMESignEncryptArchiveJobPrivate(QGpgMESignEncryptArchiveJob *qq)
        : q{qq}
    {
    }

    ~QGpgMESignEncryptArchiveJobPrivate() override = default;

private:
    GpgME::Error startIt() override;

    void startNow() override
    {
        q->run();
    }
};

}

QGpgMESignEncryptArchiveJob::QGpgMESignEncryptArchiveJob(Context *context)
    : mixin_type{context}
{
    setJobPrivate(this, std::unique_ptr<QGpgMESignEncryptArchiveJobPrivate>{new QGpgMESignEncryptArchiveJobPrivate{this}});
    lateInitialization();
    connect(this, &Job::rawProgress, this, [this](const QString &what, int type, int current, int total) {
        emitArchiveProgressSignals(this, what, type, current, total);
    });
}

static QGpgMESignEncryptArchiveJob::result_type sign_encrypt(Context *ctx,
                                                             const std::vector<GpgME::Key> &signers,
                                                             const std::vector<Key> &recipients,
                                                             const std::vector<QString> &paths,
                                                             GpgME::Data &outdata,
                                                             Context::EncryptionFlags encryptionFlags,
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
                return std::make_tuple(SigningResult{err}, EncryptionResult{}, QString{}, Error{});
            }
        }
    }

    encryptionFlags = static_cast<Context::EncryptionFlags>(encryptionFlags | Context::EncryptArchive);
    const auto res = ctx->signAndEncrypt(recipients, indata, outdata, encryptionFlags);
    const auto &signingResult = res.first;
    const auto &encryptionResult = res.second;

    Error ae;
    const QString log = _detail::audit_log_as_html(ctx, ae);
    return std::make_tuple(signingResult, encryptionResult, log, ae);
}

static QGpgMESignEncryptArchiveJob::result_type sign_encrypt_to_io_device(Context *ctx,
                                                                          QThread *thread,
                                                                          const std::vector<GpgME::Key> &signers,
                                                                          const std::vector<Key> &recipients,
                                                                          const std::vector<QString> &paths,
                                                                          const std::weak_ptr<QIODevice> &cipherText_,
                                                                          Context::EncryptionFlags encryptionFlags,
                                                                          const QString &baseDirectory)
{
    const std::shared_ptr<QIODevice> cipherText = cipherText_.lock();
    const _detail::ToThreadMover ctMover(cipherText, thread);
    QGpgME::QIODeviceDataProvider out{cipherText};
    Data outdata(&out);

    return sign_encrypt(ctx, signers, recipients, paths, outdata, encryptionFlags, baseDirectory);
}

static QGpgMESignEncryptArchiveJob::result_type sign_encrypt_to_filename(Context *ctx,
                                                                         const std::vector<GpgME::Key> &signers,
                                                                         const std::vector<Key> &recipients,
                                                                         const std::vector<QString> &paths,
                                                                         const QString &outputFileName,
                                                                         Context::EncryptionFlags encryptionFlags,
                                                                         const QString &baseDirectory)
{
    Data outdata;
#ifdef Q_OS_WIN
    outdata.setFileName(outputFileName.toUtf8().constData());
#else
    outdata.setFileName(QFile::encodeName(outputFileName).constData());
#endif

    const auto result = sign_encrypt(ctx, signers, recipients, paths, outdata, encryptionFlags, baseDirectory);
    const auto &signingResult = std::get<0>(result);
    const auto &encryptionResult = std::get<1>(result);
    if (signingResult.error().code() || encryptionResult.error().code()) {
        // ensure that the output file is removed if the operation was canceled or failed
        removeFile(outputFileName);
    }

    return result;
}

GpgME::Error QGpgMESignEncryptArchiveJob::start(const std::vector<GpgME::Key> &signers,
                                                const std::vector<GpgME::Key> &recipients,
                                                const std::vector<QString> &paths,
                                                const std::shared_ptr<QIODevice> &cipherText,
                                                const GpgME::Context::EncryptionFlags encryptionFlags)
{
    if (!cipherText) {
        return Error::fromCode(GPG_ERR_INV_VALUE);
    }

    run(std::bind(&sign_encrypt_to_io_device,
                  std::placeholders::_1,
                  std::placeholders::_2,
                  signers,
                  recipients,
                  paths,
                  std::placeholders::_3,
                  encryptionFlags,
                  baseDirectory()),
        cipherText);
    return {};
}

GpgME::Error QGpgMESignEncryptArchiveJobPrivate::startIt()
{
    if (m_outputFilePath.isEmpty()) {
        return Error::fromCode(GPG_ERR_INV_VALUE);
    }

    q->run([=](Context *ctx) {
        return sign_encrypt_to_filename(ctx, m_signers, m_recipients, m_inputPaths, m_outputFilePath, m_encryptionFlags, m_baseDirectory);
    });

    return {};
}

#include "qgpgmesignencryptarchivejob.moc"
