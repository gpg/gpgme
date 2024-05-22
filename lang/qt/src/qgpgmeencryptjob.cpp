/*
    qgpgmeencryptjob.cpp

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

#include "qgpgmeencryptjob.h"

#include "dataprovider.h"
#include "encryptjob_p.h"
#include "util.h"

#include <gpgme++/context.h>
#include <gpgme++/data.h>
#include <gpgme++/encryptionresult.h>

#include <QBuffer>
#include <QFileInfo>

#include <cassert>

using namespace QGpgME;
using namespace GpgME;

namespace
{

class QGpgMEEncryptJobPrivate : public EncryptJobPrivate
{
    QGpgMEEncryptJob *q = nullptr;

public:
    QGpgMEEncryptJobPrivate(QGpgMEEncryptJob *qq)
        : q{qq}
    {
    }

    ~QGpgMEEncryptJobPrivate() override = default;

private:
    GpgME::Error startIt() override;

    void startNow() override
    {
        q->run();
    }
};

}

QGpgMEEncryptJob::QGpgMEEncryptJob(Context *context)
    : mixin_type(context),
      mOutputIsBase64Encoded(false)
{
    setJobPrivate(this, std::unique_ptr<QGpgMEEncryptJobPrivate>{new QGpgMEEncryptJobPrivate{this}});
    lateInitialization();
}

QGpgMEEncryptJob::~QGpgMEEncryptJob() {}

void QGpgMEEncryptJob::setOutputIsBase64Encoded(bool on)
{
    mOutputIsBase64Encoded = on;
}

static QGpgMEEncryptJob::result_type encrypt(Context *ctx, QThread *thread,
        const std::vector<Key> &recipients,
        const std::weak_ptr<QIODevice> &plainText_,
        const std::weak_ptr<QIODevice> &cipherText_,
        const Context::EncryptionFlags eflags,
        bool outputIsBsse64Encoded,
        Data::Encoding inputEncoding,
        const QString &fileName)
{

    const std::shared_ptr<QIODevice> plainText = plainText_.lock();
    const std::shared_ptr<QIODevice> cipherText = cipherText_.lock();

    const _detail::ToThreadMover ctMover(cipherText, thread);
    const _detail::ToThreadMover ptMover(plainText,  thread);

    QGpgME::QIODeviceDataProvider in(plainText);
    Data indata(&in);
    indata.setEncoding(inputEncoding);

    if (!plainText->isSequential()) {
        indata.setSizeHint(plainText->size());
    }

    const auto pureFileName = QFileInfo{fileName}.fileName().toStdString();
    if (!pureFileName.empty()) {
        indata.setFileName(pureFileName.c_str());
    }

    if (!cipherText) {
        QGpgME::QByteArrayDataProvider out;
        Data outdata(&out);

        if (outputIsBsse64Encoded) {
            outdata.setEncoding(Data::Base64Encoding);
        }

        const EncryptionResult res = ctx->encrypt(recipients, indata, outdata, eflags);
        Error ae;
        const QString log = _detail::audit_log_as_html(ctx, ae);
        return std::make_tuple(res, out.data(), log, ae);
    } else {
        QGpgME::QIODeviceDataProvider out(cipherText);
        Data outdata(&out);

        if (outputIsBsse64Encoded) {
            outdata.setEncoding(Data::Base64Encoding);
        }

        const EncryptionResult res = ctx->encrypt(recipients, indata, outdata, eflags);
        Error ae;
        const QString log = _detail::audit_log_as_html(ctx, ae);
        return std::make_tuple(res, QByteArray(), log, ae);
    }

}

static QGpgMEEncryptJob::result_type encrypt_qba(Context *ctx, const std::vector<Key> &recipients, const QByteArray &plainText, const Context::EncryptionFlags eflags, bool outputIsBsse64Encoded, Data::Encoding inputEncoding, const QString &fileName)
{
    const std::shared_ptr<QBuffer> buffer(new QBuffer);
    buffer->setData(plainText);
    if (!buffer->open(QIODevice::ReadOnly)) {
        assert(!"This should never happen: QBuffer::open() failed");
    }
    return encrypt(ctx, nullptr, recipients, buffer, std::shared_ptr<QIODevice>(), eflags, outputIsBsse64Encoded, inputEncoding, fileName);
}

static QGpgMEEncryptJob::result_type encrypt_to_filename(Context *ctx,
                                                         const std::vector<Key> &recipients,
                                                         const QString &inputFilePath,
                                                         const QString &outputFilePath,
                                                         Context::EncryptionFlags flags)
{
    Data indata;
#ifdef Q_OS_WIN
    indata.setFileName(inputFilePath.toUtf8().constData());
#else
    indata.setFileName(QFile::encodeName(inputFilePath).constData());
#endif

    PartialFileGuard partFileGuard{outputFilePath};
    if (partFileGuard.tempFileName().isEmpty()) {
        return std::make_tuple(EncryptionResult{Error::fromCode(GPG_ERR_EEXIST)}, QByteArray{}, QString{}, Error{});
    }

    Data outdata;
#ifdef Q_OS_WIN
    outdata.setFileName(partFileGuard.tempFileName().toUtf8().constData());
#else
    outdata.setFileName(QFile::encodeName(partFileGuard.tempFileName()).constData());
#endif

    flags = static_cast<Context::EncryptionFlags>(flags | Context::EncryptFile);
    const auto encryptionResult = ctx->encrypt(recipients, indata, outdata, flags);

    if (!encryptionResult.error().code()) {
        // the operation succeeded -> save the result under the requested file name
        partFileGuard.commit();
    }

    Error ae;
    const QString log = _detail::audit_log_as_html(ctx, ae);
    return std::make_tuple(encryptionResult, QByteArray{}, log, ae);
}

Error QGpgMEEncryptJob::start(const std::vector<Key> &recipients, const QByteArray &plainText, bool alwaysTrust)
{
    run(std::bind(&encrypt_qba, std::placeholders::_1, recipients, plainText,
                  alwaysTrust ? Context::AlwaysTrust : Context::None, mOutputIsBase64Encoded, inputEncoding(), fileName()));
    return Error();
}

void QGpgMEEncryptJob::start(const std::vector<Key> &recipients, const std::shared_ptr<QIODevice> &plainText,
                             const std::shared_ptr<QIODevice> &cipherText, const Context::EncryptionFlags eflags)
{
    run(std::bind(&encrypt,
                    std::placeholders::_1, std::placeholders::_2,
                    recipients,
                    std::placeholders::_3, std::placeholders::_4,
                    eflags,
                    mOutputIsBase64Encoded,
                    inputEncoding(),
                    fileName()),
        plainText, cipherText);
}

EncryptionResult QGpgMEEncryptJob::exec(const std::vector<Key> &recipients, const QByteArray &plainText,
                                        const Context::EncryptionFlags eflags, QByteArray &cipherText)
{
    const result_type r = encrypt_qba(context(), recipients, plainText, eflags, mOutputIsBase64Encoded, inputEncoding(), fileName());
    cipherText = std::get<1>(r);
    return std::get<0>(r);
}

void QGpgMEEncryptJob::start(const std::vector<Key> &recipients, const std::shared_ptr<QIODevice> &plainText, const std::shared_ptr<QIODevice> &cipherText, bool alwaysTrust)
{
    return start(recipients, plainText, cipherText, alwaysTrust ? Context::AlwaysTrust : Context::None);
}

EncryptionResult QGpgMEEncryptJob::exec(const std::vector<Key> &recipients, const QByteArray &plainText, bool alwaysTrust, QByteArray &cipherText)
{
    return exec(recipients, plainText, alwaysTrust ? Context::AlwaysTrust : Context::None, cipherText);
}

GpgME::Error QGpgMEEncryptJobPrivate::startIt()
{
    if (m_inputFilePath.isEmpty() || m_outputFilePath.isEmpty()) {
        return Error::fromCode(GPG_ERR_INV_VALUE);
    }

    q->run([=](Context *ctx) {
        return encrypt_to_filename(ctx, m_recipients, m_inputFilePath, m_outputFilePath, m_encryptionFlags);
    });

    return {};
}

#include "qgpgmeencryptjob.moc"
