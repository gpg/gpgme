/*
    qgpgmesignencryptjob.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004, 2007 Klarälvdalens Datakonsult AB
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

#include "qgpgmesignencryptjob.h"

#include "signencryptjob_p.h"

#include "dataprovider.h"

#include "context.h"
#include "data.h"
#include "key.h"
#include "exception.h"

#include <QBuffer>
#include <QFileInfo>

#include <cassert>

using namespace QGpgME;
using namespace GpgME;

namespace
{

class QGpgMESignEncryptJobPrivate : public SignEncryptJobPrivate
{
    QGpgMESignEncryptJob *q = nullptr;

public:
    QGpgMESignEncryptJobPrivate(QGpgMESignEncryptJob *qq)
        : q{qq}
    {
    }

    ~QGpgMESignEncryptJobPrivate() override = default;

private:
    GpgME::Error startIt() override
    {
        Q_ASSERT(!"Not supported by this Job class.");
        return Error::fromCode(GPG_ERR_NOT_SUPPORTED);
    }

    void startNow() override
    {
        q->run();
    }
};

}

QGpgMESignEncryptJob::QGpgMESignEncryptJob(Context *context)
    : mixin_type(context),
      mOutputIsBase64Encoded(false)
{
    setJobPrivate(this, std::unique_ptr<QGpgMESignEncryptJobPrivate>{new QGpgMESignEncryptJobPrivate{this}});
    lateInitialization();
}

QGpgMESignEncryptJob::~QGpgMESignEncryptJob() {}

void QGpgMESignEncryptJob::setOutputIsBase64Encoded(bool on)
{
    mOutputIsBase64Encoded = on;
}

static QGpgMESignEncryptJob::result_type sign_encrypt(Context *ctx, QThread *thread, const std::vector<Key> &signers,
                                                      const std::vector<Key> &recipients, const std::weak_ptr<QIODevice> &plainText_,
                                                      const std::weak_ptr<QIODevice> &cipherText_, const Context::EncryptionFlags eflags, bool outputIsBsse64Encoded, const QString &fileName)
{
    const std::shared_ptr<QIODevice> &plainText = plainText_.lock();
    const std::shared_ptr<QIODevice> &cipherText = cipherText_.lock();

    const _detail::ToThreadMover ctMover(cipherText, thread);
    const _detail::ToThreadMover ptMover(plainText, thread);

    QGpgME::QIODeviceDataProvider in(plainText);
    Data indata(&in);
    if (!plainText->isSequential()) {
        indata.setSizeHint(plainText->size());
    }

    const auto pureFileName = QFileInfo{fileName}.fileName().toStdString();
    if (!pureFileName.empty()) {
        indata.setFileName(pureFileName.c_str());
    }

    ctx->clearSigningKeys();
    Q_FOREACH (const Key &signer, signers)
        if (!signer.isNull())
            if (const Error err = ctx->addSigningKey(signer)) {
                return std::make_tuple(SigningResult(err), EncryptionResult(), QByteArray(), QString(), Error());
            }

    if (!cipherText) {
        QGpgME::QByteArrayDataProvider out;
        Data outdata(&out);

        if (outputIsBsse64Encoded) {
            outdata.setEncoding(Data::Base64Encoding);
        }

        const std::pair<SigningResult, EncryptionResult> res = ctx->signAndEncrypt(recipients, indata, outdata, eflags);
        Error ae;
        const QString log = _detail::audit_log_as_html(ctx, ae);
        return std::make_tuple(res.first, res.second, out.data(), log, ae);
    } else {
        QGpgME::QIODeviceDataProvider out(cipherText);
        Data outdata(&out);

        if (outputIsBsse64Encoded) {
            outdata.setEncoding(Data::Base64Encoding);
        }

        const std::pair<SigningResult, EncryptionResult> res = ctx->signAndEncrypt(recipients, indata, outdata, eflags);
        Error ae;
        const QString log = _detail::audit_log_as_html(ctx, ae);
        return std::make_tuple(res.first, res.second, QByteArray(), log, ae);
    }

}

static QGpgMESignEncryptJob::result_type sign_encrypt_qba(Context *ctx, const std::vector<Key> &signers,
                                                          const std::vector<Key> &recipients, const QByteArray &plainText, const Context::EncryptionFlags eflags, bool outputIsBsse64Encoded, const QString &fileName)
{
    const std::shared_ptr<QBuffer> buffer(new QBuffer);
    buffer->setData(plainText);
    if (!buffer->open(QIODevice::ReadOnly)) {
        assert(!"This should never happen: QBuffer::open() failed");
    }
    return sign_encrypt(ctx, nullptr, signers, recipients, buffer, std::shared_ptr<QIODevice>(), eflags, outputIsBsse64Encoded, fileName);
}

Error QGpgMESignEncryptJob::start(const std::vector<Key> &signers, const std::vector<Key> &recipients, const QByteArray &plainText, bool alwaysTrust)
{
    run(std::bind(&sign_encrypt_qba, std::placeholders::_1, signers, recipients, plainText, alwaysTrust ? Context::AlwaysTrust : Context::None, mOutputIsBase64Encoded, fileName()));
    return Error();
}

void QGpgMESignEncryptJob::start(const std::vector<Key> &signers, const std::vector<Key> &recipients,
                                 const std::shared_ptr<QIODevice> &plainText, const std::shared_ptr<QIODevice> &cipherText, const Context::EncryptionFlags eflags)
{
    run(std::bind(&sign_encrypt, std::placeholders::_1, std::placeholders::_2, signers, recipients, std::placeholders::_3, std::placeholders::_4, eflags, mOutputIsBase64Encoded, fileName()), plainText, cipherText);
}

void QGpgMESignEncryptJob::start(const std::vector<Key> &signers, const std::vector<Key> &recipients, const std::shared_ptr<QIODevice> &plainText, const std::shared_ptr<QIODevice> &cipherText, bool alwaysTrust)
{
    return start(signers, recipients, plainText, cipherText, alwaysTrust ? Context::AlwaysTrust : Context::None);
}

std::pair<SigningResult, EncryptionResult> QGpgMESignEncryptJob::exec(const std::vector<Key> &signers, const std::vector<Key> &recipients, const QByteArray &plainText, const Context::EncryptionFlags eflags, QByteArray &cipherText)
{
    const result_type r = sign_encrypt_qba(context(), signers, recipients, plainText, eflags, mOutputIsBase64Encoded, fileName());
    cipherText = std::get<2>(r);
    resultHook(r);
    return mResult;
}

std::pair<SigningResult, EncryptionResult> QGpgMESignEncryptJob::exec(const std::vector<Key> &signers, const std::vector<Key> &recipients, const QByteArray &plainText, bool alwaysTrust, QByteArray &cipherText)
{
    return exec(signers, recipients, plainText, alwaysTrust ? Context::AlwaysTrust : Context::None, cipherText);
}


#if 0

TODO port?
void QGpgMESignEncryptJob::showErrorDialog(QWidget *parent, const QString &caption) const
{
    if ((mResult.first.error()  && !mResult.first.error().isCanceled()) ||
            (mResult.second.error() && !mResult.second.error().isCanceled())) {
        MessageBox::error(parent, mResult.first, mResult.second, this, caption);
    }
}
#endif

void QGpgMESignEncryptJob::resultHook(const result_type &tuple)
{
    mResult = std::make_pair(std::get<0>(tuple), std::get<1>(tuple));
}
#include "qgpgmesignencryptjob.moc"
