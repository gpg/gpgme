/*
    qgpgmesignjob.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004,2007,2008 Klarälvdalens Datakonsult AB
    Copyright (c) 2016 by Bundesamt für Sicherheit in der Informationstechnik
    Software engineering by Intevation GmbH

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

#include "qgpgmesignjob.h"

#include "dataprovider.h"

#include "context.h"
#include "signingresult.h"
#include "data.h"

#include <QBuffer>


#include <cassert>

using namespace QGpgME;
using namespace GpgME;

QGpgMESignJob::QGpgMESignJob(Context *context)
    : mixin_type(context),
      mOutputIsBase64Encoded(false)
{
    lateInitialization();
}

QGpgMESignJob::~QGpgMESignJob() {}

void QGpgMESignJob::setOutputIsBase64Encoded(bool on)
{
    mOutputIsBase64Encoded = on;
}

static QGpgMESignJob::result_type sign(Context *ctx, QThread *thread,
                                       const std::vector<Key> &signers,
                                       const std::weak_ptr<QIODevice> &plainText_,
                                       const std::weak_ptr<QIODevice> &signature_,
                                       SignatureMode mode,
                                       bool outputIsBsse64Encoded)
{

    const std::shared_ptr<QIODevice> plainText = plainText_.lock();
    const std::shared_ptr<QIODevice> signature = signature_.lock();

    const _detail::ToThreadMover ptMover(plainText, thread);
    const _detail::ToThreadMover sgMover(signature, thread);

    QGpgME::QIODeviceDataProvider in(plainText);
    Data indata(&in);
    if (!plainText->isSequential()) {
        indata.setSizeHint(plainText->size());
    }

    ctx->clearSigningKeys();
    Q_FOREACH (const Key &signer, signers)
        if (!signer.isNull())
            if (const Error err = ctx->addSigningKey(signer)) {
                return std::make_tuple(SigningResult(err), QByteArray(), QString(), Error());
            }

    if (!signature) {
        QGpgME::QByteArrayDataProvider out;
        Data outdata(&out);

        if (outputIsBsse64Encoded) {
            outdata.setEncoding(Data::Base64Encoding);
        }

        const SigningResult res = ctx->sign(indata, outdata, mode);
        Error ae;
        const QString log = _detail::audit_log_as_html(ctx, ae);
        return std::make_tuple(res, out.data(), log, ae);
    } else {
        QGpgME::QIODeviceDataProvider out(signature);
        Data outdata(&out);

        if (outputIsBsse64Encoded) {
            outdata.setEncoding(Data::Base64Encoding);
        }

        const SigningResult res = ctx->sign(indata, outdata, mode);
        Error ae;
        const QString log = _detail::audit_log_as_html(ctx, ae);
        return std::make_tuple(res, QByteArray(), log, ae);
    }

}

static QGpgMESignJob::result_type sign_qba(Context *ctx,
        const std::vector<Key> &signers,
        const QByteArray &plainText,
        SignatureMode mode,
        bool outputIsBsse64Encoded)
{
    const std::shared_ptr<QBuffer> buffer(new QBuffer);
    buffer->setData(plainText);
    if (!buffer->open(QIODevice::ReadOnly)) {
        assert(!"This should never happen: QBuffer::open() failed");
    }
    return sign(ctx, nullptr, signers, buffer, std::shared_ptr<QIODevice>(), mode, outputIsBsse64Encoded);
}

Error QGpgMESignJob::start(const std::vector<Key> &signers, const QByteArray &plainText, SignatureMode mode)
{
    run(std::bind(&sign_qba, std::placeholders::_1, signers, plainText, mode, mOutputIsBase64Encoded));
    return Error();
}

void QGpgMESignJob::start(const std::vector<Key> &signers, const std::shared_ptr<QIODevice> &plainText, const std::shared_ptr<QIODevice> &signature, SignatureMode mode)
{
    run(std::bind(&sign, std::placeholders::_1, std::placeholders::_2, signers, std::placeholders::_3, std::placeholders::_4, mode, mOutputIsBase64Encoded), plainText, signature);
}

SigningResult QGpgMESignJob::exec(const std::vector<Key> &signers, const QByteArray &plainText, SignatureMode mode, QByteArray &signature)
{
    const result_type r = sign_qba(context(), signers, plainText, mode, mOutputIsBase64Encoded);
    signature = std::get<1>(r);
    resultHook(r);
    return mResult;
}

void QGpgMESignJob::resultHook(const result_type &tuple)
{
    mResult = std::get<0>(tuple);
}

#if 0
TODO port
void QGpgMESignJob::showErrorDialog(QWidget *parent, const QString &caption) const
{
    if (mResult.error() && !mResult.error().isCanceled()) {
        MessageBox::error(parent, mResult, this, caption);
    }
}
#endif
#include "qgpgmesignjob.moc"
