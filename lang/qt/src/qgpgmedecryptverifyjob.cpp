/*
    qgpgmedecryptverifyjob.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004,2008 Klarälvdalens Datakonsult AB
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

#include "qgpgmedecryptverifyjob.h"

#include "dataprovider.h"

#include "context.h"
#include "decryptionresult.h"
#include "verificationresult.h"
#include "data.h"

#include <QDebug>
#include "qgpgme_debug.h"

#include <QBuffer>

#include <cassert>

using namespace QGpgME;
using namespace GpgME;

QGpgMEDecryptVerifyJob::QGpgMEDecryptVerifyJob(Context *context)
    : mixin_type(context)
{
    lateInitialization();
}

QGpgMEDecryptVerifyJob::~QGpgMEDecryptVerifyJob() {}

static QGpgMEDecryptVerifyJob::result_type decrypt_verify(Context *ctx, QThread *thread,
                                                          const std::weak_ptr<QIODevice> &cipherText_,
                                                          const std::weak_ptr<QIODevice> &plainText_)
{
    qCDebug(QGPGME_LOG) << __func__;

    const std::shared_ptr<QIODevice> cipherText = cipherText_.lock();
    const std::shared_ptr<QIODevice> plainText = plainText_.lock();

    const _detail::ToThreadMover ctMover(cipherText, thread);
    const _detail::ToThreadMover ptMover(plainText,  thread);

    QGpgME::QIODeviceDataProvider in(cipherText);
    Data indata(&in);
    if (!cipherText->isSequential()) {
        indata.setSizeHint(cipherText->size());
    }

    if (!plainText) {
        QGpgME::QByteArrayDataProvider out;
        Data outdata(&out);

        const std::pair<DecryptionResult, VerificationResult> res = ctx->decryptAndVerify(indata, outdata);
        Error ae;
        const QString log = _detail::audit_log_as_html(ctx, ae);
        qCDebug(QGPGME_LOG) << __func__ << "- End no plainText. Error:" << ae.asString();
        return std::make_tuple(res.first, res.second, out.data(), log, ae);
    } else {
        QGpgME::QIODeviceDataProvider out(plainText);
        Data outdata(&out);

        const std::pair<DecryptionResult, VerificationResult> res = ctx->decryptAndVerify(indata, outdata);
        Error ae;
        const QString log = _detail::audit_log_as_html(ctx, ae);
        qCDebug(QGPGME_LOG) << __func__ << "- End plainText. Error:" << ae.asString();
        return std::make_tuple(res.first, res.second, QByteArray(), log, ae);
    }
}

static QGpgMEDecryptVerifyJob::result_type decrypt_verify_qba(Context *ctx, const QByteArray &cipherText)
{
    const std::shared_ptr<QBuffer> buffer(new QBuffer);
    buffer->setData(cipherText);
    if (!buffer->open(QIODevice::ReadOnly)) {
        assert(!"This should never happen: QBuffer::open() failed");
    }
    return decrypt_verify(ctx, nullptr, buffer, std::shared_ptr<QIODevice>());
}

Error QGpgMEDecryptVerifyJob::start(const QByteArray &cipherText)
{
    run(std::bind(&decrypt_verify_qba, std::placeholders::_1, cipherText));
    return Error();
}

void QGpgMEDecryptVerifyJob::start(const std::shared_ptr<QIODevice> &cipherText, const std::shared_ptr<QIODevice> &plainText)
{
    run(std::bind(&decrypt_verify, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4), cipherText, plainText);
}

std::pair<GpgME::DecryptionResult, GpgME::VerificationResult>
QGpgME::QGpgMEDecryptVerifyJob::exec(const QByteArray &cipherText, QByteArray &plainText)
{
    const result_type r = decrypt_verify_qba(context(), cipherText);
    plainText = std::get<2>(r);
    resultHook(r);
    return mResult;
}

//PENDING(marc) implement showErrorDialog()

void QGpgMEDecryptVerifyJob::resultHook(const result_type &tuple)
{
    mResult = std::make_pair(std::get<0>(tuple), std::get<1>(tuple));
}
#include "qgpgmedecryptverifyjob.moc"
