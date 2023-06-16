/*
    qgpgmeverifyopaquejob.cpp

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

#include "qgpgmeverifyopaquejob.h"

#include "dataprovider.h"

#include "context.h"
#include "verificationresult.h"
#include "data.h"

#include <QBuffer>


#include <cassert>

using namespace QGpgME;
using namespace GpgME;

QGpgMEVerifyOpaqueJob::QGpgMEVerifyOpaqueJob(Context *context)
    : mixin_type(context)
{
    lateInitialization();
}

QGpgMEVerifyOpaqueJob::~QGpgMEVerifyOpaqueJob() {}

static QGpgMEVerifyOpaqueJob::result_type verify_opaque(Context *ctx, QThread *thread, const std::weak_ptr<QIODevice> &signedData_, const std::weak_ptr<QIODevice> &plainText_)
{

    const std::shared_ptr<QIODevice> plainText = plainText_.lock();
    const std::shared_ptr<QIODevice> signedData = signedData_.lock();

    const _detail::ToThreadMover ptMover(plainText,  thread);
    const _detail::ToThreadMover sdMover(signedData, thread);

    QGpgME::QIODeviceDataProvider in(signedData);
    Data indata(&in);
    if (!signedData->isSequential()) {
        indata.setSizeHint(signedData->size());
    }

    if (!plainText) {
        QGpgME::QByteArrayDataProvider out;
        Data outdata(&out);

        const VerificationResult res = ctx->verifyOpaqueSignature(indata, outdata);
        Error ae;
        const QString log = _detail::audit_log_as_html(ctx, ae);
        return std::make_tuple(res, out.data(), log, ae);
    } else {
        QGpgME::QIODeviceDataProvider out(plainText);
        Data outdata(&out);

        const VerificationResult res = ctx->verifyOpaqueSignature(indata, outdata);
        Error ae;
        const QString log = _detail::audit_log_as_html(ctx, ae);
        return std::make_tuple(res, QByteArray(), log, ae);
    }

}

static QGpgMEVerifyOpaqueJob::result_type verify_opaque_qba(Context *ctx, const QByteArray &signedData)
{
    const std::shared_ptr<QBuffer> buffer(new QBuffer);
    buffer->setData(signedData);
    if (!buffer->open(QIODevice::ReadOnly)) {
        assert(!"This should never happen: QBuffer::open() failed");
    }
    return verify_opaque(ctx, nullptr, buffer, std::shared_ptr<QIODevice>());
}

Error QGpgMEVerifyOpaqueJob::start(const QByteArray &signedData)
{
    run(std::bind(&verify_opaque_qba, std::placeholders::_1, signedData));
    return Error();
}

void QGpgMEVerifyOpaqueJob::start(const std::shared_ptr<QIODevice> &signedData, const std::shared_ptr<QIODevice> &plainText)
{
    run(std::bind(&verify_opaque, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4), signedData, plainText);
}

GpgME::VerificationResult QGpgME::QGpgMEVerifyOpaqueJob::exec(const QByteArray &signedData, QByteArray &plainText)
{
    const result_type r = verify_opaque_qba(context(), signedData);
    plainText = std::get<1>(r);
    resultHook(r);
    return mResult;
}

//PENDING(marc) implement showErrorDialog()

void QGpgME::QGpgMEVerifyOpaqueJob::resultHook(const result_type &tuple)
{
    mResult = std::get<0>(tuple);
}
#include "qgpgmeverifyopaquejob.moc"
