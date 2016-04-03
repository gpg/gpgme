/*
    qgpgmedecryptjob.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004,2008 Klarälvdalens Datakonsult AB
    Copyright (c) 2016 Intevation GmbH

    Libkleopatra is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation; either version 2 of the
    License, or (at your option) any later version.

    Libkleopatra is distributed in the hope that it will be useful,
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

#include "qgpgmedecryptjob.h"

#include "dataprovider.h"

#include "context.h"
#include "decryptionresult.h"
#include "data.h"

#include <QBuffer>

#include <boost/weak_ptr.hpp>

#include <cassert>

using namespace QGpgME;
using namespace GpgME;
using namespace boost;

QGpgMEDecryptJob::QGpgMEDecryptJob(Context *context)
    : mixin_type(context)
{
    lateInitialization();
}

QGpgMEDecryptJob::~QGpgMEDecryptJob() {}

static QGpgMEDecryptJob::result_type decrypt(Context *ctx, QThread *thread, const weak_ptr<QIODevice> &cipherText_, const weak_ptr<QIODevice> &plainText_)
{

    const shared_ptr<QIODevice> cipherText = cipherText_.lock();
    const shared_ptr<QIODevice> plainText = plainText_.lock();

    const _detail::ToThreadMover ctMover(cipherText, thread);
    const _detail::ToThreadMover ptMover(plainText,  thread);

    QGpgME::QIODeviceDataProvider in(cipherText);
    const Data indata(&in);

    if (!plainText) {
        QGpgME::QByteArrayDataProvider out;
        Data outdata(&out);

        const DecryptionResult res = ctx->decrypt(indata, outdata);
        Error ae;
        const QString log = _detail::audit_log_as_html(ctx, ae);
        return make_tuple(res, out.data(), log, ae);
    } else {
        QGpgME::QIODeviceDataProvider out(plainText);
        Data outdata(&out);

        const DecryptionResult res = ctx->decrypt(indata, outdata);
        Error ae;
        const QString log = _detail::audit_log_as_html(ctx, ae);
        return make_tuple(res, QByteArray(), log, ae);
    }

}

static QGpgMEDecryptJob::result_type decrypt_qba(Context *ctx, const QByteArray &cipherText)
{
    const shared_ptr<QBuffer> buffer(new QBuffer);
    buffer->setData(cipherText);
    if (!buffer->open(QIODevice::ReadOnly)) {
        assert(!"This should never happen: QBuffer::open() failed");
    }
    return decrypt(ctx, 0, buffer, shared_ptr<QIODevice>());
}

Error QGpgMEDecryptJob::start(const QByteArray &cipherText)
{
    run(bind(&decrypt_qba, _1, cipherText));
    return Error();
}

void QGpgMEDecryptJob::start(const shared_ptr<QIODevice> &cipherText, const shared_ptr<QIODevice> &plainText)
{
    run(bind(&decrypt, _1, _2, _3, _4), cipherText, plainText);
}

GpgME::DecryptionResult QGpgME::QGpgMEDecryptJob::exec(const QByteArray &cipherText,
        QByteArray &plainText)
{
    const result_type r = decrypt_qba(context(), cipherText);
    plainText = get<1>(r);
    resultHook(r);
    return mResult;
}

//PENDING(marc) implement showErrorDialog()

void QGpgMEDecryptJob::resultHook(const result_type &tuple)
{
    mResult = get<0>(tuple);
}

#include "qgpgmedecryptjob.moc"
