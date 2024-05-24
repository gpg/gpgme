/*
    qgpgmeverifydetachedjob.cpp

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

#include "qgpgmeverifydetachedjob.h"

#include "dataprovider.h"
#include "util.h"
#include "verifydetachedjob_p.h"

#include <QFile>

#include <gpgme++/context.h>
#include <gpgme++/data.h>
#include <gpgme++/verificationresult.h>

#include <cassert>


using namespace QGpgME;
using namespace GpgME;

namespace
{

class QGpgMEVerifyDetachedJobPrivate : public VerifyDetachedJobPrivate
{
    QGpgMEVerifyDetachedJob *q = nullptr;

public:
    QGpgMEVerifyDetachedJobPrivate(QGpgMEVerifyDetachedJob *qq)
        : q{qq}
    {
    }

    ~QGpgMEVerifyDetachedJobPrivate() override = default;

private:
    GpgME::Error startIt() override;

    void startNow() override
    {
        q->run();
    }
};

}

QGpgMEVerifyDetachedJob::QGpgMEVerifyDetachedJob(Context *context)
    : mixin_type(context)
{
    setJobPrivate(this, std::unique_ptr<QGpgMEVerifyDetachedJobPrivate>{new QGpgMEVerifyDetachedJobPrivate{this}});
    lateInitialization();
}

QGpgMEVerifyDetachedJob::~QGpgMEVerifyDetachedJob() {}

static QGpgMEVerifyDetachedJob::result_type verify_detached(Context *ctx, QThread *thread, const std::weak_ptr<QIODevice> &signature_, const std::weak_ptr<QIODevice> &signedData_)
{
    const std::shared_ptr<QIODevice> signature = signature_.lock();
    const std::shared_ptr<QIODevice> signedData = signedData_.lock();

    const _detail::ToThreadMover sgMover(signature,  thread);
    const _detail::ToThreadMover sdMover(signedData, thread);

    QGpgME::QIODeviceDataProvider sigDP(signature);
    Data sig(&sigDP);

    QGpgME::QIODeviceDataProvider dataDP(signedData);
    Data data(&dataDP);
    if (!signedData->isSequential()) {
        data.setSizeHint(signedData->size());
    }

    const VerificationResult res = ctx->verifyDetachedSignature(sig, data);
    Error ae;
    const QString log = _detail::audit_log_as_html(ctx, ae);

    return std::make_tuple(res, log, ae);
}

static QGpgMEVerifyDetachedJob::result_type verify_detached_qba(Context *ctx, const QByteArray &signature, const QByteArray &signedData)
{
    QGpgME::QByteArrayDataProvider sigDP(signature);
    Data sig(&sigDP);

    QGpgME::QByteArrayDataProvider dataDP(signedData);
    Data data(&dataDP);

    const VerificationResult res = ctx->verifyDetachedSignature(sig, data);
    Error ae;
    const QString log = _detail::audit_log_as_html(ctx, ae);

    return std::make_tuple(res, log, ae);

}

static QGpgMEVerifyDetachedJob::result_type verify_from_filename(Context *ctx,
                                                                 const QString &signatureFilePath,
                                                                 const QString &signedFilePath)
{
    Data signatureData;
#ifdef Q_OS_WIN
    signatureData.setFileName(signatureFilePath.toUtf8().constData());
#else
    signatureData.setFileName(QFile::encodeName(signatureFilePath).constData());
#endif

    Data signedData;
#ifdef Q_OS_WIN
    signedData.setFileName(signedFilePath.toUtf8().constData());
#else
    signedData.setFileName(QFile::encodeName(signedFilePath).constData());
#endif

    const auto verificationResult = ctx->verifyDetachedSignature(signatureData, signedData);

    Error ae;
    const QString log = _detail::audit_log_as_html(ctx, ae);
    return std::make_tuple(verificationResult, log, ae);
}

Error QGpgMEVerifyDetachedJob::start(const QByteArray &signature, const QByteArray &signedData)
{
    run(std::bind(&verify_detached_qba, std::placeholders::_1, signature, signedData));
    return Error();
}

void QGpgMEVerifyDetachedJob::start(const std::shared_ptr<QIODevice> &signature, const std::shared_ptr<QIODevice> &signedData)
{
    run(std::bind(&verify_detached, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4), signature, signedData);
}

GpgME::VerificationResult QGpgME::QGpgMEVerifyDetachedJob::exec(const QByteArray &signature,
        const QByteArray &signedData)
{
    const result_type r = verify_detached_qba(context(), signature, signedData);
    return std::get<0>(r);
}

GpgME::Error QGpgMEVerifyDetachedJobPrivate::startIt()
{
    if (m_signatureFilePath.isEmpty() || m_signedFilePath.isEmpty()) {
        return Error::fromCode(GPG_ERR_INV_VALUE);
    }

    q->run([=](Context *ctx) {
        return verify_from_filename(ctx, m_signatureFilePath, m_signedFilePath);
    });

    return {};
}

#include "qgpgmeverifydetachedjob.moc"
