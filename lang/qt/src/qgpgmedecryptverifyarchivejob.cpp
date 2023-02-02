/*
    qgpgmedecryptverifyarchivejob.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004,2008 Klarälvdalens Datakonsult AB
    Copyright (c) 2016 by Bundesamt für Sicherheit in der Informationstechnik
    Software engineering by Intevation GmbH
    Copyright (c) 2023 g10 Code GmbH
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

#include "qgpgmedecryptverifyarchivejob.h"

#include "dataprovider.h"
#include "decryptverifyarchivejob_p.h"

#include <data.h>

using namespace QGpgME;
using namespace GpgME;

namespace
{

class QGpgMEDecryptVerifyArchiveJobPrivate : public DecryptVerifyArchiveJobPrivate
{
    QGpgMEDecryptVerifyArchiveJob *q = nullptr;

public:
    QGpgMEDecryptVerifyArchiveJobPrivate(QGpgMEDecryptVerifyArchiveJob *qq)
        : q{qq}
    {
    }

    ~QGpgMEDecryptVerifyArchiveJobPrivate() override = default;

private:
    void start() override
    {
        q->run();
    }
};

}

QGpgMEDecryptVerifyArchiveJob::QGpgMEDecryptVerifyArchiveJob(Context *context)
    : mixin_type{context}
{
    setJobPrivate(this, std::unique_ptr<QGpgMEDecryptVerifyArchiveJobPrivate>{new QGpgMEDecryptVerifyArchiveJobPrivate{this}});
    lateInitialization();
}

static QGpgMEDecryptVerifyArchiveJob::result_type decrypt_verify(Context *ctx,
                                                                 QThread *thread,
                                                                 const std::weak_ptr<QIODevice> &cipherText_,
                                                                 const QString &outputDirectory)
{
    const std::shared_ptr<QIODevice> cipherText = cipherText_.lock();
    const _detail::ToThreadMover ctMover(cipherText, thread);

    QGpgME::QIODeviceDataProvider in{cipherText};
    Data indata(&in);

    Data outdata;
    if (!outputDirectory.isEmpty()) {
        outdata.setFileName(outputDirectory.toStdString());
    }

    const auto res = ctx->decryptAndVerify(indata, outdata, Context::DecryptArchive);
    Error ae;
    const QString log = _detail::audit_log_as_html(ctx, ae);
    return std::make_tuple(res.first, res.second, log, ae);
}

GpgME::Error QGpgMEDecryptVerifyArchiveJob::start(const std::shared_ptr<QIODevice> &cipherText)
{
    if (!cipherText) {
        return Error::fromCode(GPG_ERR_INV_VALUE);
    }

    run(std::bind(&decrypt_verify,
                  std::placeholders::_1,
                  std::placeholders::_2,
                  std::placeholders::_3,
                  outputDirectory()),
        cipherText);
    return {};
}

#include "qgpgmedecryptverifyarchivejob.moc"
