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

// #include <context.h>
#include <data.h>
// #include <encryptionresult.h>
//
// #include <QBuffer>
// #include <QFileInfo>
//
// #include <cassert>

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

    QGpgME::FileListDataProvider in{paths};
    Data indata(&in);
    if (!baseDirectory.isEmpty()) {
        indata.setFileName(baseDirectory.toStdString());
    }

    QGpgME::QIODeviceDataProvider out{cipherText};
    Data outdata(&out);

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
    Error ae;
    const QString log = _detail::audit_log_as_html(ctx, ae);
    return std::make_tuple(res.first, res.second, log, ae);
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

    run(std::bind(&sign_encrypt,
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

#include "qgpgmesignencryptarchivejob.moc"
