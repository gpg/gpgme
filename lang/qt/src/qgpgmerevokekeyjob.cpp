/*
    qgpgmerevokekeyjob.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2022 g10 Code GmbH
    Software engineering by Ingo Klöcker <dev@ingo-kloecker.de>

    QGpgME is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation; either version 2 of the
    License, or (at your option) any later version.

    QGpgME is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

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

#include "qgpgmerevokekeyjob.h"

#include "dataprovider.h"

#include <gpgme++/context.h>
#include <gpgme++/data.h>
#include <gpgme++/gpgrevokekeyeditinteractor.h>
#include <gpgme++/key.h>

#include <gpg-error.h>

#include "qgpgme_debug.h"

using namespace QGpgME;
using namespace GpgME;

QGpgMERevokeKeyJob::QGpgMERevokeKeyJob(Context *context)
    : mixin_type{context}
{
    lateInitialization();
}

QGpgMERevokeKeyJob::~QGpgMERevokeKeyJob() = default;


static Error check_arguments(const Key &key,
                             RevocationReason reason,
                             const std::vector<std::string> &description)
{
    if (key.isNull()) {
        qWarning(QGPGME_LOG) << "Error: Key is null key";
        return Error::fromCode(GPG_ERR_INV_ARG);
    }
    if (reason < RevocationReason::Unspecified || reason > RevocationReason::NoLongerUsed) {
        qWarning(QGPGME_LOG) << "Error: Invalid revocation reason" << static_cast<int>(reason);
        return Error::fromCode(GPG_ERR_INV_VALUE);
    }
    if (std::any_of(std::begin(description), std::end(description),
                    [](const std::string &line) {
                        return line.empty() || line.find('\n') != std::string::npos;
                    })) {
        qWarning(QGPGME_LOG) << "Error: Revocation description contains empty lines or lines with endline characters";
        return Error::fromCode(GPG_ERR_INV_VALUE);
    }
    return {};
}

static QGpgMERevokeKeyJob::result_type revoke_key(Context *ctx, const Key &key,
                                                  RevocationReason reason,
                                                  const std::vector<std::string> &description)
{
    std::unique_ptr<GpgRevokeKeyEditInteractor> interactor{new GpgRevokeKeyEditInteractor};
    interactor->setReason(reason, description);

    QGpgME::QByteArrayDataProvider dp;
    Data outData(&dp);
    assert(!outData.isNull());

    ctx->setFlag("extended-edit", "1");

    const Error err = ctx->edit(key, std::unique_ptr<EditInteractor>(interactor.release()), outData);
    Error ae;
    const QString log = _detail::audit_log_as_html(ctx, ae);
    return std::make_tuple(err, log, ae);
}

Error QGpgMERevokeKeyJob::start(const GpgME::Key &key,
                                GpgME::RevocationReason reason,
                                const std::vector<std::string> &description)
{
    Error err = check_arguments(key, reason, description);
    if (!err) {
        run(std::bind(&revoke_key, std::placeholders::_1, key, reason, description));
    }
    return err;
}

Error QGpgMERevokeKeyJob::exec(const GpgME::Key &key,
                               GpgME::RevocationReason reason,
                               const std::vector<std::string> &description)
{
    Error err = check_arguments(key, reason, description);
    if (!err) {
        const result_type r = revoke_key(context(), key, reason, description);
        err = std::get<0>(r);
    }
    return err;
}

#include "qgpgmerevokekeyjob.moc"
