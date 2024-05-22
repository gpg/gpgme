/*
    qgpgmesignkeyjob.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2008 Klarälvdalens Datakonsult AB
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

#include "qgpgmesignkeyjob.h"

#include <QDate>
#include <QString>

#include "dataprovider.h"

#include <gpgme++/context.h>
#include <gpgme++/data.h>
#include <gpgme++/gpgsignkeyeditinteractor.h>

#include "qgpgme_debug.h"

#include <cassert>

using namespace QGpgME;
using namespace GpgME;

namespace
{
struct TrustSignatureProperties {
    TrustSignatureProperties() = default;
    // needed for C++11 because until C++14 "aggregate initialization requires
    // class type, that has no default member initializers"
    TrustSignatureProperties(TrustSignatureTrust trust_, unsigned int depth_, const QString &scope_)
        : trust{trust_}
        , depth{depth_}
        , scope{scope_}
    {}

    TrustSignatureTrust trust = TrustSignatureTrust::None;
    unsigned int depth = 0;
    QString scope;
};
}

class QGpgMESignKeyJob::Private
{
public:
    Private() = default;

    std::vector<unsigned int> m_userIDsToSign;
    GpgME::Key m_signingKey;
    unsigned int m_checkLevel = 0;
    bool m_exportable = false;
    bool m_nonRevocable = false;
    bool m_started = false;
    bool m_dupeOk = false;
    QString m_remark;
    TrustSignatureProperties m_trustSignature;
    QDate m_expiration;
};

QGpgMESignKeyJob::QGpgMESignKeyJob(Context *context)
    : mixin_type(context)
    , d{std::unique_ptr<Private>(new Private())}
{
    lateInitialization();
}

QGpgMESignKeyJob::~QGpgMESignKeyJob() {}

static QGpgMESignKeyJob::result_type sign_key(Context *ctx, const Key &key, const std::vector<unsigned int> &uids,
                                              unsigned int checkLevel, const Key &signer, unsigned int opts,
                                              bool dupeOk, const QString &remark,
                                              const TrustSignatureProperties &trustSignature,
                                              const QDate &expirationDate)
{
    QGpgME::QByteArrayDataProvider dp;
    Data data(&dp);

    GpgSignKeyEditInteractor *skei(new GpgSignKeyEditInteractor);
    skei->setUserIDsToSign(uids);
    skei->setCheckLevel(checkLevel);
    skei->setSigningOptions(opts);
    skei->setKey(key);

    if (dupeOk) {
        ctx->setFlag("extended-edit", "1");
        skei->setDupeOk(true);
    }

    if (!remark.isEmpty()) {
        ctx->addSignatureNotation("rem@gnupg.org", remark.toUtf8().constData());
    }

    if (opts & GpgSignKeyEditInteractor::Trust) {
        skei->setTrustSignatureTrust(trustSignature.trust);
        skei->setTrustSignatureDepth(trustSignature.depth);
        skei->setTrustSignatureScope(trustSignature.scope.toUtf8().toStdString());
    }

    if (!signer.isNull()) {
        if (const Error err = ctx->addSigningKey(signer)) {
            return std::make_tuple(err, QString(), Error());
        }
    }

    if (expirationDate.isValid()) {
        // on 2106-02-07, the Unix time will reach 0xFFFFFFFF; since gpg uses uint32 internally
        // for the expiration date clip it at 2106-02-05 to avoid problems with negative time zones
        static const QDate maxAllowedDate{2106, 2, 5};
        const auto clippedExpirationDate = expirationDate <= maxAllowedDate ? expirationDate : maxAllowedDate;
        if (clippedExpirationDate != expirationDate) {
            qCDebug(QGPGME_LOG) << "Expiration of certification has been changed to" << clippedExpirationDate;
        }
        // use the "days from now" format to specify the expiration date of the certification;
        // this format is the most appropriate regardless of the local timezone
        const auto daysFromNow = QDate::currentDate().daysTo(clippedExpirationDate);
        if (daysFromNow > 0) {
            const auto certExpire = std::to_string(daysFromNow) + "d";
            ctx->setFlag("cert-expire", certExpire.c_str());
        }
    } else {
        // explicitly set "cert-expire" to "0" (no expiration) to override default-cert-expire set in gpg.conf
        ctx->setFlag("cert-expire", "0");
    }

    const Error err = ctx->edit(key, std::unique_ptr<EditInteractor> (skei), data);
    Error ae;
    const QString log = _detail::audit_log_as_html(ctx, ae);
    return std::make_tuple(err, log, ae);
}

Error QGpgMESignKeyJob::start(const Key &key)
{
    unsigned int opts = 0;
    if (d->m_nonRevocable) {
        opts |= GpgSignKeyEditInteractor::NonRevocable;
    }
    if (d->m_exportable) {
        opts |= GpgSignKeyEditInteractor::Exportable;
    }
    switch (d->m_trustSignature.trust) {
    case TrustSignatureTrust::Partial:
    case TrustSignatureTrust::Complete:
        opts |= GpgSignKeyEditInteractor::Trust;
        break;
    default:
        opts &= ~GpgSignKeyEditInteractor::Trust;
        break;
    }
    run(std::bind(&sign_key, std::placeholders::_1, key, d->m_userIDsToSign, d->m_checkLevel, d->m_signingKey,
                  opts, d->m_dupeOk, d->m_remark, d->m_trustSignature, d->m_expiration));
    d->m_started = true;
    return Error();
}

void QGpgMESignKeyJob::setUserIDsToSign(const std::vector<unsigned int> &idsToSign)
{
    assert(!d->m_started);
    d->m_userIDsToSign = idsToSign;
}

void QGpgMESignKeyJob::setCheckLevel(unsigned int checkLevel)
{
    assert(!d->m_started);
    d->m_checkLevel = checkLevel;
}

void QGpgMESignKeyJob::setExportable(bool exportable)
{
    assert(!d->m_started);
    d->m_exportable = exportable;
}

void QGpgMESignKeyJob::setSigningKey(const Key &key)
{
    assert(!d->m_started);
    d->m_signingKey = key;
}

void QGpgMESignKeyJob::setNonRevocable(bool nonRevocable)
{
    assert(!d->m_started);
    d->m_nonRevocable = nonRevocable;
}

void QGpgMESignKeyJob::setRemark(const QString &remark)
{
    assert(!d->m_started);
    d->m_remark = remark;
}

void QGpgMESignKeyJob::setDupeOk(bool value)
{
    assert(!d->m_started);
    d->m_dupeOk = value;
}

void QGpgMESignKeyJob::setTrustSignature(GpgME::TrustSignatureTrust trust, unsigned short depth, const QString &scope)
{
    assert(!d->m_started);
    assert(depth <= 255);
    d->m_trustSignature = {trust, depth, scope};
}

void QGpgMESignKeyJob::setExpirationDate(const QDate &expiration)
{
    assert(!d->m_started);
    d->m_expiration = expiration;
}

#include "qgpgmesignkeyjob.moc"
