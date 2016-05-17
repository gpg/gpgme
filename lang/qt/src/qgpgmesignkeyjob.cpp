/*
    qgpgmesignkeyjob.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2008 Klarälvdalens Datakonsult AB
    Copyright (c) 2016 Intevation GmbH

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

#include "dataprovider.h"

#include "context.h"
#include "data.h"
#include "gpgsignkeyeditinteractor.h"

#include <cassert>
#include <memory>

using namespace QGpgME;
using namespace GpgME;

QGpgMESignKeyJob::QGpgMESignKeyJob(Context *context)
    : mixin_type(context),
      m_userIDsToSign(),
      m_signingKey(),
      m_checkLevel(0),
      m_exportable(false),
      m_nonRevocable(false),
      m_started(false)
{
    lateInitialization();
}

QGpgMESignKeyJob::~QGpgMESignKeyJob() {}

static QGpgMESignKeyJob::result_type sign_key(Context *ctx, const Key &key, const std::vector<unsigned int> &uids, unsigned int checkLevel, const Key &signer, unsigned int opts)
{
    QGpgME::QByteArrayDataProvider dp;
    Data data(&dp);

    GpgSignKeyEditInteractor *skei(new GpgSignKeyEditInteractor);
    skei->setUserIDsToSign(uids);
    skei->setCheckLevel(checkLevel);
    skei->setSigningOptions(opts);

    if (!signer.isNull())
        if (const Error err = ctx->addSigningKey(signer)) {
            return std::make_tuple(err, QString(), Error());
        }
    const Error err = ctx->edit(key, std::unique_ptr<EditInteractor> (skei), data);
    Error ae;
    const QString log = _detail::audit_log_as_html(ctx, ae);
    return std::make_tuple(err, log, ae);
}

Error QGpgMESignKeyJob::start(const Key &key)
{
    unsigned int opts = 0;
    if (m_nonRevocable) {
        opts |= GpgSignKeyEditInteractor::NonRevocable;
    }
    if (m_exportable) {
        opts |= GpgSignKeyEditInteractor::Exportable;
    }
    run(std::bind(&sign_key, std::placeholders::_1, key, m_userIDsToSign, m_checkLevel, m_signingKey, opts));
    m_started = true;
    return Error();
}

void QGpgMESignKeyJob::setUserIDsToSign(const std::vector<unsigned int> &idsToSign)
{
    assert(!m_started);
    m_userIDsToSign = idsToSign;
}

void QGpgMESignKeyJob::setCheckLevel(unsigned int checkLevel)
{
    assert(!m_started);
    m_checkLevel = checkLevel;
}

void QGpgMESignKeyJob::setExportable(bool exportable)
{
    assert(!m_started);
    m_exportable = exportable;
}

void QGpgMESignKeyJob::setSigningKey(const Key &key)
{
    assert(!m_started);
    m_signingKey = key;
}

void QGpgMESignKeyJob::setNonRevocable(bool nonRevocable)
{
    assert(!m_started);
    m_nonRevocable = nonRevocable;
}
#include "qgpgmesignkeyjob.moc"
