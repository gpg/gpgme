/*
    qgpgmesignencryptjob.h

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

#ifndef __QGPGME_QGPGMESIGNENCRYPTJOB_H__
#define __QGPGME_QGPGMESIGNENCRYPTJOB_H__

#include "signencryptjob.h"

#include "threadedjobmixin.h"

#ifdef BUILDING_QGPGME
# include "signingresult.h"
#else
#include <gpgme++/signingresult.h>
#endif
#ifdef BUILDING_QGPGME
# include "encryptionresult.h"
#else
#include <gpgme++/encryptionresult.h>
#endif
#ifdef BUILDING_QGPGME
# include "key.h"
#else
#include <gpgme++/key.h>
#endif

#include <utility>

namespace QGpgME
{

class QGpgMESignEncryptJob
#ifdef Q_MOC_RUN
    : public SignEncryptJob
#else
    : public _detail::ThreadedJobMixin<SignEncryptJob, std::tuple<GpgME::SigningResult, GpgME::EncryptionResult, QByteArray, QString, GpgME::Error> >
#endif
{
    Q_OBJECT
#ifdef Q_MOC_RUN
public Q_SLOTS:
    void slotFinished();
#endif
public:
    explicit QGpgMESignEncryptJob(GpgME::Context *context);
    ~QGpgMESignEncryptJob();

    /* from SignEncryptJob */
    GpgME::Error start(const std::vector<GpgME::Key> &signers,
                       const std::vector<GpgME::Key> &recipients,
                       const QByteArray &plainText, bool alwaysTrust) override;

    /* from SignEncryptJob */
    void start(const std::vector<GpgME::Key> &signers,
               const std::vector<GpgME::Key> &recipients,
               const std::shared_ptr<QIODevice> &plainText,
               const std::shared_ptr<QIODevice> &cipherText,
               bool alwaysTrust) override;

    void start(const std::vector<GpgME::Key> &signers,
               const std::vector<GpgME::Key> &recipients,
               const std::shared_ptr<QIODevice> &plainText,
               const std::shared_ptr<QIODevice> &cipherText,
               const GpgME::Context::EncryptionFlags flags) override;

    std::pair<GpgME::SigningResult, GpgME::EncryptionResult>
    exec(const std::vector<GpgME::Key> &signers,
         const std::vector<GpgME::Key> &recipients,
         const QByteArray &plainText, bool alwaysTrust,
         QByteArray &cipherText) override;

    std::pair<GpgME::SigningResult, GpgME::EncryptionResult>
    exec(const std::vector<GpgME::Key> &signers,
         const std::vector<GpgME::Key> &recipients,
         const QByteArray &plainText, const GpgME::Context::EncryptionFlags flags,
         QByteArray &cipherText) override;

    /* from SignEncryptJob */
    void setOutputIsBase64Encoded(bool on) override;

    /* from ThreadedJobMixin */
    void resultHook(const result_type &r) override;

private:
    bool mOutputIsBase64Encoded;
    std::pair<GpgME::SigningResult, GpgME::EncryptionResult> mResult;
};

}

#endif // __QGPGME_QGPGMESIGNENCRYPTJOB_H__
