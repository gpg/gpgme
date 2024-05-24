/*
    qgpgmeencryptjob.h

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

#ifndef __QGPGME_QGPGMEENCRYPTJOB_H__
#define __QGPGME_QGPGMEENCRYPTJOB_H__

#include "encryptjob.h"

#include "threadedjobmixin.h"

#include <gpgme++/encryptionresult.h>
#include <gpgme++/key.h>

namespace QGpgME
{

class QGpgMEEncryptJob
#ifdef Q_MOC_RUN
    : public EncryptJob
#else
    : public _detail::ThreadedJobMixin<EncryptJob, std::tuple<GpgME::EncryptionResult, QByteArray, QString, GpgME::Error> >
#endif
{
    Q_OBJECT
#ifdef Q_MOC_RUN
public Q_SLOTS:
    void slotFinished();
#endif
public:
    explicit QGpgMEEncryptJob(GpgME::Context *context);
    ~QGpgMEEncryptJob();

    /* from EncryptJob */
    GpgME::Error start(const std::vector<GpgME::Key> &recipients,
                       const QByteArray &plainText, bool alwaysTrust) override;

    /* from EncryptJob */
    void start(const std::vector<GpgME::Key> &recipients,
               const std::shared_ptr<QIODevice> &plainText,
               const std::shared_ptr<QIODevice> &cipherText,
               bool alwaysTrust) override;

    /* from EncryptJob */
    GpgME::EncryptionResult exec(const std::vector<GpgME::Key> &recipients,
                                 const QByteArray &plainText, bool alwaysTrust,
                                 QByteArray &cipherText) override;
    /* from EncryptJob */
    void start(const std::vector<GpgME::Key> &recipients,
               const std::shared_ptr<QIODevice> &plainText,
               const std::shared_ptr<QIODevice> &cipherText,
               const GpgME::Context::EncryptionFlags flags) override;

    /* from EncryptJob */
    GpgME::EncryptionResult exec(const std::vector<GpgME::Key> &recipients,
                                 const QByteArray &plainText, const GpgME::Context::EncryptionFlags flags,
                                 QByteArray &cipherText) override;

    /* from EncryptJob */
    void setOutputIsBase64Encoded(bool on) override;

private:
    bool mOutputIsBase64Encoded;
};

}

#endif // __QGPGME_QGPGMEENCRYPTJOB_H__
