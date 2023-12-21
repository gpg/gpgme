/*
    signencryptjob.h

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004, 2007 Klarälvdalens Datakonsult AB
    Copyright (c) 2016 by Bundesamt für Sicherheit in der Informationstechnik
    Software engineering by Intevation GmbH
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

#ifndef __KLEO_SIGNENCRYPTJOB_H__
#define __KLEO_SIGNENCRYPTJOB_H__

#include "job.h"
#include "qgpgme_export.h"

#ifdef BUILDING_QGPGME
# include "global.h"
# include "context.h"
#else
# include <gpgme++/global.h>
# include <gpgme++/context.h>
#endif

#include <memory>
#include <vector>
#include <utility>

class QByteArray;
class QIODevice;

namespace GpgME
{
class Error;
class Key;
class SigningResult;
class EncryptionResult;
}

namespace QGpgME
{

/**
   @short An abstract base class for asynchronous combined signing and encrypting

   To use a SignEncryptJob, first obtain an instance from the
   CryptoBackend implementation, connect the progress() and result()
   signals to suitable slots and then start the operation with a
   call to start(). This call might fail, in which case the
   SignEncryptJob instance will have scheduled it's own destruction
   with a call to QObject::deleteLater().

   Alternatively, the job can be started with startIt() after setting
   an input file and an output file and, optionally, signers, recipients or flags.
   If the job is started this way then the backend reads the input and
   writes the output directly from/to the specified input file and output
   file. In this case the cipherText value of the result signal will always
   be empty. This direct IO mode is currently only supported for OpenPGP.
   Note that startIt() does not schedule the job's destruction if starting
   the job failed.

   After result() is emitted, the SignEncryptJob will schedule it's
   own destruction by calling QObject::deleteLater().
*/
class QGPGME_EXPORT SignEncryptJob : public Job
{
    Q_OBJECT
protected:
    explicit SignEncryptJob(QObject *parent);
public:
    ~SignEncryptJob() override;

    /**
     * Sets the file name to embed in the encryption result.
     *
     * This is only used if one of the start() functions is used.
     */
    void setFileName(const QString &fileName);
    QString fileName() const;

    /**
     * Sets the keys to use for signing.
     *
     * Used if the job is started with startIt().
     */
    void setSigners(const std::vector<GpgME::Key> &signers);
    std::vector<GpgME::Key> signers() const;

    /**
     * Sets the keys to use for encryption.
     *
     * Used if the job is started with startIt().
     */
    void setRecipients(const std::vector<GpgME::Key> &recipients);
    std::vector<GpgME::Key> recipients() const;

    /**
     * Sets the path of the file to encrypt.
     *
     * Used if the job is started with startIt().
     */
    void setInputFile(const QString &path);
    QString inputFile() const;

    /**
     * Sets the path of the file to write the encryption result to.
     *
     * Used if the job is started with startIt().
     *
     * \note If a file with this path exists, then the job will fail, i.e. you
     * need to delete an existing file that shall be overwritten before you
     * start the job.
     */
    void setOutputFile(const QString &path);
    QString outputFile() const;

    /**
     * Sets the flags to use for encryption.
     *
     * Defaults to \c EncryptFile.
     *
     * Used if the job is started with startIt(). The \c EncryptFile flag is
     * always assumed set.
     */
    void setEncryptionFlags(GpgME::Context::EncryptionFlags flags);
    GpgME::Context::EncryptionFlags encryptionFlags() const;

    /**
       Starts the combined signing and encrypting operation. \a signers
       is the list of keys to sign \a plainText with. \a recipients is
       a list of keys to encrypt the signed \a plainText to. In both
       lists, empty (null) keys are ignored.

       If \a alwaysTrust is true, validity checking for the
       \em recipient keys will not be performed, but full validity
       assumed for all \em recipient keys without further checks.
    */
    virtual GpgME::Error start(const std::vector<GpgME::Key> &signers,
            const std::vector<GpgME::Key> &recipients,
            const QByteArray &plainText,
            bool alwaysTrust = false) = 0;

    /*!
      \overload

      If \a cipherText is non-null, the ciphertext is written
      there. Otherwise, it will be delivered in the third argument of
      result().
    */
    virtual void start(const std::vector<GpgME::Key> &signers,
                       const std::vector<GpgME::Key> &recipients,
                       const std::shared_ptr<QIODevice> &plainText,
                       const std::shared_ptr<QIODevice> &cipherText = std::shared_ptr<QIODevice>(),
                       bool alwaysTrust = false) = 0;

    virtual std::pair<GpgME::SigningResult, GpgME::EncryptionResult>
    exec(const std::vector<GpgME::Key> &signers,
         const std::vector<GpgME::Key> &recipients,
         const QByteArray &plainText,
         bool alwaysTrust, QByteArray &cipherText) = 0;

    /*!
      This is a hack to request BASE64 output (instead of whatever
      comes out normally).
    */
    virtual void setOutputIsBase64Encoded(bool) = 0;

    /** Like start but with an additional argument for EncryptionFlags for
     * more flexibility. */
    virtual void start(const std::vector<GpgME::Key> &signers,
                       const std::vector<GpgME::Key> &recipients,
                       const std::shared_ptr<QIODevice> &plainText,
                       const std::shared_ptr<QIODevice> &cipherText = std::shared_ptr<QIODevice>(),
                       const GpgME::Context::EncryptionFlags flags = GpgME::Context::None) = 0;

    /** Like exec but with an additional argument for EncryptionFlags for
     * more flexibility. */
    virtual std::pair<GpgME::SigningResult, GpgME::EncryptionResult>
    exec(const std::vector<GpgME::Key> &signers,
         const std::vector<GpgME::Key> &recipients,
         const QByteArray &plainText,
         const GpgME::Context::EncryptionFlags flags, QByteArray &cipherText) = 0;
Q_SIGNALS:
    void result(const GpgME::SigningResult &signingresult,
                const GpgME::EncryptionResult &encryptionresult,
                const QByteArray &cipherText, const QString &auditLogAsHtml = QString(),
                const GpgME::Error &auditLogError = GpgME::Error());
};

}

#endif // __KLEO_SIGNENCRYPTJOB_H__
