/*
    signjob.h

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004, 2007 Klarälvdalens Datakonsult AB
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

#ifndef __KLEO_SIGNJOB_H__
#define __KLEO_SIGNJOB_H__

#include "job.h"

#include <gpgme++/global.h>

#include <vector>
#include <memory>

class QByteArray;
class QIODevice;

namespace GpgME
{
class Error;
class Key;
class SigningResult;
}

namespace QGpgME
{

/**
   @short An abstract base class for asynchronous signing

   To use a SignJob, first obtain an instance from the CryptoBackend
   implementation, connect the progress() and result() signals to
   suitable slots and then start the signing with a call to
   start(). This call might fail, in which case the SignJob instance
   will have scheduled it's own destruction with a call to
   QObject::deleteLater().

   Alternatively, the job can be started with startIt() after setting
   an input file and an output file and, optionally, signers or flags.
   If the job is started this way then the backend reads the input and
   writes the output directly from/to the specified input file and output
   file. In this case the signature value of the result signal will always
   be empty. This direct IO mode is currently only supported for OpenPGP.
   Note that startIt() does not schedule the job's destruction if starting
   the job failed.

   After result() is emitted, the SignJob will schedule it's own
   destruction by calling QObject::deleteLater().
*/
class QGPGME_EXPORT SignJob : public Job
{
    Q_OBJECT
protected:
    explicit SignJob(QObject *parent);
public:
    ~SignJob() override;

    /**
     * Sets the keys to use for signing.
     *
     * Used if the job is started with startIt().
     */
    void setSigners(const std::vector<GpgME::Key> &signers);
    std::vector<GpgME::Key> signers() const;

    /**
     * Sets the path of the file to sign.
     *
     * Used if the job is started with startIt().
     */
    void setInputFile(const QString &path);
    QString inputFile() const;

    /**
     * Sets the path of the file to write the signing result to.
     *
     * Used if the job is started with startIt().
     *
     * \note If a file with this path exists, then the job will fail, i.e. you
     * need to delete an existing file that shall be overwritten before you
     * start the job. If you create a detached signature then you can tell
     * the job to append the new detached signature to an existing file.
     */
    void setOutputFile(const QString &path);
    QString outputFile() const;

    /**
     * Sets the flags to use for signing.
     *
     * Defaults to \c SignFile.
     *
     * Used if the job is started with startIt(). The \c SignFile flag is
     * always assumed set.
     */
    void setSigningFlags(GpgME::SignatureMode flags);
    GpgME::SignatureMode signingFlags() const;

    /**
     * If @c true then a new detached signature is appended to an already
     * existing detached signature.
     *
     * Defaults to \c false.
     *
     * Used if the job is started with startIt().
     */
    void setAppendSignature(bool append);
    bool appendSignatureEnabled() const;

    /**
       Starts the signing operation. \a signers is the list of keys to
       sign \a plainText with. Empty (null) keys are ignored.
    */
    virtual GpgME::Error start(const std::vector<GpgME::Key> &signers,
            const QByteArray &plainText,
            GpgME::SignatureMode mode) = 0;

    /*!
      \overload

      If \a signature is non-null the signature is written
      there. Otherwise, it will be delivered in the second argument of
      result().
    */
    virtual void start(const std::vector<GpgME::Key> &signers,
                       const std::shared_ptr<QIODevice> &plainText,
                       const std::shared_ptr<QIODevice> &signature,
                       GpgME::SignatureMode mode) = 0;

    virtual GpgME::SigningResult exec(const std::vector<GpgME::Key> &signers,
                                      const QByteArray &plainText,
                                      GpgME::SignatureMode mode,
                                      QByteArray &signature) = 0;

    /*!
      This is a hack to request BASE64 output (instead of whatever
      comes out normally).
    */
    virtual void setOutputIsBase64Encoded(bool) = 0;

Q_SIGNALS:
    void result(const GpgME::SigningResult &result, const QByteArray &signature, const QString &auditLogAsHtml = QString(), const GpgME::Error &auditLogError = GpgME::Error());
};

}

#endif // __KLEO_SIGNJOB_H__
