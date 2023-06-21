/*
    decryptverifyarchivejob.h

    This file is part of qgpgme, the Qt API binding for gpgme
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

#ifndef __QGPGME_DECRYPTVERIFYARCHIVEJOB_H__
#define __QGPGME_DECRYPTVERIFYARCHIVEJOB_H__

#include "job.h"

#ifdef BUILDING_QGPGME
# include "context.h"
#else
# include <gpgme++/context.h>
#endif

namespace GpgME
{
class Key;
}

namespace QGpgME
{

/**
 * Abstract base class for job for decrypting encrypted (signed) archives
 */
class QGPGME_EXPORT DecryptVerifyArchiveJob : public Job
{
    Q_OBJECT
protected:
    explicit DecryptVerifyArchiveJob(QObject *parent);
public:
    ~DecryptVerifyArchiveJob() override;

    static bool isSupported();

    /**
     * Sets the path of the file to read the archive from.
     *
     * Used if the job is started with startIt().
     */
    void setInputFile(const QString &path);
    QString inputFile() const;

    /**
     * Sets the directory the content of the decrypted archive shall be
     * written to.
     */
    void setOutputDirectory(const QString &outputDirectory);
    QString outputDirectory() const;

    /**
     * Starts the decryption of an encrypted (and signed) archive.
     *
     * Decrypts and extracts the encrypted archive in \a cipherText. If the
     * archive is signed, then the signature is verified.
     * If a non-empty output directory was set, then the content of the archive
     * is extracted into this directory. Otherwise, it is extracted into a
     * directory named \c GPGARCH_n_ (where \c n is a number).
     *
     * Emits result() when the job has finished.
     */
    virtual GpgME::Error start(const std::shared_ptr<QIODevice> &cipherText) = 0;

Q_SIGNALS:
    /**
     * This signal is emitted whenever gpgtar sends a progress status update for
     * the number of files. In the scanning phase (i.e. while gpgtar checks
     * which files to put into the archive), \a current is the current number of
     * files and \a total is 0. In the writing phase, \a current is the number
     * of processed files and \a total is the total number of files.
     */
    void fileProgress(int current, int total);

    /**
     * This signal is emitted whenever gpgtar sends a progress status update for
     * the amount of processed data. It is only emitted in the writing phase.
     * \a current is the processed amount data and \a total is the total amount
     * of data to process. Both values never exceed 2^20.
     */
    void dataProgress(int current, int total);

    void result(const GpgME::DecryptionResult &decryptionResult,
                const GpgME::VerificationResult &verificationResult,
                const QString &auditLogAsHtml = {},
                const GpgME::Error &auditLogError = {});
};

}

#endif // __QGPGME_DECRYPTVERIFYARCHIVEJOB_H__
