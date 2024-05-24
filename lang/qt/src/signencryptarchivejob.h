/*
    signencryptarchivejob.h

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

#ifndef __QGPGME_SIGNENCRYPTARCHIVEJOB_H__
#define __QGPGME_SIGNENCRYPTARCHIVEJOB_H__

#include "job.h"

#include <gpgme++/context.h>

namespace GpgME
{
class Key;
}

namespace QGpgME
{

/**
 * Abstract base class for job for creating encrypted signed archives
 */
class QGPGME_EXPORT SignEncryptArchiveJob : public Job
{
    Q_OBJECT
protected:
    explicit SignEncryptArchiveJob(QObject *parent);
public:
    ~SignEncryptArchiveJob() override;

    static bool isSupported();

    /**
     * Sets the keys to use for signing the archive.
     *
     * Used if the job is started with startIt().
     */
    void setSigners(const std::vector<GpgME::Key> &signers);
    std::vector<GpgME::Key> signers() const;

    /**
     * Sets the keys to use for encrypting the archive.
     *
     * Used if the job is started with startIt().
     */
    void setRecipients(const std::vector<GpgME::Key> &recipients);
    std::vector<GpgME::Key> recipients() const;

    /**
     * Sets the paths of the files and folders to put into the archive.
     *
     * If base directory is set, then the paths must be relative to the
     * base directory.
     *
     * Used if the job is started with startIt().
     */
    void setInputPaths(const std::vector<QString> &paths);
    std::vector<QString> inputPaths() const;

    /**
     * Sets the path of the file to write the created archive to.
     *
     * If \a path is a relative path and base directory is set, then the
     * path is interpreted relative to the base directory.
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
     * Sets the flags to use for encryption. Defaults to \c EncryptArchive.
     * The \c EncryptArchive flag is always assumed set for this job.
     *
     * Used if the job is started with startIt().
     */
    void setEncryptionFlags(GpgME::Context::EncryptionFlags flags);
    GpgME::Context::EncryptionFlags encryptionFlags() const;

    /**
     * Sets the base directory for the relative paths of the input files and
     * the output file.
     */
    void setBaseDirectory(const QString &baseDirectory);
    QString baseDirectory() const;

    /**
     * Starts the creation of an encrypted signed archive.
     *
     * Creates an encrypted signed archive with the files and directories in
     * \a paths.
     * The archive is signed with the keys in \a signers or with the default
     * key, if \a signers is empty. Then the archive is encrypted for the
     * keys in \a recipients. If \a recipients is empty, then symmetric
     * encryption is performed. The encrypted signed archive is written to
     * \a cipherText.
     *
     * Emits result() when the job has finished.
     */
    virtual GpgME::Error start(const std::vector<GpgME::Key> &signers,
                               const std::vector<GpgME::Key> &recipients,
                               const std::vector<QString> &paths,
                               const std::shared_ptr<QIODevice> &cipherText,
                               const GpgME::Context::EncryptionFlags flags) = 0;

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

    void result(const GpgME::SigningResult &signingResult,
                const GpgME::EncryptionResult &encryptionResult,
                const QString &auditLogAsHtml = {},
                const GpgME::Error &auditLogError = {});
};

}

#endif // __QGPGME_SIGNENCRYPTARCHIVEJOB_H__
