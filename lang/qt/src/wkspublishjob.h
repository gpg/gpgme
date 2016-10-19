/* wkspublishjob.h

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
#ifndef QGPGME_WKSPUBLISHJOB_H
#define QGPGME_WKSPUBLISHJOB_H

#include "job.h"

#include "qgpgme_export.h"

namespace GpgME
{
    class Key;
} // namespace GpgME

namespace QGpgME {

/**
 * Handles Web Key Service Publishing. Needs WKS tools installed and
 * server support.
 *
 * Remember that after a result is emitted the job is auto deleted
 * so you can only use it for a single action.
 *
 * The workflow is to call startCreate, check for errors and then
 * send the RFC822 mail returned in returnedData.
 *
 * When the response is received start a startRecieve with the
 * RFC822 mail received as paramater response. Check for errors
 * and then send again send the result from returnedData back to
 * the server.
 *
 */
class QGPGME_EXPORT WKSPublishJob: public Job
{
    Q_OBJECT
protected:
    explicit WKSPublishJob(QObject *parent);
public:
    ~WKSPublishJob();


    /** Start a check if WKS Publishing is supported. As this involves
     * an HTTP Query it might take a while. Returns GPG_ERR_NOT_SUPPORED
     * result if GnuPG is too old or the required tools are not installed.
     *
     * The error GPG_ERR_NOT_ENABLED indicates that wks-tools failed to
     * detect a working wks service for this.
     *
     * @param the mailbox to check for.
     **/
    virtual void startCheck(const QString &mailbox) = 0;

    /** Create a publish request.
     * The returnedData from the result signal will contain
     * the full Request as returned by gpg-wks-client --create
     *
     * @param fpr the fingerprint of the key to create the request for.
     * @param mailbox A simple mail address without a Name.
     */
    virtual void startCreate(const char *fpr, const QString &mailbox) = 0;

    /** Handle a submisson response. The returnedData in the result singnal
     * will contain the confirmation response as returned by gpg-wks-client --receive
     *
     * @param response The response of the server.
     **/
    virtual void startReceive(const QByteArray &response) = 0;

Q_SIGNALS:
    /* Result of the operation returned Data and returned Error are
     * the results from gpg-wks-client's stdout or stderr respectively.
     *
     * As usual auditLogAsHtml and auditLogError can be ignored.
     **/
    void result(const GpgME::Error &error, const QByteArray &returnedData,
                const QByteArray &returnedError,
                const QString &auditLogAsHtml = QString(),
                const GpgME::Error &auditLogError = GpgME::Error());
};

}

#endif
