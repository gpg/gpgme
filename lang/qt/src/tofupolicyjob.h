/* tofupolicyjob.h

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
#ifndef QGPGME_TOFUPOLICYJOB_H
#define QGPGME_TOFUPOLICYJOB_H

#include "job.h"

#include "qgpgme_export.h"

#include <gpgme++/tofuinfo.h>

namespace GpgME
{
    class Key;
} // namespace GpgME

namespace QGpgME {

/**
 * Set the TOFU Policy for a key
 */
class QGPGME_EXPORT TofuPolicyJob: public Job
{
    Q_OBJECT
protected:
    explicit TofuPolicyJob(QObject *parent);
public:
    ~TofuPolicyJob();


    /* Set the policy to \a policy see the gpgme manual for
     * policy explanations. */
    virtual void start(const GpgME::Key &key, GpgME::TofuInfo::Policy policy) = 0;

    virtual GpgME::Error exec(const GpgME::Key &key, GpgME::TofuInfo::Policy policy) = 0;

Q_SIGNALS:
    /* Result of the operation
     *
     * As usual auditLogAsHtml and auditLogError can be ignored.
     **/
    void result(const GpgME::Error &error,
                const QString &auditLogAsHtml = QString(),
                const GpgME::Error &auditLogError = GpgME::Error());
};

}

#endif
