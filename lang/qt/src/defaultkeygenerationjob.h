/* defaultkeygenerationjob.h

    Copyright (c) 2016 Klarälvdalens Datakonsult AB
    2016 Bundesamt für Sicherheit in der Informationstechnik
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
#ifndef QGPGME_DEFAULTKEYGENERATION_H
#define QGPGME_DEFAULTKEYGENERATION_H

#include "job.h"

#include "qgpgme_export.h"

namespace GpgME {
class KeyGenerationResult;
}

namespace QGpgME{

/**
 * Generates a PGP RSA/2048 bit key pair for given name and email address.
 *
 * This job is deprecated. Use QuickJob::startCreate instead.
 */
class QGPGME_DEPRECATED_EXPORT DefaultKeyGenerationJob : public Job
{
    Q_OBJECT
public:
    explicit DefaultKeyGenerationJob(QObject *parent = nullptr);
    ~DefaultKeyGenerationJob();

    GpgME::Error start(const QString &email, const QString &name);

    QString auditLogAsHtml() const override;
    GpgME::Error auditLogError() const override;


public Q_SLOTS:
    void slotCancel() override;

Q_SIGNALS:
    void result(const GpgME::KeyGenerationResult &result, const QByteArray &pubkeyData,
                const QString &auditLogAsHtml, const GpgME::Error &auditLogError);

protected:
    bool eventFilter(QObject *watched, QEvent *event) override;

private:
    class Private;
    Private * const d;
};

}

#endif
