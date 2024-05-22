/* defaultkeygenerationjob.cpp

    Copyright (c) 2016 Klarälvdalens Datakonsult AB

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

#include "defaultkeygenerationjob.h"
#include "protocol.h"
#include "keygenerationjob.h"

#include <QPointer>
#include <QEvent>

using namespace QGpgME;

namespace QGpgME {

class DefaultKeyGenerationJob::Private
{
public:
    Private()
    {}

    ~Private()
    {
        if (job) {
            job->deleteLater();
        }
    }

    QPointer<KeyGenerationJob> job;
};
}


DefaultKeyGenerationJob::DefaultKeyGenerationJob(QObject* parent)
    : Job(parent)
    , d(new DefaultKeyGenerationJob::Private())
{
}

DefaultKeyGenerationJob::~DefaultKeyGenerationJob()
{
    delete d;
}

QString DefaultKeyGenerationJob::auditLogAsHtml() const
{
    return d->job ? d->job->auditLogAsHtml() : QString();
}

GpgME::Error DefaultKeyGenerationJob::auditLogError() const
{
    return d->job ? d->job->auditLogError() : GpgME::Error();
}

void DefaultKeyGenerationJob::slotCancel()
{
    if (d->job) {
        d->job->slotCancel();
    }
}

GpgME::Error DefaultKeyGenerationJob::start(const QString &email, const QString &name)
{
    const QString namePart = name.isEmpty() ? QString() :
                                QStringLiteral("name-real:     %1\n").arg(name);
    const QString mailPart = email.isEmpty() ? QString() :
                                QStringLiteral("name-email:    %1\n").arg(email);

    const QString args = QStringLiteral("<GnupgKeyParms format=\"internal\">\n"
                                        "%ask-passphrase\n"
                                        "key-type:      RSA\n"
                                        "key-length:    2048\n"
                                        "key-usage:     sign\n"
                                        "subkey-type:   RSA\n"
                                        "subkey-length: 2048\n"
                                        "subkey-usage:  encrypt\n"
                                        "%1"
                                        "%2"
                                        "</GnupgKeyParms>").arg(mailPart, namePart);

    d->job = openpgp()->keyGenerationJob();
    d->job->installEventFilter(this);
    connect(d->job.data(), &KeyGenerationJob::result,
            this, &DefaultKeyGenerationJob::result);
    connect(d->job.data(), &KeyGenerationJob::done,
            this, &DefaultKeyGenerationJob::done);
    connect(d->job.data(), &KeyGenerationJob::done,
            this, &QObject::deleteLater);
    return d->job->start(args);
}

bool DefaultKeyGenerationJob::eventFilter(QObject *watched, QEvent *event)
{
    // Intercept the KeyGenerationJob's deferred delete event. We want the job
    // to live at least as long as we do so we can delegate calls to it. We will
    // delete the job manually afterwards.
    if (watched == d->job && event->type() == QEvent::DeferredDelete) {
        return true;
    }

    return Job::eventFilter(watched, event);
}

#include "defaultkeygenerationjob.moc"
