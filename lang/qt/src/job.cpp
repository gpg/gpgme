/*
    job.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004,2005 Klarälvdalens Datakonsult AB
    Copyright (c) 2016 by Bundesamt für Sicherheit in der Informationstechnik
    Software engineering by Intevation GmbH
    Copyright (c) 2021 g10 Code GmbH
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

#ifdef HAVE_CONFIG_H
 #include "config.h"
#endif

#include "job.h"
#include "job_p.h"

#include "keylistjob.h"
#include "listallkeysjob.h"
#include "encryptjob.h"
#include "decryptjob.h"
#include "decryptverifyjob.h"
#include "signjob.h"
#include "signkeyjob.h"
#include "signencryptjob.h"
#include "verifydetachedjob.h"
#include "verifyopaquejob.h"
#include "keygenerationjob.h"
#include "importjob.h"
#include "importfromkeyserverjob.h"
#include "exportjob.h"
#include "changeexpiryjob.h"
#include "changeownertrustjob.h"
#include "changepasswdjob.h"
#include "downloadjob.h"
#include "deletejob.h"
#include "refreshkeysjob.h"
#include "addexistingsubkeyjob.h"
#include "adduseridjob.h"
#include "specialjob.h"
#include "keyformailboxjob.h"
#include "wkdlookupjob.h"
#include "wkspublishjob.h"
#include "tofupolicyjob.h"
#include "threadedjobmixin.h"
#include "quickjob.h"
#include "gpgcardjob.h"
#include "receivekeysjob.h"
#include "revokekeyjob.h"
#include "setprimaryuseridjob.h"

#include <QCoreApplication>
#include <QDebug>

#include <gpg-error.h>

#include <unordered_map>

namespace
{
typedef std::unordered_map<const QGpgME::Job*, std::unique_ptr<QGpgME::JobPrivate>> JobPrivateHash;
Q_GLOBAL_STATIC(JobPrivateHash, d_func)
}

void QGpgME::setJobPrivate(const Job *job, std::unique_ptr<JobPrivate> d)
{
    auto &ref = d_func()->operator[](job);
    ref = std::move(d);
}

const QGpgME::JobPrivate *QGpgME::getJobPrivate(const Job *job)
{
    return d_func()->operator[](job).get();
}

QGpgME::JobPrivate *QGpgME::getJobPrivate(Job *job)
{
    return d_func()->operator[](job).get();
}

QGpgME::Job::Job(QObject *parent)
    : QObject(parent)
{
    if (QCoreApplication *app = QCoreApplication::instance()) {
        connect(app, &QCoreApplication::aboutToQuit, this, &Job::slotCancel);
    }
}

QGpgME::Job::~Job()
{
    ::d_func()->erase(this);
}

QString QGpgME::Job::auditLogAsHtml() const
{
    qDebug() << "QGpgME::Job::auditLogAsHtml() should be reimplemented in Kleo::Job subclasses!";
    return QString();
}

GpgME::Error QGpgME::Job::auditLogError() const
{
    qDebug() << "QGpgME::Job::auditLogError() should be reimplemented in Kleo::Job subclasses!";
    return GpgME::Error::fromCode(GPG_ERR_NOT_IMPLEMENTED);
}

bool QGpgME::Job::isAuditLogSupported() const
{
    return auditLogError().code() != GPG_ERR_NOT_IMPLEMENTED;
}

QMap <QGpgME::Job *, GpgME::Context *> QGpgME::g_context_map;

/* static */
GpgME::Context *QGpgME::Job::context(QGpgME::Job *job)
{
    return QGpgME::g_context_map.value (job, nullptr);
}

GpgME::Error QGpgME::Job::startIt()
{
    auto d = getJobPrivate(this);
    Q_ASSERT(d && "This Job class has no JobPrivate class");
    return d->startIt();
}

void QGpgME::Job::startNow()
{
    auto d = getJobPrivate(this);
    Q_ASSERT(d && "This Job class has no JobPrivate class");
    d->startNow();
}

#define make_job_subclass_ext(x,y)                \
    QGpgME::x::x( QObject * parent ) : y( parent ) {} \
    QGpgME::x::~x() {}

#define make_job_subclass(x) make_job_subclass_ext(x,Job)

make_job_subclass(KeyListJob)
make_job_subclass(ListAllKeysJob)
make_job_subclass(EncryptJob)
make_job_subclass(DecryptJob)
make_job_subclass(DecryptVerifyJob)
make_job_subclass(SignJob)
make_job_subclass(SignEncryptJob)
make_job_subclass(SignKeyJob)
make_job_subclass(VerifyDetachedJob)
make_job_subclass(VerifyOpaqueJob)
make_job_subclass(KeyGenerationJob)
make_job_subclass(AbstractImportJob)
make_job_subclass_ext(ImportJob, AbstractImportJob)
make_job_subclass_ext(ImportFromKeyserverJob, AbstractImportJob)
make_job_subclass_ext(ReceiveKeysJob, AbstractImportJob)
make_job_subclass(ExportJob)
make_job_subclass(ChangeExpiryJob)
make_job_subclass(ChangeOwnerTrustJob)
make_job_subclass(ChangePasswdJob)
make_job_subclass(DownloadJob)
make_job_subclass(DeleteJob)
make_job_subclass(RefreshKeysJob)
make_job_subclass(AddExistingSubkeyJob)
make_job_subclass(AddUserIDJob)
make_job_subclass(SpecialJob)
make_job_subclass(KeyForMailboxJob)
make_job_subclass(WKDLookupJob)
make_job_subclass(WKSPublishJob)
make_job_subclass(TofuPolicyJob)
make_job_subclass(QuickJob)
make_job_subclass(GpgCardJob)
make_job_subclass(RevokeKeyJob)
make_job_subclass(SetPrimaryUserIDJob)

#undef make_job_subclass

#include "job.moc"

#include "keylistjob.moc"
#include "listallkeysjob.moc"
#include "encryptjob.moc"
#include "decryptjob.moc"
#include "decryptverifyjob.moc"
#include "signjob.moc"
#include "signencryptjob.moc"
#include "signkeyjob.moc"
#include "verifydetachedjob.moc"
#include "verifyopaquejob.moc"
#include "keygenerationjob.moc"
#include "abstractimportjob.moc"
#include "importjob.moc"
#include "importfromkeyserverjob.moc"
#include "exportjob.moc"
#include "changeexpiryjob.moc"
#include "changeownertrustjob.moc"
#include "changepasswdjob.moc"
#include "downloadjob.moc"
#include "deletejob.moc"
#include "refreshkeysjob.moc"
#include "addexistingsubkeyjob.moc"
#include "adduseridjob.moc"
#include "specialjob.moc"
#include "keyformailboxjob.moc"
#include "wkdlookupjob.moc"
#include "wkspublishjob.moc"
#include "tofupolicyjob.moc"
#include "quickjob.moc"
#include "gpgcardjob.moc"
#include "receivekeysjob.moc"
#include "revokekeyjob.moc"
#include "setprimaryuseridjob.moc"
