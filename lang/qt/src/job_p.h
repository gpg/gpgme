/*
    job_p.h

    This file is part of qgpgme, the Qt API binding for gpgme
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

#ifndef __QGPGME_JOB_P_H__
#define __QGPGME_JOB_P_H__

#include "job.h"

#include "qgpgme_debug.h"

#include <memory>

namespace QGpgME
{

// Base class for pimpl classes for Job subclasses
class JobPrivate
{
public:
    virtual ~JobPrivate() {}

    virtual void start() = 0;
};

// Setter and getters for the externally stored pimpl instances of jobs
// BCI: Add a real d-pointer to Job
void setJobPrivate(const Job *job, std::unique_ptr<JobPrivate> d);

JobPrivate *getJobPrivate(const Job *job);

template <typename T>
static T *jobPrivate(const Job *job) {
    auto d = getJobPrivate(job);
    return dynamic_cast<T *>(d);
}

// Helper for the archive job classes
template<class JobClass>
void emitArchiveProgressSignals(JobClass *job, const QString &what, int type, int current, int total)
{
    if (what != QLatin1String{"gpgtar"}) {
        return;
    }
    switch (type) {
    case 'c':
        Q_EMIT job->fileProgress(current, total);
        break;
    case 's':
        Q_EMIT job->dataProgress(current, total);
        break;
    default:
        qCDebug(QGPGME_LOG) << job << __func__ << "Received progress for gpgtar with unknown type" << char(type);
    };
}

}

#endif // __QGPGME_JOB_P_H__
