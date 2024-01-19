/*
    qgpgmeexportjob.h

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004,2008 Klarälvdalens Datakonsult AB
    Copyright (c) 2016 by Bundesamt für Sicherheit in der Informationstechnik
    Software engineering by Intevation GmbH
    Copyright (c) 2022 by g10 Code GmbH
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

#ifndef __QGPGME_QGPGMEEXPORTJOB_H__
#define __QGPGME_QGPGMEEXPORTJOB_H__

#include "exportjob.h"

#include "threadedjobmixin.h"

namespace QGpgME
{

class QGpgMEExportJob
#ifdef Q_MOC_RUN
    : public ExportJob
#else
    : public _detail::ThreadedJobMixin<ExportJob, std::tuple<GpgME::Error, QByteArray, QString, GpgME::Error> >
#endif
{
    Q_OBJECT
#ifdef Q_MOC_RUN
public Q_SLOTS:
    void slotFinished();
#endif
public:
    explicit QGpgMEExportJob(GpgME::Context *context);
    // Creates an export job with forced export mode @p exportMode. The
    // export mode flags set with @p exportMode cannot be overridden with
    // setExportFlags.
    explicit QGpgMEExportJob(GpgME::Context *context, unsigned int exportMode);
    ~QGpgMEExportJob() override;

    /* from ExportJob */
    void setExportFlags(unsigned int flags) override;

    /* from ExportJob */
    GpgME::Error start(const QStringList &patterns) override;
    GpgME::Error exec(const QStringList &patterns, QByteArray &data) override;

private:
    unsigned int m_exportMode;
    unsigned int m_additionalExportModeFlags;
};

}

#endif // __QGPGME_QGPGMEEXPORTJOB_H__
