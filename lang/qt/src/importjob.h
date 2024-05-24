/*
    importjob.h

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004 Klarälvdalens Datakonsult AB
    Copyright (c) 2016 by Bundesamt für Sicherheit in der Informationstechnik
    Software engineering by Intevation GmbH
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

#ifndef __KLEO_IMPORTJOB_H__
#define __KLEO_IMPORTJOB_H__

#include "abstractimportjob.h"
#include "qgpgme_export.h"

#include <gpgme++/key.h>

namespace GpgME
{
class Error;
class ImportResult;
}

namespace QGpgME
{

/**
   @short An abstract base class for asynchronous importers

   To use a ImportJob, first obtain an instance from the
   CryptoBackend implementation, connect the progress() and result()
   signals to suitable slots and then start the import with a call
   to start(). This call might fail, in which case the ImportJob
   instance will have scheduled it's own destruction with a call to
   QObject::deleteLater().

   After result() is emitted, the ImportJob will schedule it's own
   destruction by calling QObject::deleteLater().
*/
class QGPGME_EXPORT ImportJob : public AbstractImportJob
{
    Q_OBJECT
protected:
    explicit ImportJob(QObject *parent);
public:
    ~ImportJob() override;

    void setImportFilter(const QString &filter);
    QString importFilter() const;

    void setImportOptions(const QStringList &options);
    QStringList importOptions() const;

    void setKeyOrigin(GpgME::Key::Origin origin, const QString &url = {});
    GpgME::Key::Origin keyOrigin() const;
    QString keyOriginUrl() const;

    /**
       Starts the importing operation. \a keyData contains the data to
       import from.
    */
    virtual GpgME::Error start(const QByteArray &keyData) = 0;

    virtual GpgME::ImportResult exec(const QByteArray &keyData) = 0;

    virtual GpgME::Error startLater(const QByteArray &keyData) = 0;
};

}

#endif // __KLEO_IMPORTJOB_H__
