/*
    addexistingsubkeyjob.h

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2022 g10 Code GmbH
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

#ifndef __QGPGME_ADDEXISTINGSUBKEYJOB_H__
#define __QGPGME_ADDEXISTINGSUBKEYJOB_H__

#include "job.h"
#include "qgpgme_export.h"

class QString;

namespace GpgME
{
class Error;
class Key;
class Subkey;
}

namespace QGpgME
{

class QGPGME_EXPORT AddExistingSubkeyJob : public Job
{
    Q_OBJECT
protected:
    explicit AddExistingSubkeyJob(QObject *parent);

public:
    ~AddExistingSubkeyJob();

    /**
      Starts the operation. \a key is the key to add the subkey \a subkey to.

      The job deletes itself after it has completed the operation.
    */
    virtual GpgME::Error start(const GpgME::Key &key, const GpgME::Subkey &subkey) = 0;

    /**
      Runs the operation. \a key is the key to add the subkey \a subkey to.
    */
    virtual GpgME::Error exec(const GpgME::Key &key, const GpgME::Subkey &subkey) = 0;

Q_SIGNALS:
    void result(const GpgME::Error &result, const QString &auditLogAsHtml = {}, const GpgME::Error &auditLogError = {});
};

}

#endif // __QGPGME_ADDEXISTINGSUBKEYJOB_H__
