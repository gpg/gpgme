/*
    listallkeysjob.h

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004 Klarälvdalens Datakonsult AB
    Copyright (c) 2016 by Bundesamt für Sicherheit in der Informationstechnik
    Software engineering by Intevation GmbH
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

#ifndef __KLEO_LISTALLKEYSJOB_H__
#define __KLEO_LISTALLKEYSJOB_H__

#include "job.h"
#include "qgpgme_export.h"

#include <gpgme++/key.h>

#include <vector>

namespace GpgME
{
class Error;
class KeyListResult;
}

namespace QGpgME
{

/**
   @short An abstract base class for asynchronously listing all keys

   To use a ListAllKeysJob, first obtain an instance from the
   CryptoBackend implementation, connect the progress()
   and result() signals to suitable slots and then start the key
   listing with a call to start(). This call might fail, in which
   case the ListAllKeysJob instance will have schedules it's own
   destruction with a call to QObject::deleteLater().

   After result() is emitted, the ListAllKeysJob will schedule it's
   own destruction by calling QObject::deleteLater().

   This is potentially much faster than a KeyListJob with empty
   pattern.
*/
class QGPGME_EXPORT ListAllKeysJob : public Job
{
    Q_OBJECT
public:
    enum Option {
        Default = 0x00,
        DisableAutomaticTrustDatabaseCheck = 0x01,
    };
    Q_DECLARE_FLAGS(Options, Option)

protected:
    explicit ListAllKeysJob(QObject *parent);

public:
    ~ListAllKeysJob();

    void setOptions(Options options);
    Options options() const;

    /**
      Starts the listallkeys operation.  In general, all keys are
      returned (however, the backend is free to truncate the result
      and should do so; when this happens, it will be reported by the
      result object).

      If GnuPG 2.1 or later is used, then \a mergeKeys is ignored. Otherwise,
      if \a mergeKeys is true, then some (but not all) information of the
      secret keys is merged into public keys.
    */
    virtual GpgME::Error start(bool mergeKeys = false) = 0;

    /**
       Synchronous version of start().
    */
    virtual GpgME::KeyListResult exec(std::vector<GpgME::Key> &pub, std::vector<GpgME::Key> &sec, bool mergeKeys = false) = 0;

Q_SIGNALS:
    void result(const GpgME::KeyListResult &result, const std::vector<GpgME::Key> &pub = std::vector<GpgME::Key>(), const std::vector<GpgME::Key> &sec = std::vector<GpgME::Key>(), const QString &auditLogAsHtml = QString(), const GpgME::Error &auditLogError = GpgME::Error());
};

Q_DECLARE_OPERATORS_FOR_FLAGS(ListAllKeysJob::Options)

}

#endif // __KLEO_LISTALLKEYSJOB_H__
