/*
    hierarchicalkeylistjob.h

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004 Klarälvdalens Datakonsult AB
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

#ifndef __KLEO_HIERARCHICALKEYLISTJOB_H__
#define __KLEO_HIERARCHICALKEYLISTJOB_H__

#include "qgpgme_export.h"
#include "keylistjob.h"
#include "cryptobackend.h"

#include <gpgme++/keylistresult.h>

#include <QPointer>

#include <set>

namespace GpgME
{
class Error;
class Key;
}

namespace QGpgME
{
class KeyListJob;
}

namespace QGpgME
{

/**
   @short A convenience job that additionally fetches all available issuers.

   To use a HierarchicalKeyListJob, pass it a CryptoBackend
   implementation, connect the progress() and result() signals to
   suitable slots and then start the keylisting with a call to
   start(). This call might fail, in which case the
   HierarchicalKeyListJob instance will have scheduled it's own
   destruction with a call to QObject::deleteLater().

   After result() is emitted, the HierarchicalKeyListJob will
   schedule its own destruction by calling QObject::deleteLater().
*/
class QGPGME_EXPORT HierarchicalKeyListJob : public KeyListJob
{
    Q_OBJECT
public:
    explicit HierarchicalKeyListJob(const Protocol *protocol,
                                    bool remote = false, bool includeSigs = false,
                                    bool validating = false);
    ~HierarchicalKeyListJob();

    /**
       Starts the keylist operation. \a patterns is a list of patterns
       used to restrict the list of keys returned. Empty patterns are
       ignored. \a patterns must not be empty or contain only empty
       patterns; use the normal KeyListJob for a full listing.

       The \a secretOnly parameter is ignored by
       HierarchicalKeyListJob and must be set to false.
    */
    GpgME::Error start(const QStringList &patterns, bool secretOnly = false) override;

    GpgME::KeyListResult exec(const QStringList &patterns, bool secretOnly,
                              std::vector<GpgME::Key> &keys) override;

private Q_SLOTS:
    void slotResult(const GpgME::KeyListResult &);
    void slotNextKey(const GpgME::Key &key);
    /* from Job */
    void slotCancel() override;

private:
    GpgME::Error startAJob();

private:
    const Protocol *const mProtocol;
    const bool mRemote;
    const bool mIncludeSigs;
    const bool mValidating;
    bool mTruncated;
    std::set<QString> mSentSet; // keys already sent (prevent duplicates even if the backend should return them)
    std::set<QString> mScheduledSet; // keys already scheduled (by starting a job for them)
    std::set<QString> mNextSet; // keys to schedule for the next iteraton
    GpgME::KeyListResult mIntermediateResult;
    QPointer<KeyListJob> mJob;
};

}

#endif // __KLEO_HIERARCHICALKEYLISTJOB_H__
