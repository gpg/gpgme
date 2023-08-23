/*
    wkdrefreshjob.h

    This file is part of qgpgme, the Qt API binding for gpgme
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

#ifndef __QGPGME_WKDREFRESHJOB_H__
#define __QGPGME_WKDREFRESHJOB_H__

#include "abstractimportjob.h"
#include "qgpgme_export.h"

#include <vector>

namespace GpgME
{
class Error;
class Key;
class UserID;
}

namespace QGpgME
{

/**
 * This job refreshes OpenPGP keys via WKD.
 */
class QGPGME_EXPORT WKDRefreshJob : public AbstractImportJob
{
    Q_OBJECT
protected:
    explicit WKDRefreshJob(QObject *parent);
public:
    ~WKDRefreshJob() override;

    /**
     * Starts a refresh of the \a keys. Only user IDs that have WKD set as
     * origin are used for the WKD lookup. Revoked user IDs are ignored.
     *
     * Use the other start overload to use all user IDs for the WKD lookup.
     */
    GpgME::Error start(const std::vector<GpgME::Key> &keys);

    /**
     * Starts a refresh of the keys belonging to the user IDs \a userIDs.
     * All user IDs are used for the WKD lookup. Revoked user IDs are ignored.
     */
    GpgME::Error start(const std::vector<GpgME::UserID> &userIDs);
};

}

#endif // __QGPGME_WKDREFRESHJOB_H__
