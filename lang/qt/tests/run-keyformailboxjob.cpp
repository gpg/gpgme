/*
    run-keyformailbox.cpp

    This file is part of QGpgME's test suite.
    Copyright (c) 2016 by Bundesamt für Sicherheit in der Informationstechnik
    Software engineering by Intevation GmbH

    QGpgME is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License,
    version 2, as published by the Free Software Foundation.

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

#include "keyformailboxjob.h"
#include "keylistjob.h"
#include "protocol.h"

#include <gpgme++/key.h>
#include <gpgme++/keylistresult.h>

#include <QDebug>


int main(int argc, char **argv)
{
    QString mailbox;
    if (argc == 2) {
        mailbox = QString::fromLocal8Bit(argv[1]);
    }

    auto job = QGpgME::openpgp()->keyForMailboxJob();
    GpgME::Key k;
    GpgME::UserID uid;
    job->exec(mailbox, true, k, uid);
    qDebug() << "UID Name: " << uid.name() << " Mail: " << uid.email() << " id: " << uid.id();
    qDebug() << "Key fpr: " << k.primaryFingerprint();
    return 0;
}
