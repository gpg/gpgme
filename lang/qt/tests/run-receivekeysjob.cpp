/*
    run-receivekeysjob.cpp

    This file is part of QGpgME's test suite.
    Copyright (c) 2022 by g10 Code GmbH
    Software engineering by Ingo Klöcker <dev@ingo-kloecker.de>

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

#include <debug.h>
#include <gpgme++/importresult.h>
#include <protocol.h>
#include <receivekeysjob.h>

#include <QCoreApplication>
#include <QDebug>

#include <iostream>

int main(int argc, char **argv)
{
    GpgME::initializeLibrary();

    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " KEYID..." << std::endl;
        return 1;
    }

    QCoreApplication app(argc, argv);
    const QStringList keyIds = qApp->arguments().mid(1);

    auto job = QGpgME::openpgp()->receiveKeysJob();
    const auto result = job->exec(keyIds);

    std::cout << "Result: " << result.error() << std::endl;
    std::cout << "Details:\n" << result << std::endl;

    return 0;
}
