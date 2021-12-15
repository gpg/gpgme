/* t-import.cpp

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

#ifdef HAVE_CONFIG_H
 #include "config.h"
#endif

#include "t-support.h"

#include "context.h"
#include "engineinfo.h"
#include "protocol.h"
#include "importjob.h"

#include <gpgme++/importresult.h>

#include <QDebug>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTest>

using namespace QGpgME;
using namespace GpgME;

class ImportTest : public QGpgMETest
{
    Q_OBJECT

private:
    QTemporaryDir tempGpgHome;

Q_SIGNALS:
    void asyncDone();

private Q_SLOTS:
    void initTestCase()
    {
        QGpgMETest::initTestCase();
        QVERIFY2(tempGpgHome.isValid(), "Failed to create temporary GNUPGHOME");
        qputenv("GNUPGHOME", tempGpgHome.path().toLocal8Bit());
    }

    void testImportWithKeyOrigin()
    {
        if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < "2.1.22") {
            QSKIP("gpg does not yet support the --key-origin option");
        }

        static const char keyFpr[] = "5C5C428FABCC20F6913464BCCA6FB442887289B3";
        static const char keyData[] =
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
            "\n"
            "mDMEYbhuixYJKwYBBAHaRw8BAQdAulOM3IksCjdOJluEVlwalD8oZ5oa6wCw3EgW\n"
            "NswXXb60H2ltcG9ydFdpdGhLZXlPcmlnaW5AZXhhbXBsZS5uZXSIlAQTFgoAPBYh\n"
            "BFxcQo+rzCD2kTRkvMpvtEKIcomzBQJhuG6LAhsDBQsJCAcCAyICAQYVCgkICwIE\n"
            "FgIDAQIeBwIXgAAKCRDKb7RCiHKJs+cIAQDaeoOw1OCAGpZQb8xJmLJHul5dLLzU\n"
            "RBdHauMx9NROmQEA23QUVedc7walQjNKFzyIJA/YqRdbAKPiLonRBmxk9Ay4OARh\n"
            "uG6LEgorBgEEAZdVAQUBAQdAMVdO9mNWIP/q8PtNOnBGlPyhx/vs07sF5sXk50A+\n"
            "61QDAQgHiHgEGBYKACAWIQRcXEKPq8wg9pE0ZLzKb7RCiHKJswUCYbhuiwIbDAAK\n"
            "CRDKb7RCiHKJs/x6AP0SEbZqW4iLCz2i1JntQghK5qpSZOVqsBTcARd6pcJ/cwEA\n"
            "mrwskWazuS9+GVbHT5RATWOXnGaj+AICSDPE6qHtGgA=\n"
            "=putz\n"
            "-----END PGP PUBLIC KEY BLOCK-----\n";

        auto *job = openpgp()->importJob();
        job->setKeyOrigin(GpgME::Key::OriginWKD, "https://example.net");
        connect(job, &ImportJob::result, this,
                [this](ImportResult result, QString, Error)
        {
            QVERIFY(!result.error());
            QVERIFY(!result.imports().empty());
            QVERIFY(result.numImported());
            Q_EMIT asyncDone();
        });
        job->start(QByteArray{keyData});
        QSignalSpy spy (this, SIGNAL(asyncDone()));
        QVERIFY(spy.wait());

        auto ctx = Context::createForProtocol(GpgME::OpenPGP);
        GpgME::Error err;
        const auto key = ctx->key(keyFpr, err, false);
        QVERIFY(!key.isNull());
        QVERIFY(key.origin() == Key::OriginWKD);
        // the origin URL is currently not available in GpgME
    }
};

QTEST_MAIN(ImportTest)

#include "t-import.moc"
