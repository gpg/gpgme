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

#include <gpgme++/context.h>
#include <gpgme++/engineinfo.h>
#include "protocol.h"
#include "importjob.h"

#include <gpgme++/importresult.h>

#include <QDebug>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTest>

#include <memory>

using namespace QGpgME;
using namespace GpgME;

class ImportTest : public QGpgMETest
{
    Q_OBJECT

private:
    QTemporaryDir tempGpgHome;

private Q_SLOTS:
    void initTestCase()
    {
        QGpgMETest::initTestCase();
        QVERIFY2(tempGpgHome.isValid(), "Failed to create temporary GNUPGHOME");
        qputenv("GNUPGHOME", tempGpgHome.path().toLocal8Bit());
    }

    void testImportWithImportFilter()
    {
        if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < "2.1.14") {
            QSKIP("gpg does not yet support the --import-filter option");
        }

        // pub   ed25519 2021-12-15 [SC]
        //       E7A0841292ACC9465D3142652FB3A6F51FBF28A2
        // uid           [ultimate] importWithImportFilter@example.com
        // uid           [ultimate] importWithImportFilter@example.net
        // sub   cv25519 2021-12-15 [E]
        static const char keyFpr[] = "E7A0841292ACC9465D3142652FB3A6F51FBF28A2";
        static const char keyData[] =
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
            "\n"
            "mDMEYbm2PhYJKwYBBAHaRw8BAQdACzxBWtNNsmJ6rzpZkjh1yBe+Ajsk9NR8umEu\n"
            "Da3HLgG0ImltcG9ydFdpdGhJbXBvcnRGaWx0ZXJAZXhhbXBsZS5uZXSIlAQTFgoA\n"
            "PBYhBOeghBKSrMlGXTFCZS+zpvUfvyiiBQJhubY+AhsDBQsJCAcCAyICAQYVCgkI\n"
            "CwIEFgIDAQIeBwIXgAAKCRAvs6b1H78oosRgAQCc/ke6q076nvzIE2UzT83JK/B6\n"
            "lxSV7Fb8bKltOMpvsAD+Phap3EzA8jdMyKoO0FM926bw5lX7QROfeZ/JBYqyPwC0\n"
            "ImltcG9ydFdpdGhJbXBvcnRGaWx0ZXJAZXhhbXBsZS5jb22IlAQTFgoAPBYhBOeg\n"
            "hBKSrMlGXTFCZS+zpvUfvyiiBQJhubZlAhsDBQsJCAcCAyICAQYVCgkICwIEFgID\n"
            "AQIeBwIXgAAKCRAvs6b1H78oohPWAQC/u9UXzkxRkrB2huaTZCsyimWEGZIMmxWd\n"
            "tE+vN9/IvQD/Yzia+xRS6yca3Yz6iW8xS844ZqRxvkUEHjtJXSOzagm4OARhubY+\n"
            "EgorBgEEAZdVAQUBAQdANQFjmDctY3N0/ELPZtj9tapwFs4vrmTVpx/SCfZmihkD\n"
            "AQgHiHgEGBYKACAWIQTnoIQSkqzJRl0xQmUvs6b1H78oogUCYbm2PgIbDAAKCRAv\n"
            "s6b1H78oovGyAP41ySzvvDpV7XDJBOAFxvWLmywa5IcO7Lrg7y1efoWj0AD+Kk/B\n"
            "s7jGLdoG51h670h50MMoYCANB6MwAdSP+qZUlQg=\n"
            "=/3O0\n"
            "-----END PGP PUBLIC KEY BLOCK-----\n";

        auto *job = openpgp()->importJob();
        job->setImportFilter(QLatin1String{"keep-uid=mbox = importWithImportFilter@example.net"});
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

        auto ctx = std::unique_ptr<GpgME::Context>(Context::createForProtocol(GpgME::OpenPGP));
        GpgME::Error err;
        const auto key = ctx->key(keyFpr, err, false);
        QVERIFY(!key.isNull());
        QCOMPARE(key.numUserIDs(), 1u);
        QCOMPARE(key.userID(0).id(), "importWithImportFilter@example.net");
    }

    void testImportWithImportOptions()
    {
        if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < "2.1.23") {
            QSKIP("gpg does not yet support --import-options show-only");
        }

        // pub   ed25519 2024-06-12 [SC]
        //       A52F4947AF1506F3A7572EFC140278B773CA7C16
        // uid                      importOptions@example.net
        static const char keyFpr[] = "A52F4947AF1506F3A7572EFC140278B773CA7C16";
        static const char keyData[] =
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
            "\n"
            "mDMEZmlpmBYJKwYBBAHaRw8BAQdAZaSopKwccTwnMlJBVCWMT6et1T1WF9EkXdJi\n"
            "gzI74xW0GWltcG9ydE9wdGlvbnNAZXhhbXBsZS5uZXSIkwQTFgoAOxYhBKUvSUev\n"
            "FQbzp1cu/BQCeLdzynwWBQJmaWmYAhsDBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4H\n"
            "AheAAAoJEBQCeLdzynwWjmQBAP4dQEN/M4/dKIAlxNAbWzIkV+eSoUFLJszOJ/xx\n"
            "FwJzAP43gkdXkUsHZt/U3mLZqtiHJFd7JxVm7hKRoAVBhZZYDw==\n"
            "=7Z1j\n"
            "-----END PGP PUBLIC KEY BLOCK-----\n";

        auto *job = openpgp()->importJob();
        job->setImportOptions({QStringLiteral("show-only")});
        connect(job, &ImportJob::result, this,
                [this](ImportResult result, QString, Error)
        {
            QVERIFY(!result.error());
            QCOMPARE(result.numConsidered(), 0);
            QCOMPARE(result.numImported(), 0);
            QVERIFY(result.imports().empty());
            Q_EMIT asyncDone();
        });
        job->start(QByteArray{keyData});
        QSignalSpy spy (this, SIGNAL(asyncDone()));
        QVERIFY(spy.wait());

        auto ctx = std::unique_ptr<GpgME::Context>(Context::createForProtocol(GpgME::OpenPGP));
        GpgME::Error err;
        const auto key = ctx->key(keyFpr, err, false);
        QVERIFY(key.isNull());
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

        auto ctx = std::unique_ptr<GpgME::Context>(Context::createForProtocol(GpgME::OpenPGP));
        GpgME::Error err;
        const auto key = ctx->key(keyFpr, err, false);
        QVERIFY(!key.isNull());
        QVERIFY(key.origin() == Key::OriginWKD);
        // the origin URL is currently not available in GpgME
    }

    void testDeferredStart()
    {
        // pub   ed25519 2023-01-05 [SC]
        //       4D1367FE9AF6334D8A55BA635A817A94C7B37E5D
        // uid                      importDeferred@example.net
        static const char keyFpr[] = "4D1367FE9AF6334D8A55BA635A817A94C7B37E5D";
        static const char keyData[] =
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
            "\n"
            "mDMEY7bNSxYJKwYBBAHaRw8BAQdAazIWyd/xEMeObDSUnh2+AXQuo0oM+TDBG49z\n"
            "KHvTAYG0GmltcG9ydERlZmVycmVkQGV4YW1wbGUubmV0iJMEExYKADsWIQRNE2f+\n"
            "mvYzTYpVumNagXqUx7N+XQUCY7bNSwIbAwULCQgHAgIiAgYVCgkICwIEFgIDAQIe\n"
            "BwIXgAAKCRBagXqUx7N+XasrAP4qPzLzPd6tWDZvP29ZYPTSrjrTb0U5MOJeIPKX\n"
            "73jZswEAwWRvgH+GmhTOigw0UVtinAFvUEFVyvcW/GR19mw5XA0=\n"
            "=JnpA\n"
            "-----END PGP PUBLIC KEY BLOCK-----\n";

        auto *job = openpgp()->importJob();
        job->startLater(QByteArray{keyData});
        connect(job, &ImportJob::result, this,
                [this](ImportResult result, QString, Error)
        {
            QVERIFY(!result.error());
            QVERIFY(!result.imports().empty());
            QVERIFY(result.numImported());
            Q_EMIT asyncDone();
        });
        job->startNow();
        QSignalSpy spy (this, SIGNAL(asyncDone()));
        QVERIFY(spy.wait());

        auto ctx = std::unique_ptr<GpgME::Context>(Context::createForProtocol(GpgME::OpenPGP));
        GpgME::Error err;
        const auto key = ctx->key(keyFpr, err, false);
        QVERIFY(!key.isNull());
    }
};

QTEST_MAIN(ImportTest)

#include "t-import.moc"
