/* t-remarks.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2017 by Bundesamt für Sicherheit in der Informationstechnik
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


#ifdef HAVE_CONFIG_H
 #include "config.h"
#endif

#include <QDebug>
#include <QTest>
#include <QSignalSpy>
#include <QTemporaryDir>
#include "keylistjob.h"
#include "protocol.h"
#include "signkeyjob.h"
#include <gpgme++/context.h>
#include <gpgme++/engineinfo.h>

#include "t-support.h"

using namespace QGpgME;
using namespace GpgME;

class TestRemarks: public QGpgMETest
{
    Q_OBJECT

public:
    // This test is disabled (no slot) because the behavior
    // is not clearly defined. Better to prevent that
    // case in the UI
    void testRemarkOwnKey()
    {
        if (!loopbackSupported()) {
            return;
        }
        // Get the signing key (alfa)
        auto ctx = Context::create(OpenPGP);
        QVERIFY (ctx);
        Error err;
        auto seckey = ctx->key("A0FF4590BB6122EDEF6E3C542D727CC768697734", err, true);
        QVERIFY (!seckey.isNull());
        QVERIFY (!err);

        // Create the job
        auto job = openpgp()->signKeyJob();
        QVERIFY (job);
        hookUpPassphraseProvider(job);

        // Set up the job
        job->setExportable(false);
        std::vector<unsigned int> uids;
        uids.push_back(0);
        job->setUserIDsToSign(uids);
        job->setSigningKey(seckey);
        job->setRemark(QStringLiteral("Just GNU it!"));
        job->setDupeOk(true);

        connect(job, &SignKeyJob::result, this, [this] (const GpgME::Error &err2,
                                                        const QString,
                                                        const GpgME::Error) {
            Q_EMIT asyncDone();
            if (err2) {
                qDebug() << "Error: " << err2.asString();
            }
            QVERIFY(err2);
        });

        job->start(seckey);
        QSignalSpy spy (this, SIGNAL(asyncDone()));
        QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));
    }


private Q_SLOTS:

    void testRemarkReplaceSingleUIDExportable()
    {
        if (!loopbackSupported()) {
            return;
        }
        // Get the signing key (alfa)
        auto ctx = Context::create(OpenPGP);
        QVERIFY (ctx);
        Error err;
        auto seckey = ctx->key("A0FF4590BB6122EDEF6E3C542D727CC768697734", err, true);
        QVERIFY (!seckey.isNull());
        QVERIFY (!err);

        // Get the target key (tango)
        auto target = ctx->key("ECAC774F4EEEB0620767044A58CB9A4C85A81F38", err, false);
        QVERIFY (!target.isNull());
        QVERIFY (!err);
        QVERIFY (target.numUserIDs());

        // Create the job
        auto job = openpgp()->signKeyJob();
        QVERIFY (job);
        hookUpPassphraseProvider(job);

        // Set up the job
        job->setExportable(true);
        std::vector<unsigned int> uids;
        uids.push_back(0);
        job->setUserIDsToSign(uids);
        job->setSigningKey(seckey);
        job->setRemark(QStringLiteral("The quick brown fox jumps over the lazy dog"));

        connect(job, &SignKeyJob::result, this, [this] (const GpgME::Error &err2,
                                                        const QString,
                                                        const GpgME::Error) {
            Q_EMIT asyncDone();
            QVERIFY(!err2);
        });

        job->start(target);
        QSignalSpy spy (this, SIGNAL(asyncDone()));
        QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

        // At this point the remark should have been added.
        target.update();
        const char *remark = target.userID(0).remark(seckey, err);
        QVERIFY(!err);
        QVERIFY(remark);
        QCOMPARE(QString::fromUtf8(remark), QStringLiteral("The quick brown fox "
                                                           "jumps over the lazy dog"));

        // Now replace the remark
        auto job3 = openpgp()->signKeyJob();
        QVERIFY (job3);
        hookUpPassphraseProvider(job3);

        // Set up the job
        job3->setExportable(false);
        job3->setUserIDsToSign(uids);
        job3->setSigningKey(seckey);
        job3->setDupeOk(true);
        job3->setRemark(QStringLiteral("The quick brown fox fails to jump over Frodo"));

        connect(job3, &SignKeyJob::result, this, [this] (const GpgME::Error &err2,
                                                         const QString,
                                                         const GpgME::Error) {
            Q_EMIT asyncDone();
            QVERIFY(!err2);
        });

        job3->start(target);
        QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

        target.update();
        remark = target.userID(0).remark(seckey, err);
        QVERIFY(!err);
        QVERIFY(remark);
        QCOMPARE(QString::fromUtf8(remark), QStringLiteral("The quick brown fox fails "
                                                           "to jump over Frodo"));
    }


    void testMultipleRemarks()
    {
        if (!loopbackSupported()) {
            return;
        }
        // Get the signing key1 (alfa)
        auto ctx = Context::create(OpenPGP);
        QVERIFY (ctx);
        Error err;
        auto alpha = ctx->key("A0FF4590BB6122EDEF6E3C542D727CC768697734", err, true);
        QVERIFY (!alpha.isNull());
        QVERIFY (!err);

        // Get the signing key2 (zulu)
        auto zulu = ctx->key("23FD347A419429BACCD5E72D6BC4778054ACD246", err, true);
        QVERIFY (!zulu.isNull());
        QVERIFY (!err);

        // Get the target key (victor)
        auto target = ctx->key("E8143C489C8D41124DC40D0B47AF4B6961F04784", err, false);
        QVERIFY (!target.isNull());
        QVERIFY (!err);
        QVERIFY (target.numUserIDs());

        // Create the job
        auto job = openpgp()->signKeyJob();
        QVERIFY (job);
        hookUpPassphraseProvider(job);

        // Setup the first job
        job->setExportable(false);
        std::vector<unsigned int> uids;
        uids.push_back(0);
        job->setUserIDsToSign(uids);
        job->setSigningKey(alpha);
        job->setRemark(QStringLiteral("String one"));

        connect(job, &SignKeyJob::result, this, [this] (const GpgME::Error &err2,
                                                        const QString,
                                                        const GpgME::Error) {
            Q_EMIT asyncDone();
            QVERIFY(!err2);
        });
        job->start(target);
        QSignalSpy spy (this, SIGNAL(asyncDone()));
        QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

        // Now another remark from zulu
        auto job3 = openpgp()->signKeyJob();
        QVERIFY (job3);
        hookUpPassphraseProvider(job3);

        // Set up the job
        job3->setExportable(false);
        job3->setUserIDsToSign(uids);
        job3->setSigningKey(zulu);
        job3->setDupeOk(true);
        job3->setRemark(QStringLiteral("String two"));

        connect(job3, &SignKeyJob::result, this, [this] (const GpgME::Error &err2,
                                                         const QString,
                                                         const GpgME::Error) {
            Q_EMIT asyncDone();
            QVERIFY(!err2);
        });

        job3->start(target);
        QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

        target.update();
        std::vector<GpgME::Key> keys;
        keys.push_back(alpha);
        keys.push_back(zulu);

        const auto remarks = target.userID(0).remarks(keys, err);

        QVERIFY(!err);
        QVERIFY(remarks.size() == 2);
        QCOMPARE(remarks[0], std::string("String one"));
        QCOMPARE(remarks[1], std::string("String two"));
    }

    void testRemarkReplaceSingleUID()
    {
        if (!loopbackSupported()) {
            return;
        }
        // Get the signing key (alfa)
        auto ctx = Context::create(OpenPGP);
        QVERIFY (ctx);
        Error err;
        auto seckey = ctx->key("A0FF4590BB6122EDEF6E3C542D727CC768697734", err, true);
        QVERIFY (!seckey.isNull());
        QVERIFY (!err);

        // Get the target key (xray)
        auto target = ctx->key("04C1DF62EFA0EBB00519B06A8979A6C5567FB34A", err, false);
        QVERIFY (!target.isNull());
        QVERIFY (!err);
        QVERIFY (target.numUserIDs());

        // Create the job
        auto job = openpgp()->signKeyJob();
        QVERIFY (job);
        hookUpPassphraseProvider(job);

        // Set up the job
        job->setExportable(false);
        std::vector<unsigned int> uids;
        uids.push_back(0);
        job->setUserIDsToSign(uids);
        job->setSigningKey(seckey);
        job->setRemark(QStringLiteral("The quick brown fox jumps over the lazy dog"));

        connect(job, &SignKeyJob::result, this, [this] (const GpgME::Error &err2,
                                                        const QString,
                                                        const GpgME::Error) {
            Q_EMIT asyncDone();
            QVERIFY(!err2);
        });

        job->start(target);
        QSignalSpy spy (this, SIGNAL(asyncDone()));
        QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

        // At this point the remark should have been added.
        target.update();
        const char *remark = target.userID(0).remark(seckey, err);
        QVERIFY(!err);
        QVERIFY(remark);
        QCOMPARE(QString::fromUtf8(remark), QStringLiteral("The quick brown fox "
                                                           "jumps over the lazy dog"));

        // Now replace the remark
        auto job3 = openpgp()->signKeyJob();
        QVERIFY (job3);
        hookUpPassphraseProvider(job3);

        // Set up the job
        job3->setExportable(false);
        job3->setUserIDsToSign(uids);
        job3->setSigningKey(seckey);
        job3->setDupeOk(true);
        job3->setRemark(QStringLiteral("The quick brown fox jumps over Frodo"));

        connect(job3, &SignKeyJob::result, this, [this] (const GpgME::Error &err2,
                                                         const QString,
                                                         const GpgME::Error) {
            Q_EMIT asyncDone();
            QVERIFY(!err2);
        });

        job3->start(target);
        QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

        target.update();
        remark = target.userID(0).remark(seckey, err);
        QVERIFY(!err);
        QVERIFY(remark);
        QCOMPARE(QString::fromUtf8(remark), QStringLiteral("The quick brown fox "
                                                            "jumps over Frodo"));
    }

    void testRemarkReplaceMultiUID()
    {
        if (!loopbackSupported()) {
            return;
        }
        // Get the signing key (alfa)
        auto ctx = Context::create(OpenPGP);
        QVERIFY (ctx);
        Error err;
        auto seckey = ctx->key("A0FF4590BB6122EDEF6E3C542D727CC768697734", err, true);
        QVERIFY (!seckey.isNull());
        QVERIFY (!err);

        // Get the target key (mallory / mike)
        auto target = ctx->key("2686AA191A278013992C72EBBE794852BE5CF886", err, false);
        QVERIFY (!target.isNull());
        QVERIFY (!err);
        QVERIFY (target.numUserIDs());

        // Create the job
        auto job = openpgp()->signKeyJob();
        QVERIFY (job);
        hookUpPassphraseProvider(job);

        // Set up the job
        job->setExportable(false);
        std::vector<unsigned int> uids;
        uids.push_back(0);
        job->setUserIDsToSign(uids);
        job->setSigningKey(seckey);
        job->setRemark(QStringLiteral("Mallory is evil 😠"));

        connect(job, &SignKeyJob::result, this, [this] (const GpgME::Error &err2,
                                                        const QString,
                                                        const GpgME::Error) {
            Q_EMIT asyncDone();
            QVERIFY(!err2);
        });

        job->start(target);
        QSignalSpy spy (this, SIGNAL(asyncDone()));
        QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

        // At this point the remark should have been added.
        target.update();
        const char *remark = target.userID(0).remark(seckey, err);
        QVERIFY(!err);
        QVERIFY(remark);
        QCOMPARE(QString::fromUtf8(remark), QStringLiteral("Mallory is evil 😠"));

        // Try to replace it without dupeOK
        auto job2 = openpgp()->signKeyJob();
        QVERIFY (job2);
        hookUpPassphraseProvider(job2);

        // Set up the job
        job2->setExportable(false);
        job2->setUserIDsToSign(uids);
        job2->setSigningKey(seckey);
        job2->setRemark(QStringLiteral("Mallory is nice"));

        connect(job2, &SignKeyJob::result, this, [this] (const GpgME::Error &err2,
                                                         const QString,
                                                         const GpgME::Error) {
            Q_EMIT asyncDone();
            QVERIFY(err2);
        });

        job2->start(target);
        QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

        // Now replace the remark
        auto job3 = openpgp()->signKeyJob();
        QVERIFY (job3);
        hookUpPassphraseProvider(job3);

        // Set up the job
        job3->setExportable(false);
        job3->setUserIDsToSign(uids);
        job3->setSigningKey(seckey);
        job3->setDupeOk(true);
        job3->setRemark(QStringLiteral("Mallory is nice"));

        connect(job3, &SignKeyJob::result, this, [this] (const GpgME::Error &err2,
                                                         const QString,
                                                         const GpgME::Error) {
            Q_EMIT asyncDone();
            QVERIFY(!err2);
        });

        job3->start(target);
        QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

        target.update();
        remark = target.userID(0).remark(seckey, err);
        QVERIFY(!err);
        QVERIFY(remark);
        QCOMPARE(QString::fromUtf8(remark), QStringLiteral("Mallory is nice"));
    }

    void initTestCase()
    {
        QGpgMETest::initTestCase();
        const QString gpgHome = qgetenv("GNUPGHOME");
        QVERIFY(copyKeyrings(gpgHome, mDir.path()));
        qputenv("GNUPGHOME", mDir.path().toUtf8());
        QFile conf(mDir.path() + QStringLiteral("/gpg.conf"));
        QVERIFY(conf.open(QIODevice::WriteOnly));
        if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() >= "2.2.18") {
            conf.write("allow-weak-key-signatures");
        }
        conf.close();
    }

private:
    QTemporaryDir mDir;
};

QTEST_MAIN(TestRemarks)

#include "t-remarks.moc"
