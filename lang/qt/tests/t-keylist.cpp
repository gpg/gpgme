#include <QDebug>
#include <QTest>
#include <QSignalSpy>
#include "keylistjob.h"
#include "qgpgmebackend.h"
#include "keylistresult.h"

using namespace QGpgME;
using namespace GpgME;

class KeyListTest : public QObject
{
    Q_OBJECT

Q_SIGNALS:
    void asyncDone();

private Q_SLOTS:

    void testSingleKeyListSync()
    {
        KeyListJob *job = openpgp()->keyListJob(false, false, false);
        std::vector<GpgME::Key> keys;
        GpgME::KeyListResult result = job->exec(QStringList() << QStringLiteral("alfa@example.net"),
                                                false, keys);
        Q_ASSERT (!result.error());
        Q_ASSERT (keys.size() == 1);
        const QString kId = QLatin1String(keys.front().keyID());
        Q_ASSERT (kId == QStringLiteral("2D727CC768697734"));
    }

    void testKeyListAsync()
    {
        KeyListJob *job = openpgp()->keyListJob();
        connect(job, &KeyListJob::result, job, [this, job](KeyListResult, std::vector<Key> keys, QString, Error)
        {
            Q_ASSERT(keys.size() == 1);
            Q_EMIT asyncDone();
        });
        job->start(QStringList() << "alfa@example.net");
        QSignalSpy spy (this, &KeyListTest::asyncDone);
        Q_ASSERT(spy.wait());
    }

    void initTestCase()
    {
        const QString gpgHome = qgetenv("GNUPGHOME");
        QVERIFY2(!gpgHome.isEmpty(), "GNUPGHOME environment variable is not set.");
    }
};

QTEST_MAIN(KeyListTest)

#include "t-keylist.moc"
