/*
    qgpgmecryptoconfig.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004 Klarälvdalens Datakonsult AB
    Copyright (c) 2016 Intevation GmbH

    Libkleopatra is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation; either version 2 of the
    License, or (at your option) any later version.

    Libkleopatra is distributed in the hope that it will be useful,
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

#include "qgpgmecryptoconfig.h"

#include <QList>
#include <QByteArray>
#include <errno.h>
#include "gpgme_backend_debug.h"

#include "engineinfo.h"
#include "global.h"

#include <cassert>
#include <QTemporaryFile>
#include <QFile>
#include <cstdlib>
#include <iterator>
#include <QStandardPaths>

// Just for the Q_ASSERT in the dtor. Not thread-safe, but who would
// have 2 threads talking to gpgconf anyway? :)
static bool s_duringClear = false;

static const int GPGCONF_FLAG_GROUP = 1;
static const int GPGCONF_FLAG_OPTIONAL = 2;
static const int GPGCONF_FLAG_LIST = 4;
static const int GPGCONF_FLAG_RUNTIME = 8;
static const int GPGCONF_FLAG_DEFAULT = 16; // fixed default value available
//static const int GPGCONF_FLAG_DEFAULT_DESC = 32; // runtime default value available
//static const int GPGCONF_FLAG_NOARG_DESC = 64; // option with optional arg; special meaning if no arg set
static const int GPGCONF_FLAG_NO_CHANGE = 128; // readonly
// Change size of mFlags bitfield if adding new values here

QString QGpgMECryptoConfig::gpgConfPath()
{
    const GpgME::EngineInfo info = GpgME::engineInfo(GpgME::GpgConfEngine);
    return info.fileName() ? QFile::decodeName(info.fileName()) : QStandardPaths::findExecutable(QStringLiteral("gpgconf"));
}

QGpgMECryptoConfig::QGpgMECryptoConfig()
    :  mParsed(false)
{
}

QGpgMECryptoConfig::~QGpgMECryptoConfig()
{
    clear();
}

void QGpgMECryptoConfig::runGpgConf(bool showErrors)
{
    // Run gpgconf --list-components to make the list of components
    KProcess process;

    process << gpgConfPath();
    process << QStringLiteral("--list-components");

    connect(&process, &KProcess::readyReadStandardOutput, this, &QGpgMECryptoConfig::slotCollectStdOut);

    // run the process:
    int rc = 0;
    process.setOutputChannelMode(KProcess::OnlyStdoutChannel);
    process.start();
    if (!process.waitForFinished()) {
        rc = -2;
    } else if (process.exitStatus() == QProcess::NormalExit) {
        rc = process.exitCode();
    } else {
        rc = -1;
    }

    // handle errors, if any (and if requested)
    if (showErrors && rc != 0) {
        QString reason;
        if (rc == -1) {
            reason = i18n("program terminated unexpectedly");
        } else if (rc == -2) {
            reason = i18n("program not found or cannot be started");
        } else {
            reason = QString::fromLocal8Bit(strerror(rc));    // XXX errno as an exit code?
        }
        QString wmsg = i18n("<qt>Failed to execute gpgconf:<p>%1</p></qt>", reason);
        qCWarning(GPGPME_BACKEND_LOG) << wmsg; // to see it from test_cryptoconfig.cpp
        KMessageBox::error(0, wmsg);
    }
    mParsed = true;
}

void QGpgMECryptoConfig::slotCollectStdOut()
{
    assert(qobject_cast<KProcess *>(QObject::sender()));
    KProcess *const proc = static_cast<KProcess *>(QObject::sender());
    while (proc->canReadLine()) {
        QString line = QString::fromUtf8(proc->readLine());
        if (line.endsWith(QLatin1Char('\n'))) {
            line.chop(1);
        }
        if (line.endsWith(QLatin1Char('\r'))) {
            line.chop(1);
        }
        //qCDebug(GPGPME_BACKEND_LOG) <<"GOT LINE:" << line;
        // Format: NAME:DESCRIPTION
        const QStringList lst = line.split(QLatin1Char(':'));
        if (lst.count() >= 2) {
            const std::pair<QString, QGpgMECryptoConfigComponent *> pair(lst[0], new QGpgMECryptoConfigComponent(this, lst[0], lst[1]));
            mComponentsNaturalOrder.push_back(pair);
            mComponentsByName[pair.first] = pair.second;
        } else {
            qCWarning(GPGPME_BACKEND_LOG) << "Parse error on gpgconf --list-components output:" << line;
        }
    }
}

namespace
{
struct Select1St {
    template <typename U, typename V>
    const U &operator()(const std::pair<U, V> &p) const
    {
        return p.first;
    }
    template <typename U, typename V>
    const U &operator()(const QPair<U, V> &p) const
    {
        return p.first;
    }
};
}

QStringList QGpgMECryptoConfig::componentList() const
{
    if (!mParsed) {
        const_cast<QGpgMECryptoConfig *>(this)->runGpgConf(true);
    }
    QStringList result;
    std::transform(mComponentsNaturalOrder.begin(), mComponentsNaturalOrder.end(),
                   std::back_inserter(result), Select1St());
    return result;
}

QGpgME::CryptoConfigComponent *QGpgMECryptoConfig::component(const QString &name) const
{
    if (!mParsed) {
        const_cast<QGpgMECryptoConfig *>(this)->runGpgConf(false);
    }
    return mComponentsByName.value(name);
}

void QGpgMECryptoConfig::sync(bool runtime)
{
    Q_FOREACH (QGpgMECryptoConfigComponent *it, mComponentsByName) {
        it->sync(runtime);
    }
}

void QGpgMECryptoConfig::clear()
{
    s_duringClear = true;
    mComponentsNaturalOrder.clear();
    qDeleteAll(mComponentsByName);
    mComponentsByName.clear();
    s_duringClear = false;
    mParsed = false; // next call to componentList/component will need to run gpgconf again
}

////

QGpgMECryptoConfigComponent::QGpgMECryptoConfigComponent(QGpgMECryptoConfig *, const QString &name, const QString &description)
    : mName(name), mDescription(description)
{
    runGpgConf();
}

QGpgMECryptoConfigComponent::~QGpgMECryptoConfigComponent()
{
    mGroupsNaturalOrder.clear();
    qDeleteAll(mGroupsByName);
    mGroupsByName.clear();
}

void QGpgMECryptoConfigComponent::runGpgConf()
{
    const QString gpgconf = QGpgMECryptoConfig::gpgConfPath();
    if (gpgconf.isEmpty()) {
        qCWarning(GPGPME_BACKEND_LOG) << "Can't get path to gpgconf executable...";
        return;
    }

    // Run gpgconf --list-options <component>, and create all groups and entries for that component
    KProcess proc;
    proc << gpgconf;
    proc << QStringLiteral("--list-options");
    proc << mName;

    //qCDebug(GPGPME_BACKEND_LOG) <<"Running gpgconf --list-options" << mName;

    connect(&proc, &KProcess::readyReadStandardOutput, this, &QGpgMECryptoConfigComponent::slotCollectStdOut);
    mCurrentGroup = 0;

    // run the process:
    int rc = 0;
    proc.setOutputChannelMode(KProcess::OnlyStdoutChannel);
    proc.start();
    if (!proc.waitForFinished()) {
        rc = -2;
    } else if (proc.exitStatus() == QProcess::NormalExit) {
        rc = proc.exitCode();
    } else {
        rc = -1;
    }

    if (rc != 0) { // can happen when using the wrong version of gpg...
        qCWarning(GPGPME_BACKEND_LOG) << "Running 'gpgconf --list-options" << mName << "' failed." << strerror(rc) << ", but try that command to see the real output";
    } else {
        if (mCurrentGroup && !mCurrentGroup->mEntriesNaturalOrder.empty()) {   // only add non-empty groups
            mGroupsByName.insert(mCurrentGroupName, mCurrentGroup);
            mGroupsNaturalOrder.push_back(std::make_pair(mCurrentGroupName, mCurrentGroup));
        }
    }
}

void QGpgMECryptoConfigComponent::slotCollectStdOut()
{
    assert(qobject_cast<KProcess *>(QObject::sender()));
    KProcess *const proc = static_cast<KProcess *>(QObject::sender());
    while (proc->canReadLine()) {
        QString line = QString::fromUtf8(proc->readLine());
        if (line.endsWith(QLatin1Char('\n'))) {
            line.chop(1);
        }
        if (line.endsWith(QLatin1Char('\r'))) {
            line.chop(1);
        }
        //qCDebug(GPGPME_BACKEND_LOG) <<"GOT LINE:" << line;
        // Format: NAME:FLAGS:LEVEL:DESCRIPTION:TYPE:ALT-TYPE:ARGNAME:DEFAULT:ARGDEF:VALUE
        const QStringList lst = line.split(QLatin1Char(':'));
        if (lst.count() >= 10) {
            const int flags = lst[1].toInt();
            const int level = lst[2].toInt();
            if (level > 2) { // invisible or internal -> skip it;
                continue;
            }
            if (flags & GPGCONF_FLAG_GROUP) {
                if (mCurrentGroup && !mCurrentGroup->mEntriesNaturalOrder.empty()) {   // only add non-empty groups
                    mGroupsByName.insert(mCurrentGroupName, mCurrentGroup);
                    mGroupsNaturalOrder.push_back(std::make_pair(mCurrentGroupName, mCurrentGroup));
                }
                //else
                //  qCDebug(GPGPME_BACKEND_LOG) <<"Discarding empty group" << mCurrentGroupName;
                mCurrentGroup = new QGpgMECryptoConfigGroup(this, lst[0], lst[3], level);
                mCurrentGroupName = lst[0];
            } else {
                // normal entry
                if (!mCurrentGroup) {    // first toplevel entry -> create toplevel group
                    mCurrentGroup = new QGpgMECryptoConfigGroup(this, QStringLiteral("<nogroup>"), QString(), 0);
                    mCurrentGroupName = QStringLiteral("<nogroup>");
                }
                const QString &name = lst[0];
                QGpgMECryptoConfigEntry *value = new QGpgMECryptoConfigEntry(mCurrentGroup, lst);
                mCurrentGroup->mEntriesByName.insert(name, value);
                mCurrentGroup->mEntriesNaturalOrder.push_back(std::make_pair(name, value));
            }
        } else {
            // This happens on lines like
            // dirmngr[31465]: error opening `/home/dfaure/.gnupg/dirmngr_ldapservers.conf': No such file or directory
            // so let's not bother the user with it.
            //qCWarning(GPGPME_BACKEND_LOG) <<"Parse error on gpgconf --list-options output:" << line;
        }
    }
}

QStringList QGpgMECryptoConfigComponent::groupList() const
{
    QStringList result;
    std::transform(mGroupsNaturalOrder.begin(), mGroupsNaturalOrder.end(),
                   std::back_inserter(result), Select1St());
    return result;
}

QGpgME::CryptoConfigGroup *QGpgMECryptoConfigComponent::group(const QString &name) const
{
    return mGroupsByName.value(name);
}

void QGpgMECryptoConfigComponent::sync(bool runtime)
{
    QTemporaryFile tmpFile;
    tmpFile.open();

    QList<QGpgMECryptoConfigEntry *> dirtyEntries;

    // Collect all dirty entries
    const QList<QString> keylist = mGroupsByName.uniqueKeys();
    Q_FOREACH (const QString &key, keylist) {
        const QHash<QString, QGpgMECryptoConfigEntry *> entry = mGroupsByName[key]->mEntriesByName;
        const QList<QString> keylistentry = entry.uniqueKeys();
        Q_FOREACH (const QString &keyentry, keylistentry) {
            if (entry[keyentry]->isDirty()) {
                // OK, we can set it.currentKey() to it.current()->outputString()
                QString line = keyentry;
                if (entry[keyentry]->isSet()) {   // set option
                    line += QLatin1String(":0:");
                    line += entry[keyentry]->outputString();
                } else {                       // unset option
                    line += QLatin1String(":16:");
                }
#ifdef Q_OS_WIN
                line += QLatin1Char('\r');
#endif
                line += QLatin1Char('\n');
                const QByteArray line8bit = line.toUtf8(); // encode with utf8, and K3ProcIO uses utf8 when reading.
                tmpFile.write(line8bit);
                dirtyEntries.append(entry[keyentry]);

            }
        }
    }

    tmpFile.flush();
    if (dirtyEntries.isEmpty()) {
        return;
    }

    // Call gpgconf --change-options <component>
    const QString gpgconf = QGpgMECryptoConfig::gpgConfPath();
    QString commandLine = gpgconf.isEmpty()
                          ? QStringLiteral("gpgconf")
                          : KShell::quoteArg(gpgconf);
    if (runtime) {
        commandLine += QLatin1String(" --runtime");
    }
    commandLine += QLatin1String(" --change-options ");
    commandLine += KShell::quoteArg(mName);
    commandLine += QLatin1String(" < ");
    commandLine += KShell::quoteArg(tmpFile.fileName());

    //qCDebug(GPGPME_BACKEND_LOG) << commandLine;
    //system( QCString( "cat " ) + tmpFile.name().toLatin1() ); // DEBUG

    KProcess proc;
    proc.setShellCommand(commandLine);

    // run the process:
    int rc = proc.execute();

    if (rc == -2) {
        QString wmsg = i18n("Could not start gpgconf.\nCheck that gpgconf is in the PATH and that it can be started.");
        qCWarning(GPGPME_BACKEND_LOG) << wmsg;
        KMessageBox::error(0, wmsg);
    } else if (rc != 0) { // Happens due to bugs in gpgconf (e.g. issues 104/115)
        QString wmsg = i18n("Error from gpgconf while saving configuration: %1", QString::fromLocal8Bit(strerror(rc)));
        qCWarning(GPGPME_BACKEND_LOG) << ":" << strerror(rc);
        KMessageBox::error(0, wmsg);
    } else {
        QList<QGpgMECryptoConfigEntry *>::const_iterator it = dirtyEntries.constBegin();
        for (; it != dirtyEntries.constEnd(); ++it) {
            (*it)->setDirty(false);
        }
    }
}

////

QGpgMECryptoConfigGroup::QGpgMECryptoConfigGroup(QGpgMECryptoConfigComponent *comp, const QString &name, const QString &description, int level)
    :
    mComponent(comp),
    mName(name),
    mDescription(description),
    mLevel(static_cast<QGpgME::CryptoConfigEntry::Level>(level))
{
}

QGpgMECryptoConfigGroup::~QGpgMECryptoConfigGroup()
{
    mEntriesNaturalOrder.clear();
    qDeleteAll(mEntriesByName);
    mEntriesByName.clear();
}

QStringList QGpgMECryptoConfigGroup::entryList() const
{
    QStringList result;
    std::transform(mEntriesNaturalOrder.begin(), mEntriesNaturalOrder.end(),
                   std::back_inserter(result), Select1St());
    return result;
}

QGpgME::CryptoConfigEntry *QGpgMECryptoConfigGroup::entry(const QString &name) const
{
    return mEntriesByName.value(name);
}

////

static QString gpgconf_unescape(const QString &str, bool handleComma = true)
{
    /* See gpgconf_escape */
    QString dec(str);
    dec.replace(QStringLiteral("%25"), QStringLiteral("%"));
    dec.replace(QStringLiteral("%3a"), QStringLiteral(":"));
    if (handleComma) {
        dec.replace(QStringLiteral("%2c"), QStringLiteral(","));
    }
    return dec;
}

static QString gpgconf_escape(const QString &str, bool handleComma = true)
{
    /* Gpgconf does not really percent encode. It just
     * encodes , % and : characters. It expects all other
     * chars to be UTF-8 encoded.
     * Except in the Base-DN part where a , may not be percent
     * escaped.
     */
    QString esc(str);
    esc.replace(QLatin1Char('%'), QStringLiteral("%25"));
    esc.replace(QLatin1Char(':'), QStringLiteral("%3a"));
    if (handleComma) {
        esc.replace(QLatin1Char(','), QStringLiteral("%2c"));
    }
    return esc;
}

static QString urlpart_escape(const QString &str)
{
    /* We need to double escape here, as a username or password
     * or an LDAP Base-DN may contain : or , and in that
     * case we would break gpgconf's format if we only escaped
     * the : once. As an escaped : is used internaly to split
     * the parts of an url. */

    return gpgconf_escape(gpgconf_escape(str, false), false);
}

static QString urlpart_unescape(const QString &str)
{
    /* See urlpart_escape */
    return gpgconf_unescape(gpgconf_unescape(str, false), false);
}

// gpgconf arg type number -> CryptoConfigEntry arg type enum mapping
static QGpgME::CryptoConfigEntry::ArgType knownArgType(int argType, bool &ok)
{
    ok = true;
    switch (argType) {
    case 0: // none
        return QGpgME::CryptoConfigEntry::ArgType_None;
    case 1: // string
        return QGpgME::CryptoConfigEntry::ArgType_String;
    case 2: // int32
        return QGpgME::CryptoConfigEntry::ArgType_Int;
    case 3: // uint32
        return QGpgME::CryptoConfigEntry::ArgType_UInt;
    case 32: // pathname
        return QGpgME::CryptoConfigEntry::ArgType_Path;
    case 33: // ldap server
        return QGpgME::CryptoConfigEntry::ArgType_LDAPURL;
    default:
        ok = false;
        return QGpgME::CryptoConfigEntry::ArgType_None;
    }
}

QGpgMECryptoConfigEntry::QGpgMECryptoConfigEntry(QGpgMECryptoConfigGroup *group, const QStringList &parsedLine)
    : mGroup(group)
{
    // Format: NAME:FLAGS:LEVEL:DESCRIPTION:TYPE:ALT-TYPE:ARGNAME:DEFAULT:ARGDEF:VALUE
    assert(parsedLine.count() >= 10);   // called checked for it already
    QStringList::const_iterator it = parsedLine.constBegin();
    mName = *it++;
    mFlags = (*it++).toInt();
    mLevel = (*it++).toInt();
    mDescription = *it++;
    bool ok;
    // we keep the real (int) arg type, since it influences the parsing (e.g. for ldap urls)
    mRealArgType = (*it++).toInt();
    mArgType = knownArgType(mRealArgType, ok);
    if (!ok && !(*it).isEmpty()) {
        // use ALT-TYPE
        mRealArgType = (*it).toInt();
        mArgType = knownArgType(mRealArgType, ok);
    }
    if (!ok) {
        qCWarning(GPGPME_BACKEND_LOG) << "Unsupported datatype:" << parsedLine[4] << " :" << *it << " for" << parsedLine[0];
    }
    ++it; // done with alt-type
    ++it; // skip argname (not useful in GUIs)

    mSet = false;
    QString value;
    if (mFlags & GPGCONF_FLAG_DEFAULT) {
        value = *it; // get default value
        mDefaultValue = stringToValue(value, true);
    }
    ++it; // done with DEFAULT
    ++it; // ### skip ARGDEF for now. It's only for options with an "optional arg"
    //qCDebug(GPGPME_BACKEND_LOG) <<"Entry" << parsedLine[0] <<" val=" << *it;

    if (!(*it).isEmpty()) {    // a real value was set
        mSet = true;
        value = *it;
        mValue = stringToValue(value, true);
    } else {
        mValue = mDefaultValue;
    }

    mDirty = false;
}

QVariant QGpgMECryptoConfigEntry::stringToValue(const QString &str, bool unescape) const
{
    const bool isString = isStringType();

    if (isList()) {
        if (argType() == ArgType_None) {
            bool ok = true;
            const QVariant v = str.isEmpty() ? 0U : str.toUInt(&ok);
            if (!ok) {
                qCWarning(GPGPME_BACKEND_LOG) << "list-of-none should have an unsigned int as value:" << str;
            }
            return v;
        }
        QList<QVariant> lst;
        QStringList items = str.split(QLatin1Char(','), QString::SkipEmptyParts);
        for (QStringList::const_iterator valit = items.constBegin(); valit != items.constEnd(); ++valit) {
            QString val = *valit;
            if (isString) {
                if (val.isEmpty()) {
                    lst << QVariant(QString());
                    continue;
                } else if (unescape) {
                    if (val[0] != QLatin1Char('"')) { // see README.gpgconf
                        qCWarning(GPGPME_BACKEND_LOG) << "String value should start with '\"' :" << val;
                    }
                    val = val.mid(1);
                }
            }
            lst << QVariant(unescape ? gpgconf_unescape(val) : val);
        }
        return lst;
    } else { // not a list
        QString val(str);
        if (isString) {
            if (val.isEmpty()) {
                return QVariant(QString());    // not set  [ok with lists too?]
            } else if (unescape) {
                if (val[0] != QLatin1Char('"')) { // see README.gpgconf
                    qCWarning(GPGPME_BACKEND_LOG) << "String value should start with '\"' :" << val;
                }
                val = val.mid(1);
            }
        }
        return QVariant(unescape ? gpgconf_unescape(val) : val);
    }
}

QGpgMECryptoConfigEntry::~QGpgMECryptoConfigEntry()
{
#ifndef NDEBUG
    if (!s_duringClear && mDirty)
        qCWarning(GPGPME_BACKEND_LOG) << "Deleting a QGpgMECryptoConfigEntry that was modified (" << mDescription << ")"
                                      << "You forgot to call sync() (to commit) or clear() (to discard)";
#endif
}

bool QGpgMECryptoConfigEntry::isOptional() const
{
    return mFlags & GPGCONF_FLAG_OPTIONAL;
}

bool QGpgMECryptoConfigEntry::isReadOnly() const
{
    return mFlags & GPGCONF_FLAG_NO_CHANGE;
}

bool QGpgMECryptoConfigEntry::isList() const
{
    return mFlags & GPGCONF_FLAG_LIST;
}

bool QGpgMECryptoConfigEntry::isRuntime() const
{
    return mFlags & GPGCONF_FLAG_RUNTIME;
}

bool QGpgMECryptoConfigEntry::isSet() const
{
    return mSet;
}

bool QGpgMECryptoConfigEntry::boolValue() const
{
    Q_ASSERT(mArgType == ArgType_None);
    Q_ASSERT(!isList());
    return mValue.toBool();
}

QString QGpgMECryptoConfigEntry::stringValue() const
{
    return toString(false);
}

int QGpgMECryptoConfigEntry::intValue() const
{
    Q_ASSERT(mArgType == ArgType_Int);
    Q_ASSERT(!isList());
    return mValue.toInt();
}

unsigned int QGpgMECryptoConfigEntry::uintValue() const
{
    Q_ASSERT(mArgType == ArgType_UInt);
    Q_ASSERT(!isList());
    return mValue.toUInt();
}

static QUrl parseURL(int mRealArgType, const QString &str)
{
    if (mRealArgType == 33) {   // LDAP server
        // The format is HOSTNAME:PORT:USERNAME:PASSWORD:BASE_DN
        QStringList items = str.split(QLatin1Char(':'));
        if (items.count() == 5) {
            QStringList::const_iterator it = items.constBegin();
            QUrl url;
            url.setScheme(QStringLiteral("ldap"));
            url.setHost(gpgconf_unescape(*it++));

            bool ok;
            const int port = (*it++).toInt(&ok);
            if (ok) {
                url.setPort(port);
            } else if (!it->isEmpty()) {
                qCWarning(GPGPME_BACKEND_LOG) << "parseURL: malformed LDAP server port, ignoring: \"" << *it << "\"";
            }

            const QString userName = urlpart_unescape(*it++);
            if (!userName.isEmpty()) {
                url.setUserName(userName);
            }
            const QString passWord = urlpart_unescape(*it++);
            if (!passWord.isEmpty()) {
                url.setPassword(passWord);
            }
            url.setQuery(urlpart_unescape(*it));
            return url;
        } else {
            qCWarning(GPGPME_BACKEND_LOG) << "parseURL: malformed LDAP server:" << str;
        }
    }
    // other URLs : assume wellformed URL syntax.
    return QUrl(str);
}

// The opposite of parseURL
static QString splitURL(int mRealArgType, const QUrl &url)
{
    if (mRealArgType == 33) {   // LDAP server
        // The format is HOSTNAME:PORT:USERNAME:PASSWORD:BASE_DN
        Q_ASSERT(url.scheme() == QLatin1String("ldap"));
        return gpgconf_escape(url.host()) + QLatin1Char(':') +
               (url.port() != -1 ? QString::number(url.port()) : QString()) + QLatin1Char(':') +     // -1 is used for default ports, omit
               urlpart_escape(url.userName()) + QLatin1Char(':') +
               urlpart_escape(url.password()) + QLatin1Char(':') +
               urlpart_escape(url.query());
    }
    return url.path();
}

QUrl QGpgMECryptoConfigEntry::urlValue() const
{
    Q_ASSERT(mArgType == ArgType_Path || mArgType == ArgType_LDAPURL);
    Q_ASSERT(!isList());
    QString str = mValue.toString();
    if (mArgType == ArgType_Path) {
        QUrl url = QUrl::fromUserInput(str, QString(), QUrl::AssumeLocalFile);
        return url;
    }
    return parseURL(mRealArgType, str);
}

unsigned int QGpgMECryptoConfigEntry::numberOfTimesSet() const
{
    Q_ASSERT(mArgType == ArgType_None);
    Q_ASSERT(isList());
    return mValue.toUInt();
}

std::vector<int> QGpgMECryptoConfigEntry::intValueList() const
{
    Q_ASSERT(mArgType == ArgType_Int);
    Q_ASSERT(isList());
    std::vector<int> ret;
    QList<QVariant> lst = mValue.toList();
    ret.reserve(lst.size());
    for (QList<QVariant>::const_iterator it = lst.constBegin(); it != lst.constEnd(); ++it) {
        ret.push_back((*it).toInt());
    }
    return ret;
}

std::vector<unsigned int> QGpgMECryptoConfigEntry::uintValueList() const
{
    Q_ASSERT(mArgType == ArgType_UInt);
    Q_ASSERT(isList());
    std::vector<unsigned int> ret;
    QList<QVariant> lst = mValue.toList();
    ret.reserve(lst.size());
    for (QList<QVariant>::const_iterator it = lst.constBegin(); it != lst.constEnd(); ++it) {
        ret.push_back((*it).toUInt());
    }
    return ret;
}

QList<QUrl> QGpgMECryptoConfigEntry::urlValueList() const
{
    Q_ASSERT(mArgType == ArgType_Path || mArgType == ArgType_LDAPURL);
    Q_ASSERT(isList());
    QStringList lst = mValue.toStringList();

    QList<QUrl> ret;
    for (QStringList::const_iterator it = lst.constBegin(); it != lst.constEnd(); ++it) {
        if (mArgType == ArgType_Path) {
            QUrl url = QUrl::fromUserInput(*it, QString(), QUrl::AssumeLocalFile);
        } else {
            ret << parseURL(mRealArgType, *it);
        }
    }
    return ret;
}

void QGpgMECryptoConfigEntry::resetToDefault()
{
    mSet = false;
    mDirty = true;
    if (mFlags & GPGCONF_FLAG_DEFAULT) {
        mValue = mDefaultValue;
    } else if (mArgType == ArgType_None) {
        if (isList()) {
            mValue = 0U;
        } else {
            mValue = false;
        }
    }
}

void QGpgMECryptoConfigEntry::setBoolValue(bool b)
{
    Q_ASSERT(mArgType == ArgType_None);
    Q_ASSERT(!isList());
    // A "no arg" option is either set or not set.
    // Being set means mSet==true + mValue==true, being unset means resetToDefault(), i.e. both false
    mValue = b;
    mSet = b;
    mDirty = true;
}

void QGpgMECryptoConfigEntry::setStringValue(const QString &str)
{
    mValue = stringToValue(str, false);
    // When setting a string to empty (and there's no default), we need to act like resetToDefault
    // Otherwise we try e.g. "ocsp-responder:0:" and gpgconf answers:
    // "gpgconf: argument required for option ocsp-responder"
    if (str.isEmpty() && !isOptional()) {
        mSet = false;
    } else {
        mSet = true;
    }
    mDirty = true;
}

void QGpgMECryptoConfigEntry::setIntValue(int i)
{
    Q_ASSERT(mArgType == ArgType_Int);
    Q_ASSERT(!isList());
    mValue = i;
    mSet = true;
    mDirty = true;
}

void QGpgMECryptoConfigEntry::setUIntValue(unsigned int i)
{
    mValue = i;
    mSet = true;
    mDirty = true;
}

void QGpgMECryptoConfigEntry::setURLValue(const QUrl &url)
{
    QString str = splitURL(mRealArgType, url);
    if (str.isEmpty() && !isOptional()) {
        mSet = false;
    } else {
        mSet = true;
    }
    mValue = str;
    mDirty = true;
}

void QGpgMECryptoConfigEntry::setNumberOfTimesSet(unsigned int i)
{
    Q_ASSERT(mArgType == ArgType_None);
    Q_ASSERT(isList());
    mValue = i;
    mSet = i > 0;
    mDirty = true;
}

void QGpgMECryptoConfigEntry::setIntValueList(const std::vector<int> &lst)
{
    QList<QVariant> ret;
    for (std::vector<int>::const_iterator it = lst.begin(); it != lst.end(); ++it) {
        ret << QVariant(*it);
    }
    mValue = ret;
    if (ret.isEmpty() && !isOptional()) {
        mSet = false;
    } else {
        mSet = true;
    }
    mDirty = true;
}

void QGpgMECryptoConfigEntry::setUIntValueList(const std::vector<unsigned int> &lst)
{
    QList<QVariant> ret;
    for (std::vector<unsigned int>::const_iterator it = lst.begin(); it != lst.end(); ++it) {
        ret << QVariant(*it);
    }
    if (ret.isEmpty() && !isOptional()) {
        mSet = false;
    } else {
        mSet = true;
    }
    mValue = ret;
    mDirty = true;
}

void QGpgMECryptoConfigEntry::setURLValueList(const QList<QUrl> &urls)
{
    QStringList lst;
    for (QList<QUrl>::const_iterator it = urls.constBegin(); it != urls.constEnd(); ++it) {
        lst << splitURL(mRealArgType, *it);
    }
    mValue = lst;
    if (lst.isEmpty() && !isOptional()) {
        mSet = false;
    } else {
        mSet = true;
    }
    mDirty = true;
}

QString QGpgMECryptoConfigEntry::toString(bool escape) const
{
    // Basically the opposite of stringToValue
    if (isStringType()) {
        if (mValue.isNull()) {
            return QString();
        } else if (isList()) { // string list
            QStringList lst = mValue.toStringList();
            if (escape) {
                for (QStringList::iterator it = lst.begin(); it != lst.end(); ++it) {
                    if (!(*it).isNull()) {
                        *it = gpgconf_escape(*it).prepend(QLatin1String("\""));
                    }
                }
            }
            const QString res = lst.join(QStringLiteral(","));
            //qCDebug(GPGPME_BACKEND_LOG) <<"toString:" << res;
            return res;
        } else { // normal string
            QString res = mValue.toString();
            if (escape) {
                res = gpgconf_escape(res).prepend(QLatin1String("\""));
            }
            return res;
        }
    }
    if (!isList()) { // non-list non-string
        if (mArgType == ArgType_None) {
            return mValue.toBool() ? QStringLiteral("1") : QString();
        } else { // some int
            Q_ASSERT(mArgType == ArgType_Int || mArgType == ArgType_UInt);
            return mValue.toString(); // int to string conversion
        }
    }

    // Lists (of other types than strings)
    if (mArgType == ArgType_None) {
        return QString::number(numberOfTimesSet());
    }

    QStringList ret;
    QList<QVariant> lst = mValue.toList();
    for (QList<QVariant>::const_iterator it = lst.constBegin(); it != lst.constEnd(); ++it) {
        ret << (*it).toString(); // QVariant does the conversion
    }
    return ret.join(QStringLiteral(","));
}

QString QGpgMECryptoConfigEntry::outputString() const
{
    Q_ASSERT(mSet);
    return toString(true);
}

bool QGpgMECryptoConfigEntry::isStringType() const
{
    return (mArgType == QGpgME::CryptoConfigEntry::ArgType_String
            || mArgType == QGpgME::CryptoConfigEntry::ArgType_Path
            || mArgType == QGpgME::CryptoConfigEntry::ArgType_LDAPURL);
}

void QGpgMECryptoConfigEntry::setDirty(bool b)
{
    mDirty = b;
}
