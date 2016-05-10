/*
    qgpgmenewcryptoconfig.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2010 Klarälvdalens Datakonsult AB
    Copyright (c) 2016 Intevation GmbH

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

#include "qgpgmenewcryptoconfig.h"

#include <QDebug>
#include "gpgme_backend_debug.h"

#include <QFile>

#include "global.h"
#include "error.h"


#include <sstream>
#include <string>
#include <cassert>

using namespace QGpgME;
using namespace GpgME;
using namespace GpgME::Configuration;

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

// Just for the Q_ASSERT in the dtor. Not thread-safe, but who would
// have 2 threads talking to gpgconf anyway? :)
static bool s_duringClear = false;

QGpgMENewCryptoConfig::QGpgMENewCryptoConfig()
    :  m_parsed(false)
{
}

QGpgMENewCryptoConfig::~QGpgMENewCryptoConfig()
{
    clear();
}

void QGpgMENewCryptoConfig::reloadConfiguration(bool showErrors)
{
    clear();

    Error error;
    const std::vector<Component> components = Component::load(error);
#ifndef NDEBUG
    {
        std::stringstream ss;
        ss << "error: " << error
           << "components:\n";
        std::copy(components.begin(), components.end(),
                  std::ostream_iterator<Component>(ss, "\n"));
        qCDebug(GPGPME_BACKEND_LOG) << ss.str().c_str();
    }
#endif
#if 0
    TODO port?
    if (error && showErrors) {
        const QString wmsg = i18n("<qt>Failed to execute gpgconf:<p>%1</p></qt>", QString::fromLocal8Bit(error.asString()));
        qCWarning(GPGPME_BACKEND_LOG) << wmsg; // to see it from test_cryptoconfig.cpp
        KMessageBox::error(0, wmsg);
    }
#endif
    Q_FOREACH(const Component & c, components) {
        const std::shared_ptr<QGpgMENewCryptoConfigComponent> comp(new QGpgMENewCryptoConfigComponent);
        comp->setComponent(c);
        m_componentsByName[ comp->name() ] = comp;
    }
    m_parsed = true;
}

QStringList QGpgMENewCryptoConfig::componentList() const
{
    if (!m_parsed) {
        const_cast<QGpgMENewCryptoConfig *>(this)->reloadConfiguration(true);
    }
    QStringList result;
    std::transform(m_componentsByName.begin(), m_componentsByName.end(),
                   std::back_inserter(result),
                   mem_fn(&QGpgMENewCryptoConfigComponent::name));
    return result;
}

QGpgMENewCryptoConfigComponent *QGpgMENewCryptoConfig::component(const QString &name) const
{
    if (!m_parsed) {
        const_cast<QGpgMENewCryptoConfig *>(this)->reloadConfiguration(false);
    }
    return m_componentsByName.value(name).get();
}

void QGpgMENewCryptoConfig::sync(bool runtime)
{
    Q_FOREACH(const std::shared_ptr<QGpgMENewCryptoConfigComponent> &c, m_componentsByName)
    c->sync(runtime);
}

void QGpgMENewCryptoConfig::clear()
{
    s_duringClear = true;
    m_componentsByName.clear();
    s_duringClear = false;
    m_parsed = false; // next call to componentList/component will need to run gpgconf again
}

////

QGpgMENewCryptoConfigComponent::QGpgMENewCryptoConfigComponent()
    : CryptoConfigComponent(),
      m_component()
{

}

void QGpgMENewCryptoConfigComponent::setComponent(const Component &component)
{
    m_component = component;
    m_groupsByName.clear();

    std::shared_ptr<QGpgMENewCryptoConfigGroup> group;

    const std::vector<Option> options = m_component.options();
    Q_FOREACH(const Option & o, options)
    if (o.flags() & Group) {
        if (group) {
            m_groupsByName[group->name()] = group;
        }
        group.reset(new QGpgMENewCryptoConfigGroup(shared_from_this(), o));
    } else if (group) {
        const std::shared_ptr<QGpgMENewCryptoConfigEntry> entry(new QGpgMENewCryptoConfigEntry(group, o));
        const QString name = entry->name();
        group->m_entryNames.push_back(name);
        group->m_entriesByName[name] = entry;
    } else {
        qCWarning(GPGPME_BACKEND_LOG) << "found no group for entry" << o.name() << "of component" << name();
    }
    if (group) {
        m_groupsByName[group->name()] = group;
    }

}

QGpgMENewCryptoConfigComponent::~QGpgMENewCryptoConfigComponent() {}

QString QGpgMENewCryptoConfigComponent::name() const
{
    return QString::fromUtf8(m_component.name());
}

QString QGpgMENewCryptoConfigComponent::description() const
{
    return QString::fromUtf8(m_component.description());
}

QStringList QGpgMENewCryptoConfigComponent::groupList() const
{
    QStringList result;
    result.reserve(m_groupsByName.size());
    std::transform(m_groupsByName.begin(), m_groupsByName.end(),
                   std::back_inserter(result),
                   std::mem_fn(&QGpgMENewCryptoConfigGroup::name));
    return result;
}

QGpgMENewCryptoConfigGroup *QGpgMENewCryptoConfigComponent::group(const QString &name) const
{
    return m_groupsByName.value(name).get();
}

void QGpgMENewCryptoConfigComponent::sync(bool runtime)
{
    Q_UNUSED(runtime)
    // ### how to pass --runtime to gpgconf? -> marcus: not yet supported (2010-11-20)
    if (const Error err = m_component.save()) {
#if 0
        TODO port
        const QString wmsg = i18n("Error from gpgconf while saving configuration: %1", QString::fromLocal8Bit(err.asString()));
        qCWarning(GPGPME_BACKEND_LOG) << ":" << wmsg;
        KMessageBox::error(0, wmsg);
#endif
    }
    // ### unset dirty state again
}

////

QGpgMENewCryptoConfigGroup::QGpgMENewCryptoConfigGroup(const std::shared_ptr<QGpgMENewCryptoConfigComponent> &comp, const Option &option)
    : CryptoConfigGroup(),
      m_component(comp),
      m_option(option)
{
}

QGpgMENewCryptoConfigGroup::~QGpgMENewCryptoConfigGroup() {}

QString QGpgMENewCryptoConfigGroup::name() const
{
    return QString::fromUtf8(m_option.name());
}

QString QGpgMENewCryptoConfigGroup::description() const
{
    return QString::fromUtf8(m_option.description());
}

QString QGpgMENewCryptoConfigGroup::path() const
{
    if (const std::shared_ptr<QGpgMENewCryptoConfigComponent> c = m_component.lock()) {
        return c->name() + QLatin1Char('/') + name();
    } else {
        return QString();
    }
}

CryptoConfigEntry::Level QGpgMENewCryptoConfigGroup::level() const
{
    // two casts to make SunCC happy:
    return static_cast<CryptoConfigEntry::Level>(static_cast<unsigned int>(m_option.level()));
}

QStringList QGpgMENewCryptoConfigGroup::entryList() const
{
    return m_entryNames;
}

QGpgMENewCryptoConfigEntry *QGpgMENewCryptoConfigGroup::entry(const QString &name) const
{
    return m_entriesByName.value(name).get();
}

static QString urlpart_encode(const QString &str)
{
    QString enc(str);
    enc.replace(QLatin1Char('%'), QStringLiteral("%25"));   // first!
    enc.replace(QLatin1Char(':'), QStringLiteral("%3a"));
    //qCDebug(GPGPME_BACKEND_LOG) <<"  urlpart_encode:" << str <<" ->" << enc;
    return enc;
}

static QString urlpart_decode(const QString &str)
{
    return QUrl::fromPercentEncoding(str.toLatin1());
}

// gpgconf arg type number -> NewCryptoConfigEntry arg type enum mapping
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

QGpgMENewCryptoConfigEntry::QGpgMENewCryptoConfigEntry(const std::shared_ptr<QGpgMENewCryptoConfigGroup> &group, const Option &option)
    : m_group(group), m_option(option)
{
}

#if 0
QVariant QGpgMENewCryptoConfigEntry::stringToValue(const QString &str, bool unescape) const
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
        QStringList items = str.split(',', QString::SkipEmptyParts);
        for (QStringList::const_iterator valit = items.constBegin(); valit != items.constEnd(); ++valit) {
            QString val = *valit;
            if (isString) {
                if (val.isEmpty()) {
                    lst << QVariant(QString());
                    continue;
                } else if (unescape) {
                    if (val[0] != '"') { // see README.gpgconf
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
                if (val[0] != '"') { // see README.gpgconf
                    qCWarning(GPGPME_BACKEND_LOG) << "String value should start with '\"' :" << val;
                }
                val = val.mid(1);
            }
        }
        return QVariant(unescape ? gpgconf_unescape(val) : val);
    }
}
#endif

QGpgMENewCryptoConfigEntry::~QGpgMENewCryptoConfigEntry()
{
#ifndef NDEBUG
    if (!s_duringClear && m_option.dirty())
        qCWarning(GPGPME_BACKEND_LOG) << "Deleting a QGpgMENewCryptoConfigEntry that was modified (" << m_option.description() << ")"
                                      << "You forgot to call sync() (to commit) or clear() (to discard)";
#endif
}

QString QGpgMENewCryptoConfigEntry::name() const
{
    return QString::fromUtf8(m_option.name());
}

QString QGpgMENewCryptoConfigEntry::description() const
{
    return QString::fromUtf8(m_option.description());
}

QString QGpgMENewCryptoConfigEntry::path() const
{
    if (const std::shared_ptr<QGpgMENewCryptoConfigGroup> g = m_group.lock()) {
        return g->path() + QLatin1Char('/') + name();
    } else {
        return QString();
    }
}

bool QGpgMENewCryptoConfigEntry::isOptional() const
{
    return m_option.flags() & Optional;
}

bool QGpgMENewCryptoConfigEntry::isReadOnly() const
{
    return m_option.flags() & NoChange;
}

bool QGpgMENewCryptoConfigEntry::isList() const
{
    return m_option.flags() & List;
}

bool QGpgMENewCryptoConfigEntry::isRuntime() const
{
    return m_option.flags() & Runtime;
}

CryptoConfigEntry::Level QGpgMENewCryptoConfigEntry::level() const
{
    // two casts to make SunCC happy:
    return static_cast<Level>(static_cast<unsigned int>(m_option.level()));
}

CryptoConfigEntry::ArgType QGpgMENewCryptoConfigEntry::argType() const
{
    bool ok = false;
    const ArgType type = knownArgType(m_option.type(), ok);
    if (ok) {
        return type;
    } else {
        return knownArgType(m_option.alternateType(), ok);
    }
}

bool QGpgMENewCryptoConfigEntry::isSet() const
{
    return m_option.set();
}

bool QGpgMENewCryptoConfigEntry::boolValue() const
{
    Q_ASSERT(m_option.alternateType() == NoType);
    Q_ASSERT(!isList());
    return m_option.currentValue().boolValue();
}

QString QGpgMENewCryptoConfigEntry::stringValue() const
{
    //return toString( false );
    Q_ASSERT(m_option.alternateType() == StringType);
    Q_ASSERT(!isList());
    return QString::fromUtf8(m_option.currentValue().stringValue());
}

int QGpgMENewCryptoConfigEntry::intValue() const
{
    Q_ASSERT(m_option.alternateType() == IntegerType);
    Q_ASSERT(!isList());
    return m_option.currentValue().intValue();
}

unsigned int QGpgMENewCryptoConfigEntry::uintValue() const
{
    Q_ASSERT(m_option.alternateType() == UnsignedIntegerType);
    Q_ASSERT(!isList());
    return m_option.currentValue().uintValue();
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
            url.setHost(urlpart_decode(*it++));

            bool ok;
            const int port = (*it++).toInt(&ok);
            if (ok) {
                url.setPort(port);
            } else if (!it->isEmpty()) {
                qCWarning(GPGPME_BACKEND_LOG) << "parseURL: malformed LDAP server port, ignoring: \"" << *it << "\"";
            }

            const QString userName = urlpart_decode(*it++);
            if (!userName.isEmpty()) {
                url.setUserName(userName);
            }
            const QString passWord = urlpart_decode(*it++);
            if (!passWord.isEmpty()) {
                url.setPassword(passWord);
            }
            url.setQuery(urlpart_decode(*it));
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
        return urlpart_encode(url.host()) + QLatin1Char(':') +
               (url.port() != -1 ? QString::number(url.port()) : QString()) + QLatin1Char(':') +     // -1 is used for default ports, omit
               urlpart_encode(url.userName()) + QLatin1Char(':') +
               urlpart_encode(url.password()) + QLatin1Char(':') +
               urlpart_encode(url.query());
    }
    return url.path();
}

QUrl QGpgMENewCryptoConfigEntry::urlValue() const
{
    const Type type = m_option.type();
    Q_ASSERT(type == FilenameType || type == LdapServerType);
    Q_ASSERT(!isList());
    if (type == FilenameType) {
        QUrl url;
        url.setPath(QFile::decodeName(m_option.currentValue().stringValue()));
        return url;
    }
    return parseURL(type, stringValue());
}

unsigned int QGpgMENewCryptoConfigEntry::numberOfTimesSet() const
{
    Q_ASSERT(m_option.alternateType() == NoType);
    Q_ASSERT(isList());
    return m_option.currentValue().uintValue();
}

std::vector<int> QGpgMENewCryptoConfigEntry::intValueList() const
{
    Q_ASSERT(m_option.alternateType() == IntegerType);
    Q_ASSERT(isList());
    return m_option.currentValue().intValues();
}

std::vector<unsigned int> QGpgMENewCryptoConfigEntry::uintValueList() const
{
    Q_ASSERT(m_option.alternateType() == UnsignedIntegerType);
    Q_ASSERT(isList());
    return m_option.currentValue().uintValues();
}

QList<QUrl> QGpgMENewCryptoConfigEntry::urlValueList() const
{
    const Type type = m_option.type();
    Q_ASSERT(type == FilenameType || type == LdapServerType);
    Q_ASSERT(isList());
    const Argument arg = m_option.currentValue();
    const std::vector<const char *> values = arg.stringValues();
    QList<QUrl> ret;
    Q_FOREACH(const char *value, values)
    if (type == FilenameType) {
        QUrl url;
        url.setPath(QFile::decodeName(value));
        ret << url;
    } else {
        ret << parseURL(type, QString::fromUtf8(value));
    }
    return ret;
}

void QGpgMENewCryptoConfigEntry::resetToDefault()
{
    m_option.resetToDefaultValue();
}

void QGpgMENewCryptoConfigEntry::setBoolValue(bool b)
{
    Q_ASSERT(m_option.alternateType() == NoType);
    Q_ASSERT(!isList());
    // A "no arg" option is either set or not set.
    // Being set means createNoneArgument(), being unset means resetToDefault()
    m_option.setNewValue(m_option.createNoneArgument(b));
}

void QGpgMENewCryptoConfigEntry::setStringValue(const QString &str)
{
    Q_ASSERT(m_option.alternateType() == StringType);
    Q_ASSERT(!isList());
    const Type type = m_option.type();
    // When setting a string to empty (and there's no default), we need to act like resetToDefault
    // Otherwise we try e.g. "ocsp-responder:0:" and gpgconf answers:
    // "gpgconf: argument required for option ocsp-responder"
    if (str.isEmpty() && !isOptional()) {
        m_option.resetToDefaultValue();
    } else if (type == FilenameType) {
        m_option.setNewValue(m_option.createStringArgument(QFile::encodeName(str).constData()));
    } else {
        m_option.setNewValue(m_option.createStringArgument(str.toUtf8().constData()));
    }
}

void QGpgMENewCryptoConfigEntry::setIntValue(int i)
{
    Q_ASSERT(m_option.alternateType() == IntegerType);
    Q_ASSERT(!isList());
    m_option.setNewValue(m_option.createIntArgument(i));
}

void QGpgMENewCryptoConfigEntry::setUIntValue(unsigned int i)
{
    Q_ASSERT(m_option.alternateType() == UnsignedIntegerType);
    Q_ASSERT(!isList());
    m_option.setNewValue(m_option.createUIntArgument(i));
}

void QGpgMENewCryptoConfigEntry::setURLValue(const QUrl &url)
{
    const Type type = m_option.type();
    Q_ASSERT(type == FilenameType || type == LdapServerType);
    Q_ASSERT(!isList());
    const QString str = splitURL(type, url);
    // cf. setStringValue()
    if (str.isEmpty() && !isOptional()) {
        m_option.resetToDefaultValue();
    } else if (type == FilenameType) {
        m_option.setNewValue(m_option.createStringArgument(QFile::encodeName(str).constData()));
    } else {
        m_option.setNewValue(m_option.createStringArgument(str.toUtf8().constData()));
    }
}

void QGpgMENewCryptoConfigEntry::setNumberOfTimesSet(unsigned int i)
{
    Q_ASSERT(m_option.alternateType() == NoType);
    Q_ASSERT(isList());
    m_option.setNewValue(m_option.createNoneListArgument(i));
}

void QGpgMENewCryptoConfigEntry::setIntValueList(const std::vector<int> &lst)
{
    Q_ASSERT(m_option.alternateType() == IntegerType);
    Q_ASSERT(isList());
    m_option.setNewValue(m_option.createIntListArgument(lst));
}

void QGpgMENewCryptoConfigEntry::setUIntValueList(const std::vector<unsigned int> &lst)
{
    Q_ASSERT(m_option.alternateType() == UnsignedIntegerType);
    Q_ASSERT(isList());
    m_option.setNewValue(m_option.createUIntListArgument(lst));
}

void QGpgMENewCryptoConfigEntry::setURLValueList(const QList<QUrl> &urls)
{
    const Type type = m_option.type();
    Q_ASSERT(m_option.alternateType() == StringType);
    Q_ASSERT(isList());
    std::vector<std::string> values;
    values.reserve(urls.size());
    Q_FOREACH (const QUrl &url, urls)
        if (type == FilenameType) {
            values.push_back(QFile::encodeName(url.path()).constData());
        } else {
            values.push_back(splitURL(type, url).toUtf8().constData());
        }
    m_option.setNewValue(m_option.createStringListArgument(values));
}

bool QGpgMENewCryptoConfigEntry::isDirty() const
{
    return m_option.dirty();
}

#if 0
QString QGpgMENewCryptoConfigEntry::toString(bool escape) const
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
                        *it = gpgconf_escape(*it).prepend("\"");
                    }
                }
            }
            QString res = lst.join(",");
            //qCDebug(GPGPME_BACKEND_LOG) <<"toString:" << res;
            return res;
        } else { // normal string
            QString res = mValue.toString();
            if (escape) {
                res = gpgconf_escape(res).prepend("\"");
            }
            return res;
        }
    }
    if (!isList()) { // non-list non-string
        if (mArgType == ArgType_None) {
            return mValue.toBool() ? QString::fromLatin1("1") : QString();
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
    return ret.join(",");
}

QString QGpgMENewCryptoConfigEntry::outputString() const
{
    Q_ASSERT(mSet);
    return toString(true);
}

bool QGpgMENewCryptoConfigEntry::isStringType() const
{
    return (mArgType == QGpgME::NewCryptoConfigEntry::ArgType_String
            || mArgType == QGpgME::NewCryptoConfigEntry::ArgType_Path
            || mArgType == QGpgME::NewCryptoConfigEntry::ArgType_URL
            || mArgType == QGpgME::NewCryptoConfigEntry::ArgType_LDAPURL);
}

void QGpgMENewCryptoConfigEntry::setDirty(bool b)
{
    mDirty = b;
}
#endif
