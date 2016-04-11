/*
    qgpgmenewcryptoconfig.h

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2010 Klarälvdalens Datakonsult AB
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

#ifndef QGPGME_QGPGMENEWCRYPTOCONFIG_H
#define QGPGME_QGPGMENEWCRYPTOCONFIG_H

#include "qgpgme_export.h"
#include "cryptoconfig.h"

#include <QHash>
#include <QStringList>
#include <QVariant>

#ifdef BUILDING_QGPGME
# include "configuration.h"
#else
# include <gpgme++/configuration.h>
#endif


#include <vector>
#include <utility>

class QGpgMENewCryptoConfig;
class QGpgMENewCryptoConfigComponent;
class QGpgMENewCryptoConfigGroup;
class QGpgMENewCryptoConfigEntry;

class QGpgMENewCryptoConfigEntry : public QGpgME::CryptoConfigEntry
{
public:
    QGpgMENewCryptoConfigEntry(const std::shared_ptr<QGpgMENewCryptoConfigGroup> &group, const GpgME::Configuration::Option &option);
    ~QGpgMENewCryptoConfigEntry();

    QString name() const Q_DECL_OVERRIDE;
    QString description() const Q_DECL_OVERRIDE;
    QString path() const Q_DECL_OVERRIDE;
    bool isOptional() const Q_DECL_OVERRIDE;
    bool isReadOnly() const Q_DECL_OVERRIDE;
    bool isList() const Q_DECL_OVERRIDE;
    bool isRuntime() const Q_DECL_OVERRIDE;
    Level level() const Q_DECL_OVERRIDE;
    ArgType argType() const Q_DECL_OVERRIDE;
    bool isSet() const Q_DECL_OVERRIDE;
    bool boolValue() const Q_DECL_OVERRIDE;
    QString stringValue() const Q_DECL_OVERRIDE;
    int intValue() const Q_DECL_OVERRIDE;
    unsigned int uintValue() const Q_DECL_OVERRIDE;
    QUrl urlValue() const Q_DECL_OVERRIDE;
    unsigned int numberOfTimesSet() const Q_DECL_OVERRIDE;
    std::vector<int> intValueList() const Q_DECL_OVERRIDE;
    std::vector<unsigned int> uintValueList() const Q_DECL_OVERRIDE;
    QList<QUrl> urlValueList() const Q_DECL_OVERRIDE;
    void resetToDefault() Q_DECL_OVERRIDE;
    void setBoolValue(bool) Q_DECL_OVERRIDE;
    void setStringValue(const QString &) Q_DECL_OVERRIDE;
    void setIntValue(int) Q_DECL_OVERRIDE;
    void setUIntValue(unsigned int) Q_DECL_OVERRIDE;
    void setURLValue(const QUrl &) Q_DECL_OVERRIDE;
    void setNumberOfTimesSet(unsigned int) Q_DECL_OVERRIDE;
    void setIntValueList(const std::vector<int> &) Q_DECL_OVERRIDE;
    void setUIntValueList(const std::vector<unsigned int> &) Q_DECL_OVERRIDE;
    void setURLValueList(const QList<QUrl> &) Q_DECL_OVERRIDE;
    bool isDirty() const Q_DECL_OVERRIDE;

#if 0
    void setDirty(bool b);
    QString outputString() const;

protected:
    bool isStringType() const;
    QVariant stringToValue(const QString &value, bool unescape) const;
    QString toString(bool escape) const;
#endif
private:
    std::weak_ptr<QGpgMENewCryptoConfigGroup> m_group;
    GpgME::Configuration::Option m_option;
};

class QGpgMENewCryptoConfigGroup : public QGpgME::CryptoConfigGroup
{
public:
    QGpgMENewCryptoConfigGroup(const std::shared_ptr<QGpgMENewCryptoConfigComponent> &parent, const GpgME::Configuration::Option &option);
    ~QGpgMENewCryptoConfigGroup();

    QString name() const Q_DECL_OVERRIDE;
    QString iconName() const Q_DECL_OVERRIDE
    {
        return QString();
    }
    QString description() const Q_DECL_OVERRIDE;
    QString path() const Q_DECL_OVERRIDE;
    QGpgME::CryptoConfigEntry::Level level() const Q_DECL_OVERRIDE;
    QStringList entryList() const Q_DECL_OVERRIDE;
    QGpgMENewCryptoConfigEntry *entry(const QString &name) const Q_DECL_OVERRIDE;

private:
    friend class QGpgMENewCryptoConfigComponent; // it adds the entries
    std::weak_ptr<QGpgMENewCryptoConfigComponent> m_component;
    GpgME::Configuration::Option m_option;
    QStringList m_entryNames;
    QHash< QString, std::shared_ptr<QGpgMENewCryptoConfigEntry> > m_entriesByName;
};

/// For docu, see kleo/cryptoconfig.h
class QGpgMENewCryptoConfigComponent : public QGpgME::CryptoConfigComponent, public std::enable_shared_from_this<QGpgMENewCryptoConfigComponent>
{
public:
    QGpgMENewCryptoConfigComponent();
    ~QGpgMENewCryptoConfigComponent();

    void setComponent(const GpgME::Configuration::Component &component);

    QString name() const Q_DECL_OVERRIDE;
    QString iconName() const Q_DECL_OVERRIDE
    {
        return name();
    }
    QString description() const Q_DECL_OVERRIDE;
    QStringList groupList() const Q_DECL_OVERRIDE;
    QGpgMENewCryptoConfigGroup *group(const QString &name) const Q_DECL_OVERRIDE;

    void sync(bool runtime);

private:
    GpgME::Configuration::Component m_component;
    QHash< QString, std::shared_ptr<QGpgMENewCryptoConfigGroup> > m_groupsByName;
};

/**
 * CryptoConfig implementation around the gpgconf command-line tool
 * For method docu, see kleo/cryptoconfig.h
 */
class QGPGME_EXPORT QGpgMENewCryptoConfig : public QGpgME::CryptoConfig
{
public:
    /**
     * Constructor
     */
    QGpgMENewCryptoConfig();
    ~QGpgMENewCryptoConfig();

    QStringList componentList() const Q_DECL_OVERRIDE;

    QGpgMENewCryptoConfigComponent *component(const QString &name) const Q_DECL_OVERRIDE;

    void clear() Q_DECL_OVERRIDE;
    void sync(bool runtime) Q_DECL_OVERRIDE;

private:
    /// @param showErrors if true, a messagebox will be shown if e.g. gpgconf wasn't found
    void reloadConfiguration(bool showErrors);

private:
    QHash< QString, std::shared_ptr<QGpgMENewCryptoConfigComponent> > m_componentsByName;
    bool m_parsed;
};

#endif /* QGPGME_QGPGMENEWCRYPTOCONFIG_H */
