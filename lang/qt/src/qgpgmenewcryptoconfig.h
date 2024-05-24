/*
    qgpgmenewcryptoconfig.h

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2010 Klarälvdalens Datakonsult AB
    Copyright (c) 2016 by Bundesamt für Sicherheit in der Informationstechnik
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

#ifndef QGPGME_QGPGMENEWCRYPTOCONFIG_H
#define QGPGME_QGPGMENEWCRYPTOCONFIG_H

#include "qgpgme_export.h"
#include "cryptoconfig.h"

#include <QHash>
#include <QStringList>
#include <QVariant>

#include <gpgme++/configuration.h>

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

    QString name() const override;
    QString description() const override;
    QString path() const override;
    bool isOptional() const override;
    bool isReadOnly() const override;
    bool isList() const override;
    bool isRuntime() const override;
    Level level() const override;
    ArgType argType() const override;
    bool isSet() const override;
    bool boolValue() const override;
    QString stringValue() const override;
    int intValue() const override;
    unsigned int uintValue() const override;
    QUrl urlValue() const override;
    unsigned int numberOfTimesSet() const override;
    std::vector<int> intValueList() const override;
    std::vector<unsigned int> uintValueList() const override;
    QList<QUrl> urlValueList() const override;
    void resetToDefault() override;
    void setBoolValue(bool) override;
    void setStringValue(const QString &) override;
    void setIntValue(int) override;
    void setUIntValue(unsigned int) override;
    void setURLValue(const QUrl &) override;
    void setNumberOfTimesSet(unsigned int) override;
    void setIntValueList(const std::vector<int> &) override;
    void setUIntValueList(const std::vector<unsigned int> &) override;
    void setURLValueList(const QList<QUrl> &) override;
    bool isDirty() const override;

    QStringList stringValueList() const;
    QVariant defaultValue() const;

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

    QString name() const override;
    QString iconName() const override
    {
        return QString();
    }
    QString description() const override;
    QString path() const override;
    QGpgME::CryptoConfigEntry::Level level() const override;
    QStringList entryList() const override;
    QGpgMENewCryptoConfigEntry *entry(const QString &name) const override;

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

    QString name() const override;
    QString iconName() const override
    {
        return name();
    }
    QString description() const override;
    QStringList groupList() const override;
    QGpgMENewCryptoConfigGroup *group(const QString &name) const override;

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

    QStringList componentList() const override;

    QGpgMENewCryptoConfigComponent *component(const QString &name) const override;

    void clear() override;
    void sync(bool runtime) override;

private:
    /// @param showErrors if true, a messagebox will be shown if e.g. gpgconf wasn't found
    void reloadConfiguration(bool showErrors);

private:
    QHash< QString, std::shared_ptr<QGpgMENewCryptoConfigComponent> > m_componentsByName;
    bool m_parsed;
};

#endif /* QGPGME_QGPGMENEWCRYPTOCONFIG_H */
