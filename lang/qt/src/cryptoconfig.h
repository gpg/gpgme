/*
    cryptoconfig.h

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004 Klarälvdalens Datakonsult AB
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

#ifndef CRYPTOCONFIG_H
#define CRYPTOCONFIG_H

#include "qgpgme_export.h"
#ifdef __cplusplus
/* we read this file from a C compiler, and are only interested in the
 * enums... */

#include <QUrl>

#include <vector>

class QVariant;

/* Start reading this file from the bottom up :) */

namespace QGpgME
{

/**
 * Description of a single option
 */
class QGPGME_EXPORT CryptoConfigEntry
{

public:
#endif /* __cplusplus */
    /**
       @li basic        This option should always be offered to the user.
       @li advanced        This option may be offered to advanced users.
       @li expert        This option should only be offered to expert users.
       */
    enum Level { Level_Basic = 0,
                 Level_Advanced = 1,
                 Level_Expert = 2
               };

    /**
       Type of the argument
       @li ArgType_None        The option is set or not set, but no argument.
       @li ArgType_String        An unformatted string.
       @li ArgType_Int                A signed integer number.
       @li ArgType_UInt        An unsigned integer number.
       @li ArgType_Path        A string that describes the pathname of a file.
       The file does not necessarily need to exist.
       Separated from string so that e.g. a FileDialog can be used.
       @li ArgType_DirPath        A string that describes the pathname of a directory.
       The directory does not necessarily need to exist.
       Separated from path so that e.g. a FileDialog can be used which only
       allows directories to be selected.
       @li ArgType_LDAPURL        A LDAP URL
       Separated from URL so that a more specific widget can be shown, hiding the url syntax
    */
    enum ArgType { ArgType_None = 0,
                   ArgType_String = 1,
                   ArgType_Int = 2,
                   ArgType_UInt = 3,
                   ArgType_Path = 4,
                   /* Nr. 5 was URL historically. */
                   ArgType_LDAPURL = 6,
                   ArgType_DirPath = 7,

                   NumArgType
                 };

#ifdef __cplusplus
    virtual ~CryptoConfigEntry() {}

    /**
     * Return the internal name of this entry
     */
    virtual QString name() const = 0;

    /**
     * @return user-visible description of this entry
     */
    virtual QString description() const = 0;

    /**
     * @return "component/group/name"
     */
    virtual QString path() const = 0;

    /**
     * @return true if the argument is optional
     */
    virtual bool isOptional() const = 0;

    /**
     * @return true if the entry is readonly
     */
    virtual bool isReadOnly() const = 0;

    /**
     * @return true if the argument can be given multiple times
     */
    virtual bool isList() const = 0;

    /**
     * @return true if the argument can be changed at runtime
     */
    virtual bool isRuntime() const = 0;

    /**
     * User level
     */
    virtual Level level() const = 0;

    /**
     * Argument type
     */
    virtual ArgType argType() const = 0;

    /**
     * Return true if the option is set, i.e. different from default
     */
    virtual bool isSet() const = 0;

    /**
     * Return value as a bool (only allowed for ArgType_None)
     */
    virtual bool boolValue() const = 0;

    /**
     * Return value as a string (available for all argtypes)
     * The returned string can be empty (explicitly set to empty) or null (not set).
     */
    virtual QString stringValue() const = 0;

    /**
     * Return value as a signed int
     */
    virtual int intValue() const = 0;

    /**
     * Return value as an unsigned int
     */
    virtual unsigned int uintValue() const = 0;

    /**
     * Return value as a URL (only meaningful for Path and URL argtypes)
     */
    virtual QUrl urlValue() const = 0;

    /**
     * Return number of times the option is set (only valid for ArgType_None, if isList())
     */
    virtual unsigned int numberOfTimesSet() const = 0;

    /**
     * Return value as a list of signed ints
     */
    virtual std::vector<int> intValueList() const = 0;

    /**
     * Return value as a list of unsigned ints
     */
    virtual std::vector<unsigned int> uintValueList() const = 0;

    /**
     * Return value as a list of URLs (only meaningful for Path and URL argtypes, if isList())
     */
    virtual QList<QUrl> urlValueList() const = 0;

    /**
     * Reset an option to its default value
     */
    virtual void resetToDefault() = 0;

    /**
     * Define whether the option is set or not (only allowed for ArgType_None)
     * #### TODO: and for options with optional args
     */
    virtual void setBoolValue(bool) = 0;

    /**
     * Set string value (allowed for all argtypes)
     */
    virtual void setStringValue(const QString &) = 0;

    /**
     * Set a new signed int value
     */
    virtual void setIntValue(int) = 0;

    /**
     * Set a new unsigned int value
     */
    virtual void setUIntValue(unsigned int) = 0;

    /**
     * Set value as a URL (only meaningful for Path (if local) and URL argtypes)
     */
    virtual void setURLValue(const QUrl &) = 0;

    /**
     * Set the number of times the option is set (only valid for ArgType_None, if isList())
     */
    virtual void setNumberOfTimesSet(unsigned int) = 0;

    /**
     * Set a new list of signed int values
     */
    virtual void setIntValueList(const std::vector<int> &) = 0;

    /**
     * Set a new list of unsigned int values
     */
    virtual void setUIntValueList(const std::vector<unsigned int> &) = 0;

    /**
     * Set value as a URL list (only meaningful for Path (if all URLs are local) and URL argtypes, if isList())
     */
    virtual void setURLValueList(const QList<QUrl> &) = 0;

    /**
     * @return true if the value was changed
     */
    virtual bool isDirty() const = 0;

    // Design change from here on we are closely bound to one implementation
    // of cryptoconfig. To avoid ABI breaks with every new function we
    // add real functions from now on.

    /**
     * @return a stringValueList.
     */
    QStringList stringValueList() const;

    /**
     * Return the default value as a variant (available for all argtypes).
     */
    QVariant defaultValue() const;
};

/**
 * Group containing a set of config options
 */
class QGPGME_EXPORT CryptoConfigGroup
{

public:
    virtual ~CryptoConfigGroup() {}

    /**
     * Return the internal name of this group
     */
    virtual QString name() const = 0;

    /**
     * Return the name of the icon for this group
     */
    virtual QString iconName() const = 0;

    /**
     * @return user-visible description of this group
     */
    virtual QString description() const = 0;

    /**
     * @return "component/group"
     */
    virtual QString path() const = 0;

    /**
     * User level
     */
    virtual CryptoConfigEntry::Level level() const = 0;

    /**
     * Returns the list of entries that are known by this group.
     *
     * @return list of group entry names.
     **/
    virtual QStringList entryList() const = 0;

    /**
     * @return the configuration object for a given entry in this group
     * The object is owned by CryptoConfigGroup, don't delete it.
     * Groups cannot be nested, so all entries returned here are pure entries, no groups.
     */
    virtual CryptoConfigEntry *entry(const QString &name) const = 0;
};

/**
 * Crypto config for one component (e.g. gpg-agent, dirmngr etc.)
 */
class QGPGME_EXPORT CryptoConfigComponent
{

public:
    virtual ~CryptoConfigComponent() {}

    /**
     * Return the internal name of this component
     */
    virtual QString name() const = 0;

    /**
     * Return the name of the icon for this component
     */
    virtual QString iconName() const = 0;

    /**
     * Return user-visible description of this component
     */
    virtual QString description() const = 0;

    /**
     * Returns the list of groups that are known about.
     *
     * @return list of group names. One of them can be "<nogroup>", which is the group where all
     * "toplevel" options (belonging to no group) are.
     */
    virtual QStringList groupList() const = 0;

    /**
     * @return the configuration object for a given group
     * The object is owned by CryptoConfigComponent, don't delete it.
     */
    virtual CryptoConfigGroup *group(const QString &name) const = 0;

};

/**
 * Main interface to crypto configuration.
 */
class QGPGME_EXPORT CryptoConfig
{

public:
    virtual ~CryptoConfig() {}

    /**
     * Returns the list of known components (e.g. "gpg-agent", "dirmngr" etc.).
     * Use @ref component() to retrieve more information about each one.
     * @return list of component names.
     **/
    virtual QStringList componentList() const = 0;

    /**
     * @return the configuration object for a given component
     * The object is owned by CryptoConfig, don't delete it.
     */
    virtual CryptoConfigComponent *component(const QString &name) const = 0;

    /**
     * Convenience method to get hold of a single configuration entry when
     * its component and name are known. This can be used to read
     * the value and/or to set a value to it.
     *
     * @return the configuration object for a single configuration entry, 0 if not found.
     * The object is owned by CryptoConfig, don't delete it.
     */
    CryptoConfigEntry *entry(const QString &componentName, const QString &entryName) const;

    /**
     * This function is obsolete. It is provided to keep old source code working.
     * We strongly advise against using it in new code.
     *
     * This function overloads @ref entry().
     *
     * Use the entry overload that does not require a group name instead. The group name
     * is not needed to identify a configuration entry because it only provides logical
     * grouping for user interfaces. Sometimes configuration entries are moved to different
     * groups to improve usability.
     */
    QGPGME_DEPRECATED CryptoConfigEntry *entry(const QString &componentName, const QString &groupName, const QString &entryName) const;

    /**
     * Write back changes
     *
     * @param runtime this parameter is ignored. Changes will always
     * be made with --runtime set.
     */
    virtual void sync(bool runtime) = 0;

    /**
     * Tells the CryptoConfig to discard any cached information, including
     * all components, groups and entries.
     * Call this to free some memory when you won't be using the object
     * for some time.
     * DON'T call this if you're holding pointers to components, groups or entries.
     */
    virtual void clear() = 0;
};

}
#endif /* __cplusplus */
#endif /* CRYPTOCONFIG_H */
