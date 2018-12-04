/*
  configuration.h - wraps gpgme configuration components
  Copyright (C) 2010 Klarälvdalens Datakonsult AB
  2016 Bundesamt für Sicherheit in der Informationstechnik
  Software engineering by Intevation GmbH

  This file is part of GPGME++.

  GPGME++ is free software; you can redistribute it and/or
  modify it under the terms of the GNU Library General Public
  License as published by the Free Software Foundation; either
  version 2 of the License, or (at your option) any later version.

  GPGME++ is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Library General Public License for more details.

  You should have received a copy of the GNU Library General Public License
  along with GPGME++; see the file COPYING.LIB.  If not, write to the
  Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
  Boston, MA 02110-1301, USA.
*/

// -*- c++ -*-
#ifndef __GPGMEPP_CONFIGURATION_H__
#define __GPGMEPP_CONFIGURATION_H__

#include "global.h"

#include "gpgmefw.h"

#include <iosfwd>
#include <vector>
#include <string>
#include <algorithm>
#include <memory>

namespace GpgME
{
namespace Configuration
{

typedef std::shared_ptr< std::remove_pointer<gpgme_conf_comp_t>::type > shared_gpgme_conf_comp_t;
typedef std::weak_ptr< std::remove_pointer<gpgme_conf_comp_t>::type > weak_gpgme_conf_comp_t;

class Argument;
class Option;
class Component;

enum Level {
    Basic,
    Advanced,
    Expert,
    Invisible,
    Internal,

    NumLevels
};

enum Type {
    NoType,
    StringType,
    IntegerType,
    UnsignedIntegerType,

    FilenameType = 32,
    LdapServerType,
    KeyFingerprintType,
    PublicKeyType,
    SecretKeyType,
    AliasListType,

    MaxType
};

enum Flag {
    Group    = (1 << 0),
    Optional = (1 << 1),
    List     = (1 << 2),
    Runtime  = (1 << 3),
    Default  = (1 << 4),
    DefaultDescription = (1 << 5),
    NoArgumentDescription = (1 << 6),
    NoChange = (1 << 7),

    LastFlag = NoChange
};

//
// class Component
//

class GPGMEPP_EXPORT Component
{
public:
    Component() : comp() {}
    explicit Component(const shared_gpgme_conf_comp_t &gpgme_comp)
        : comp(gpgme_comp) {}

    // copy ctor is ok

    const Component &operator=(const Component &other)
    {
        if (this != &other) {
            Component(other).swap(*this);
        }
        return *this;
    }

    void swap(Component &other)
    {
        using std::swap;
        swap(this->comp, other.comp);
    }

    bool isNull() const
    {
        return !comp;
    }

    static std::vector<Component> load(Error &err);
    Error save() const;

    const char *name() const;
    const char *description() const;
    const char *programName() const;

    Option option(unsigned int index) const;
    Option option(const char *name) const;

    unsigned int numOptions() const;

    std::vector<Option> options() const;

    GPGMEPP_MAKE_SAFE_BOOL_OPERATOR(!isNull())
private:
    shared_gpgme_conf_comp_t comp;
};

//
// class Option
//

class GPGMEPP_EXPORT Option
{
public:
    Option() : comp(), opt(nullptr) {}
    Option(const shared_gpgme_conf_comp_t &gpgme_comp, gpgme_conf_opt_t gpgme_opt)
        : comp(gpgme_comp), opt(gpgme_opt) {}

    const Option &operator=(const Option &other)
    {
        if (this != &other) {
            Option(other).swap(*this);
        }
        return *this;
    }

    void swap(Option &other)
    {
        using std::swap;
        swap(this->comp, other.comp);
        swap(this->opt,  other.opt);
    }

    bool isNull() const
    {
        return comp.expired() || !opt;
    }

    Component parent() const;

    unsigned int flags() const;

    Level level() const;

    const char *name() const;
    const char *description() const;
    const char *argumentName() const;

    Type type() const;
    Type alternateType() const;

    Argument defaultValue() const;
    const char *defaultDescription() const;

    Argument noArgumentValue() const;
    const char *noArgumentDescription() const;

    /*! The value that is in the config file (or null, if it's not set). */
    Argument activeValue() const;
    /*! The value that is in this object, ie. either activeValue(), newValue(), or defaultValue() */
    Argument currentValue() const;

    Argument newValue() const;
    bool set() const;
    bool dirty() const;

    Error setNewValue(const Argument &argument);
    Error resetToDefaultValue();
    Error resetToActiveValue();

    Argument createNoneArgument(bool set) const;
    Argument createStringArgument(const char *value) const;
    Argument createStringArgument(const std::string &value) const;
    Argument createIntArgument(int value) const;
    Argument createUIntArgument(unsigned int value) const;

    Argument createNoneListArgument(unsigned int count) const;
    Argument createStringListArgument(const std::vector<const char *> &value) const;
    Argument createStringListArgument(const std::vector<std::string> &value) const;
    Argument createIntListArgument(const std::vector<int> &values) const;
    Argument createUIntListArgument(const std::vector<unsigned int> &values) const;

    GPGMEPP_MAKE_SAFE_BOOL_OPERATOR(!isNull())
private:
    weak_gpgme_conf_comp_t  comp;
    gpgme_conf_opt_t opt;
};

//
// class Argument
//

class GPGMEPP_EXPORT Argument
{
    friend class ::GpgME::Configuration::Option;
    Argument(const shared_gpgme_conf_comp_t &comp, gpgme_conf_opt_t opt, gpgme_conf_arg_t arg, bool owns);
public:
    Argument() : comp(), opt(nullptr), arg(nullptr) {}
    //Argument( const shared_gpgme_conf_comp_t & comp, gpgme_conf_opt_t opt, gpgme_conf_arg_t arg );
    Argument(const Argument &other);
    ~Argument();

    const Argument &operator=(const Argument &other)
    {
        if (this != &other) {
            Argument(other).swap(*this);
        }
        return *this;
    }

    void swap(Argument &other)
    {
        using std::swap;
        swap(this->comp, other.comp);
        swap(this->opt,  other.opt);
        swap(this->arg,  other.arg);
    }

    bool isNull() const
    {
        return comp.expired() || !opt || !arg;
    }

    Option parent() const;

    unsigned int numElements() const;

    bool boolValue() const;
    const char *stringValue(unsigned int index = 0) const;
    int          intValue(unsigned int index = 0) const;
    unsigned int uintValue(unsigned int index = 0) const;

    unsigned int numberOfTimesSet() const;
    std::vector<const char *> stringValues() const;
    std::vector<int>          intValues() const;
    std::vector<unsigned int> uintValues() const;

    GPGMEPP_MAKE_SAFE_BOOL_OPERATOR(!isNull())
private:
    weak_gpgme_conf_comp_t comp;
    gpgme_conf_opt_t opt;
    gpgme_conf_arg_t arg;
};

GPGMEPP_EXPORT std::ostream &operator<<(std::ostream &os, Level level);
GPGMEPP_EXPORT std::ostream &operator<<(std::ostream &os, Type type);
GPGMEPP_EXPORT std::ostream &operator<<(std::ostream &os, Flag flag);
GPGMEPP_EXPORT std::ostream &operator<<(std::ostream &os, const Component &component);
GPGMEPP_EXPORT std::ostream &operator<<(std::ostream &os, const Option &option);
GPGMEPP_EXPORT std::ostream &operator<<(std::ostream &os, const Argument &argument);

} // namespace Configuration
} // namespace GpgME

GPGMEPP_MAKE_STD_SWAP_SPECIALIZATION(Configuration::Component)
GPGMEPP_MAKE_STD_SWAP_SPECIALIZATION(Configuration::Option)
GPGMEPP_MAKE_STD_SWAP_SPECIALIZATION(Configuration::Argument)

#endif // __GPGMEPP_CONFIGURATION_H__
