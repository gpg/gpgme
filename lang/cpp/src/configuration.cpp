/*
  configuration.cpp - wraps gpgme configuration components
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

#include "configuration.h"
#include "error.h"
#include "util.h"

#include <gpgme.h>

#include <iterator>
#include <algorithm>
#include <ostream>
#include <cstring>
#include <assert.h>

using namespace GpgME;
using namespace GpgME::Configuration;

typedef std::shared_ptr< std::remove_pointer<gpgme_conf_opt_t>::type > shared_gpgme_conf_opt_t;
typedef std::weak_ptr< std::remove_pointer<gpgme_conf_opt_t>::type > weak_gpgme_conf_opt_t;

typedef std::shared_ptr< std::remove_pointer<gpgme_conf_arg_t>::type > shared_gpgme_conf_arg_t;
typedef std::weak_ptr< std::remove_pointer<gpgme_conf_arg_t>::type > weak_gpgme_conf_arg_t;

typedef std::shared_ptr< std::remove_pointer<gpgme_ctx_t>::type > shared_gpgme_ctx_t;
typedef std::weak_ptr< std::remove_pointer<gpgme_ctx_t>::type > weak_gpgme_ctx_t;

namespace
{
struct nodelete {
    template <typename T> void operator()(T *) {}
};
}

// static
std::vector<Component> Component::load(Error &returnedError)
{

    //
    // 1. get a context:
    //
    gpgme_ctx_t ctx_native = nullptr;
    if (const gpgme_error_t err = gpgme_new(&ctx_native)) {
        returnedError = Error(err);
        return std::vector<Component>();
    }
    const shared_gpgme_ctx_t ctx(ctx_native, &gpgme_release);

    //
    // 2. load the config:
    //
    gpgme_conf_comp_t conf_list_native = nullptr;
    if (const gpgme_error_t err = gpgme_op_conf_load(ctx_native, &conf_list_native)) {
        returnedError = Error(err);
        return std::vector<Component>();
    }
    shared_gpgme_conf_comp_t head(conf_list_native, &gpgme_conf_release);

    //
    // 3. convert to vector<Component>:
    //
    std::vector<Component> result;

    while (head) {
        // secure 'head->next' (if any) against memleaks:
        shared_gpgme_conf_comp_t next;
        if (head->next) {
            next.reset(head->next, &gpgme_conf_release);
        }

        // now prevent double-free of next.get() and following:
        head->next = nullptr;

        // now add a new Component to 'result' (may throw):
        result.resize(result.size() + 1);
        result.back().comp.swap(head);   // .comp = std::move( head );
        head.swap(next);                 //  head = std::move( next );
    }

    return result;
}

Error Component::save() const
{

    if (isNull()) {
        return Error(make_error(GPG_ERR_INV_ARG));
    }

    //
    // 1. get a context:
    //
    gpgme_ctx_t ctx_native = nullptr;
    if (const gpgme_error_t err = gpgme_new(&ctx_native)) {
        return Error(err);
    }
    const shared_gpgme_ctx_t ctx(ctx_native, &gpgme_release);

    //
    // 2. save the config:
    //
    return Error(gpgme_op_conf_save(ctx.get(), comp.get()));
}

const char *Component::name() const
{
    return comp ? comp->name : nullptr;
}

const char *Component::description() const
{
    return comp ? comp->description : nullptr ;
}

const char *Component::programName() const
{
    return comp ? comp->program_name : nullptr ;
}

Option Component::option(unsigned int idx) const
{
    gpgme_conf_opt_t opt = nullptr;
    if (comp) {
        opt = comp->options;
    }
    while (opt && idx) {
        opt = opt->next;
        --idx;
    }
    if (opt) {
        return Option(comp, opt);
    }
    return Option();
}

Option Component::option(const char *name) const
{
    gpgme_conf_opt_t opt = nullptr;
    if (comp) {
        opt = comp->options;
    }
    using namespace std; // for strcmp
    while (opt && strcmp(name, opt->name) != 0) {
        opt = opt->next;
    }
    if (opt) {
        return Option(comp, opt);
    }
    return Option();
}

unsigned int Component::numOptions() const
{
    unsigned int result = 0;
    for (gpgme_conf_opt_t opt = comp ? comp->options : nullptr ; opt ; opt = opt->next) {
        ++result;
    }
    return result;
}

std::vector<Option> Component::options() const
{
    std::vector<Option> result;
    for (gpgme_conf_opt_t opt = comp ? comp->options : nullptr ; opt ; opt = opt->next) {
        result.push_back(Option(comp, opt));
    }
    return result;
}

static gpgme_conf_arg_t mygpgme_conf_arg_copy(gpgme_conf_arg_t other, gpgme_conf_type_t type)
{
    gpgme_conf_arg_t result = nullptr, last = nullptr;
    for (gpgme_conf_arg_t a = other ; a ; a = a->next) {
        gpgme_conf_arg_t arg = nullptr;
        const gpgme_error_t err
            = gpgme_conf_arg_new(&arg, type,
                                 a->no_arg                 ? nullptr :
                                 type == GPGME_CONF_STRING ? a->value.string :
                                 /* else */                  static_cast<void *>(&a->value));
        if (err) {
            gpgme_conf_arg_release(result, type);
            return nullptr;
        }
        assert(arg);
        if (result) {
            last->next = arg;
        } else {
            result = arg;
        }
        last = arg;
    }
    return result;
}

Component Option::parent() const
{
    return Component(comp.lock());
}

unsigned int Option::flags() const
{
    return isNull() ? 0 : opt->flags;
}

Level Option::level() const
{
    return isNull() ? Internal : static_cast<Level>(opt->level) ;
}

const char *Option::name() const
{
    return isNull() ? nullptr : opt->name ;
}

const char *Option::description() const
{
    return isNull() ? nullptr : opt->description ;
}

const char *Option::argumentName() const
{
    return isNull() ? nullptr : opt->argname ;
}

Type Option::type() const
{
    return isNull() ? NoType : static_cast<Type>(opt->type) ;
}

Type Option::alternateType() const
{
    return isNull() ? NoType : static_cast<Type>(opt->alt_type) ;
}

Argument Option::defaultValue() const
{
    if (isNull()) {
        return Argument();
    } else {
        return Argument(comp.lock(), opt, opt->default_value, false);
    }
}

const char *Option::defaultDescription() const
{
    return isNull() ? nullptr : opt->default_description ;
}

Argument Option::noArgumentValue() const
{
    if (isNull()) {
        return Argument();
    } else {
        return Argument(comp.lock(), opt, opt->no_arg_value, false);
    }
}

const char *Option::noArgumentDescription() const
{
    return isNull() ? nullptr : opt->no_arg_description ;
}

Argument Option::activeValue() const
{
    if (isNull()) {
        return Argument();
    } else {
        return Argument(comp.lock(), opt, opt->value, false);
    }
}

Argument Option::currentValue() const
{
    if (isNull()) {
        return Argument();
    }
    const gpgme_conf_arg_t arg =
        opt->change_value ? opt->new_value ? opt->new_value : opt->default_value :
        opt->value        ? opt->value :
        /* else */          opt->default_value ;
    return Argument(comp.lock(), opt, arg, false);
}

Argument Option::newValue() const
{
    if (isNull()) {
        return Argument();
    } else {
        return Argument(comp.lock(), opt, opt->new_value, false);
    }
}

bool Option::set() const
{
    if (isNull()) {
        return false;
    } else if (opt->change_value) {
        return opt->new_value;
    } else {
        return opt->value;
    }
}

bool Option::dirty() const
{
    return !isNull() && opt->change_value ;
}

Error Option::setNewValue(const Argument &argument)
{
    if (isNull()) {
        return Error(make_error(GPG_ERR_INV_ARG));
    } else if (argument.isNull()) {
        return resetToDefaultValue();
    } else if (const gpgme_conf_arg_t arg = mygpgme_conf_arg_copy(argument.arg, opt->alt_type)) {
        return Error(gpgme_conf_opt_change(opt, 0, arg));
    } else {
        return Error(make_error(GPG_ERR_ENOMEM));
    }
}

Error Option::resetToActiveValue()
{
    if (isNull()) {
        return Error(make_error(GPG_ERR_INV_ARG));
    } else {
        return Error(gpgme_conf_opt_change(opt, 1, nullptr));
    }
}

Error Option::resetToDefaultValue()
{
    if (isNull()) {
        return Error(make_error(GPG_ERR_INV_ARG));
    } else {
        return Error(gpgme_conf_opt_change(opt, 0, nullptr));
    }
}

static gpgme_conf_arg_t make_argument(gpgme_conf_type_t type, const void *value)
{
    gpgme_conf_arg_t arg = nullptr;
    if (const gpgme_error_t err = gpgme_conf_arg_new(&arg, type, value)) {
        return nullptr;
    } else {
        return arg;
    }
}

Argument Option::createNoneArgument(bool set) const
{
    if (isNull() || alternateType() != NoType) {
        return Argument();
    } else {
        if (set) {
            return createNoneListArgument(1);
        }
    }
    return Argument();
}

Argument Option::createStringArgument(const char *value) const
{
    if (isNull() || alternateType() != StringType) {
        return Argument();
    } else {
        return Argument(comp.lock(), opt, make_argument(GPGME_CONF_STRING, value), true);
    }
}

Argument Option::createStringArgument(const std::string &value) const
{
    if (isNull() || alternateType() != StringType) {
        return Argument();
    } else {
        return Argument(comp.lock(), opt, make_argument(GPGME_CONF_STRING, value.c_str()), true);
    }
}

Argument Option::createIntArgument(int value) const
{
    if (isNull() || alternateType() != IntegerType) {
        return Argument();
    } else {
        return Argument(comp.lock(), opt, make_argument(GPGME_CONF_INT32, &value), true);
    }
}

Argument Option::createUIntArgument(unsigned int value) const
{
    if (isNull() || alternateType() != UnsignedIntegerType) {
        return Argument();
    } else {
        return Argument(comp.lock(), opt, make_argument(GPGME_CONF_UINT32, &value), true);
    }
}

namespace
{
const void *to_void_star(const char *s)
{
    return s;
}
const void *to_void_star(const std::string &s)
{
    return s.c_str();
}
const void *to_void_star(const int &i)
{
    return &i;    // const-&: sic!
}
const void *to_void_star(const unsigned int &i)
{
    return &i;    // const-&: sic!
}

template <typename T>
gpgme_conf_arg_t make_argument(gpgme_conf_type_t type, const std::vector<T> &value)
{
    gpgme_conf_arg_t result = nullptr;
    gpgme_conf_arg_t last = nullptr;
    for (typename std::vector<T>::const_iterator it = value.begin(), end = value.end() ; it != end ; ++it) {
        if (gpgme_conf_arg_t arg = make_argument(type, to_void_star(*it))) {
            if (last) {
                last = last->next = arg;
            } else {
                result = last = arg;
            }
        }
    }
    return result;
}
}

Argument Option::createNoneListArgument(unsigned int value) const
{
    if (value) {
        return Argument(comp.lock(), opt, make_argument(GPGME_CONF_NONE, &value), true);
    }
    return Argument();
}

Argument Option::createStringListArgument(const std::vector<const char *> &value) const
{
    return Argument(comp.lock(), opt, make_argument(GPGME_CONF_STRING, value), true);
}

Argument Option::createStringListArgument(const std::vector<std::string> &value) const
{
    return Argument(comp.lock(), opt, make_argument(GPGME_CONF_STRING, value), true);
}

Argument Option::createIntListArgument(const std::vector<int> &value) const
{
    return Argument(comp.lock(), opt, make_argument(GPGME_CONF_INT32, value), true);
}

Argument Option::createUIntListArgument(const std::vector<unsigned int> &value) const
{
    return Argument(comp.lock(), opt, make_argument(GPGME_CONF_UINT32, value), true);
}

Argument::Argument(const shared_gpgme_conf_comp_t &comp, gpgme_conf_opt_t opt, gpgme_conf_arg_t arg, bool owns)
    : comp(comp),
      opt(opt),
      arg(owns ? arg : mygpgme_conf_arg_copy(arg, opt ? opt->alt_type : GPGME_CONF_NONE))
{

}

#if 0
Argument::Argument(const shared_gpgme_conf_comp_t &comp, gpgme_conf_opt_t opt, gpgme_conf_arg_t arg)
    : comp(comp),
      opt(opt),
      arg(mygpgme_conf_arg_copy(arg, opt ? opt->alt_type : GPGME_CONF_NONE))
{

}
#endif

Argument::Argument(const Argument &other)
    : comp(other.comp),
      opt(other.opt),
      arg(mygpgme_conf_arg_copy(other.arg, opt ? opt->alt_type : GPGME_CONF_NONE))
{

}

Argument::~Argument()
{
    gpgme_conf_arg_release(arg, opt ? opt->alt_type : GPGME_CONF_NONE);
}

Option Argument::parent() const
{
    return Option(comp.lock(), opt);
}

bool Argument::boolValue() const
{
    return numberOfTimesSet();
}

unsigned int Argument::numElements() const
{
    if (isNull()) {
        return 0;
    }
    unsigned int result = 0;
    for (gpgme_conf_arg_t a = arg ; a ; a = a->next) {
        ++result;
    }
    return result;
}

const char *Argument::stringValue(unsigned int idx) const
{
    if (isNull() || opt->alt_type != GPGME_CONF_STRING) {
        return nullptr;
    }
    gpgme_conf_arg_t a = arg;
    while (a && idx) {
        a = a->next;
        --idx;
    }
    return a ? a->value.string : nullptr ;
}

int Argument::intValue(unsigned int idx) const
{
    if (isNull() || opt->alt_type != GPGME_CONF_INT32) {
        return 0;
    }
    gpgme_conf_arg_t a = arg;
    while (a && idx) {
        a = a->next;
        --idx;
    }
    return a ? a->value.int32 : 0 ;
}

unsigned int Argument::uintValue(unsigned int idx) const
{
    if (isNull() || opt->alt_type != GPGME_CONF_UINT32) {
        return 0;
    }
    gpgme_conf_arg_t a = arg;
    while (a && idx) {
        a = a->next;
        --idx;
    }
    return a ? a->value.uint32 : 0 ;
}

unsigned int Argument::numberOfTimesSet() const
{
    if (isNull() || opt->alt_type != GPGME_CONF_NONE) {
        return 0;
    }
    return arg->value.count;
}

std::vector<const char *> Argument::stringValues() const
{
    if (isNull() || opt->alt_type != GPGME_CONF_STRING) {
        return std::vector<const char *>();
    }
    std::vector<const char *> result;
    for (gpgme_conf_arg_t a = arg ; a ; a = a->next) {
        result.push_back(a->value.string);
    }
    return result;
}

std::vector<int> Argument::intValues() const
{
    if (isNull() || opt->alt_type != GPGME_CONF_INT32) {
        return std::vector<int>();
    }
    std::vector<int> result;
    for (gpgme_conf_arg_t a = arg ; a ; a = a->next) {
        result.push_back(a->value.int32);
    }
    return result;
}

std::vector<unsigned int> Argument::uintValues() const
{
    if (isNull() || opt->alt_type != GPGME_CONF_UINT32) {
        return std::vector<unsigned int>();
    }
    std::vector<unsigned int> result;
    for (gpgme_conf_arg_t a = arg ; a ; a = a->next) {
        result.push_back(a->value.uint32);
    }
    return result;
}

std::ostream &Configuration::operator<<(std::ostream &os, Level level)
{
    switch (level) {
    case Basic:     return os << "Basic";
    case Advanced:  return os << "Advanced";
    case Expert:    return os << "Expert";
    case Invisible: return os << "Invisible";
    case Internal:  return os << "Internal";
    case NumLevels: ;
    }
    return os << "<unknown>";
}

std::ostream &Configuration::operator<<(std::ostream &os, Type type)
{
    switch (type) {
    case NoType:              return os << "None";
    case StringType:          return os << "String";
    case IntegerType:         return os << "Integer";
    case UnsignedIntegerType: return os << "UnsignedInteger";
    case FilenameType:        return os << "Filename";
    case LdapServerType:      return os << "LdapServer";
    case KeyFingerprintType:  return os << "KeyFingerprint";
    case PublicKeyType:       return os << "PublicKey";
    case SecretKeyType:       return os << "SecretKey";
    case AliasListType:       return os << "AliasList";
    case MaxType: ;
    }
    return os << "<unknown>";
}

std::ostream &Configuration::operator<<(std::ostream &os, Flag f)
{
    unsigned int flags = f;
    std::vector<const char *> s;
    if (flags & Group) {
        s.push_back("Group");
    }
    if (flags & Optional) {
        s.push_back("Optional");
    }
    if (flags & List) {
        s.push_back("List");
    }
    if (flags & Runtime) {
        s.push_back("Runtime");
    }
    if (flags & Default) {
        s.push_back("Default");
    }
    if (flags & DefaultDescription) {
        s.push_back("DefaultDescription");
    }
    if (flags & NoArgumentDescription) {
        s.push_back("NoArgumentDescription");
    }
    if (flags & NoChange) {
        s.push_back("NoChange");
    }
    flags &= ~(Group | Optional | List | Runtime | Default | DefaultDescription | NoArgumentDescription | NoChange);
    if (flags) {
        s.push_back("other flags(");
    }
    std::copy(s.begin(), s.end(),
              std::ostream_iterator<const char *>(os, "|"));
    if (flags) {
        os << flags << ')';
    }
    return os;
}

std::ostream &Configuration::operator<<(std::ostream &os, const Component &c)
{
    os << "Component["
       << "\n  name       : " << protect(c.name())
       << "\n  description: " << protect(c.description())
       << "\n  programName: " << protect(c.programName())
       << "\n  options    : \n";
    const std::vector<Option> options = c.options();
    std::copy(options.begin(), options.end(),
              std::ostream_iterator<Option>(os, "\n"));
    os << "\n]";
    return os;
}

std::ostream &Configuration::operator<<(std::ostream &os, const Option &o)
{
    return os << "Option["
           << "\n  name:       : " << protect(o.name())
           << "\n  description : " << protect(o.description())
           << "\n  argName     : " << protect(o.argumentName())
           << "\n  flags       : " << static_cast<Flag>(o.flags())
           << "\n  level       : " << o.level()
           << "\n  type        : " << o.type()
           << "\n  alt_type    : " << o.alternateType()
           << "\n  default_val : " << o.defaultValue()
           << "\n  default_desc: " << protect(o.defaultDescription())
           << "\n  no_arg_value: " << o.noArgumentValue()
           << "\n  no_arg_desc : " << protect(o.noArgumentDescription())
           << "\n  active_value: " << o.activeValue()
           << "\n  new_value   : " << o.newValue()
           << "\n  --> cur_val : " << o.currentValue()
           << "\n  set         : " << o.set()
           << "\n  dirty       : " << o.dirty()
           << "\n]"
           ;
}

std::ostream &Configuration::operator<<(std::ostream &os, const Argument &a)
{
    const Option o = a.parent();
    const bool list = o.flags() & List;
    os << "Argument[";
    if (a) {
        switch (o.alternateType()) {
        case NoType:
            if (list) {
                os << a.numberOfTimesSet() << 'x';
            } else {
                os << a.boolValue();
            }
            break;
        default:
        case StringType:
            if (list) {
                const std::vector<const char *> v = a.stringValues();
                os << v.size() << ':';
                // can't use std::copy + ostream_iterator here, since we need the protect() call
                bool first = true;
                std::for_each(v.begin(), v.end(), [&first, &os](const char *s) {
                    if (first) {
                        first = false;
                    } else {
                        os << ',';
                    }
                    os << protect(s);
                });
            } else {
                os << protect(a.stringValue());
            }
            break;
        case IntegerType:
            if (list) {
                const std::vector<int> v = a.intValues();
                os << v.size() << ':';
                std::copy(v.begin(), v.end(),
                          std::ostream_iterator<int>(os, ","));
            } else {
                os << a.intValue();
            }
            break;
        case UnsignedIntegerType:
            if (list) {
                const std::vector<unsigned int> v = a.uintValues();
                os << v.size() << ':';
                std::copy(v.begin(), v.end(),
                          std::ostream_iterator<unsigned int>(os, ","));
            } else {
                os << a.intValue();
            }
            break;
        }
    }
    return os << ']';
}
