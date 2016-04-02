/****************************************************************************
** Copyright (C) 2001-2007 Klarälvdalens Datakonsult AB
    Copyright (c) 2016 Intevation GmbH.  All rights reserved.
**
** This file is part of the KD Tools library.
**
** This file may be distributed and/or modified under the terms of the
** GNU General Public License version 2 as published by the Free Software
** Foundation and appearing in the file LICENSE.GPL included in the
** packaging of this file.
**
** Licensees holding valid commercial KD Tools licenses may use this file in
** accordance with the KD Tools Commercial License Agreement provided with
** the Software.
**
** This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
** WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
**
** Contact info@klaralvdalens-datakonsult.se if any conditions of this
** licensing are not clear to you.
**
**********************************************************************/
#ifndef __KDTOOLSCORE_STL_UTIL_H__
#define __KDTOOLSCORE_STL_UTIL_H__

#include <boost/range.hpp>
#include <boost/iterator/filter_iterator.hpp>
#include <boost/iterator/transform_iterator.hpp>
#include <boost/call_traits.hpp>
#include <boost/version.hpp>

#include <algorithm>
#include <numeric>
#include <utility>
#include <iterator>
#include <functional>

namespace kdtools
{

struct nodelete {
    template <typename T>
    void operator()(const T *) const {}
};

struct identity {
    template <typename T>
    T *operator()(T *t) const
    {
        return t;
    }
    template <typename T>
    const T *operator()(const T *t) const
    {
        return t;
    }
    template <typename T>
    T &operator()(T &t) const
    {
        return t;
    }
    template <typename T>
    const T &operator()(const T &t) const
    {
        return t;
    }
};

template <typename Pair>
struct select1st;

template <typename U, typename V>
struct select1st< std::pair<U, V> >
    : std::unary_function<std::pair<U, V>, U> {
    typename boost::call_traits<U>::param_type
    operator()(const std::pair<U, V> &pair) const
    {
        return pair.first;
    }
};

template <typename Pair>
struct select2nd;

template <typename U, typename V>
struct select2nd< std::pair<U, V> >
    : std::unary_function<std::pair<U, V>, V> {
    typename boost::call_traits<V>::param_type
    operator()(const std::pair<U, V> &pair) const
    {
        return pair.second;
    }
};

template <typename InputIterator, typename OutputIterator, typename UnaryPredicate>
OutputIterator copy_if(InputIterator first, InputIterator last, OutputIterator dest, UnaryPredicate pred)
{
    while (first != last) {
        if (pred(*first)) {
            *dest = *first;
            ++dest;
        }
        ++first;
    }
    return dest;
}

template <typename OutputIterator, typename InputIterator, typename UnaryFunction, typename UnaryPredicate>
OutputIterator transform_if(InputIterator first, InputIterator last, OutputIterator dest, UnaryPredicate pred, UnaryFunction filter)
{
    return std::transform(boost::make_filter_iterator(filter, first, last),
                          boost::make_filter_iterator(filter, last,  last),
                          dest, pred);
}

template <typename InputIterator, typename OutputIterator>
OutputIterator copy_1st(InputIterator first, InputIterator last, OutputIterator dest)
{
    return std::copy(boost::make_transform_iterator(first, select1st<typename std::iterator_traits<InputIterator>::value_type>()),
                     boost::make_transform_iterator(last,  select1st<typename std::iterator_traits<InputIterator>::value_type>()),
                     dest);
}

template <typename InputIterator, typename OutputIterator>
OutputIterator copy_2nd(InputIterator first, InputIterator last, OutputIterator dest)
{
    return std::copy(boost::make_transform_iterator(first, select2nd<typename std::iterator_traits<InputIterator>::value_type>()),
                     boost::make_transform_iterator(last,  select2nd<typename std::iterator_traits<InputIterator>::value_type>()),
                     dest);
}

template <typename InputIterator, typename OutputIterator, typename Predicate>
OutputIterator copy_1st_if(InputIterator first, InputIterator last, OutputIterator dest, Predicate pred)
{
    return kdtools::copy_if(boost::make_transform_iterator(first, select1st<typename std::iterator_traits<InputIterator>::value_type>()),
                            boost::make_transform_iterator(last,  select1st<typename std::iterator_traits<InputIterator>::value_type>()),
                            dest, pred);
}

template <typename InputIterator, typename OutputIterator, typename Predicate>
OutputIterator copy_2nd_if(InputIterator first, InputIterator last, OutputIterator dest, Predicate pred)
{
    return kdtools::copy_if(boost::make_transform_iterator(first, select2nd<typename std::iterator_traits<InputIterator>::value_type>()),
                            boost::make_transform_iterator(last,  select2nd<typename std::iterator_traits<InputIterator>::value_type>()),
                            dest, pred);
}

template <typename OutputIterator, typename InputIterator, typename UnaryFunction>
OutputIterator transform_1st(InputIterator first, InputIterator last, OutputIterator dest, UnaryFunction func)
{
    return std::transform(boost::make_transform_iterator(first, select1st<typename std::iterator_traits<InputIterator>::value_type>()),
                          boost::make_transform_iterator(last,  select1st<typename std::iterator_traits<InputIterator>::value_type>()),
                          dest, func);
}

template <typename OutputIterator, typename InputIterator, typename UnaryFunction>
OutputIterator transform_2nd(InputIterator first, InputIterator last, OutputIterator dest, UnaryFunction func)
{
    return std::transform(boost::make_transform_iterator(first, select2nd<typename std::iterator_traits<InputIterator>::value_type>()),
                          boost::make_transform_iterator(last,  select2nd<typename std::iterator_traits<InputIterator>::value_type>()),
                          dest, func);
}

template <typename Value, typename InputIterator, typename UnaryPredicate>
Value accumulate_if(InputIterator first, InputIterator last, UnaryPredicate filter, const Value &value = Value())
{
    return std::accumulate(boost::make_filter_iterator(filter, first, last),
                           boost::make_filter_iterator(filter, last,  last), value);
}

template <typename Value, typename InputIterator, typename UnaryPredicate, typename BinaryOperation>
Value accumulate_if(InputIterator first, InputIterator last, UnaryPredicate filter, const Value &value, BinaryOperation op)
{
    return std::accumulate(boost::make_filter_iterator(filter, first, last),
                           boost::make_filter_iterator(filter, last,  last), value, op);
}

template <typename Value, typename InputIterator, typename UnaryFunction>
Value accumulate_transform(InputIterator first, InputIterator last, UnaryFunction map, const Value &value = Value())
{
    return std::accumulate(boost::make_transform_iterator(first, map),
                           boost::make_transform_iterator(last, map), value);
}

template <typename Value, typename InputIterator, typename UnaryFunction, typename BinaryOperation>
Value accumulate_transform(InputIterator first, InputIterator last, UnaryFunction map, const Value &value, BinaryOperation op)
{
    return std::accumulate(boost::make_transform_iterator(first, map),
                           boost::make_transform_iterator(last, map), value, op);
}

template <typename Value, typename InputIterator, typename UnaryFunction, typename UnaryPredicate>
Value accumulate_transform_if(InputIterator first, InputIterator last, UnaryFunction map, UnaryPredicate pred, const Value &value = Value())
{
    return std::accumulate(boost::make_transform_iterator(first, map),
                           boost::make_transform_iterator(last, map), value);
}

template <typename Value, typename InputIterator, typename UnaryFunction, typename UnaryPredicate, typename BinaryOperation>
Value accumulate_transform_if(InputIterator first, InputIterator last, UnaryFunction map, UnaryPredicate filter, const Value &value, BinaryOperation op)
{
    return std::accumulate(boost::make_transform_iterator(boost::make_filter_iterator(filter, first, last), map),
                           boost::make_transform_iterator(boost::make_filter_iterator(filter, last, last), map), value, op);
}

template <typename InputIterator, typename OutputIterator1, typename OutputIterator2, typename UnaryPredicate>
std::pair<OutputIterator1, OutputIterator2> separate_if(InputIterator first, InputIterator last, OutputIterator1 dest1, OutputIterator2 dest2, UnaryPredicate pred)
{
    while (first != last) {
        if (pred(*first)) {
            *dest1 = *first;
            ++dest1;
        } else {
            *dest2 = *first;
            ++dest2;
        }
        ++first;
    }
    return std::make_pair(dest1, dest2);
}

template <typename InputIterator>
bool any(InputIterator first, InputIterator last)
{
    while (first != last)
        if (*first) {
            return true;
        } else {
            ++first;
        }
    return false;
}

template <typename InputIterator, typename UnaryPredicate>
bool any(InputIterator first, InputIterator last, UnaryPredicate pred)
{
    while (first != last)
        if (pred(*first)) {
            return true;
        } else {
            ++first;
        }
    return false;
}

template <typename InputIterator>
bool all(InputIterator first, InputIterator last)
{
    while (first != last)
        if (*first) {
            ++first;
        } else {
            return false;
        }
    return true;
}

template <typename InputIterator, typename UnaryPredicate>
bool all(InputIterator first, InputIterator last, UnaryPredicate pred)
{
    while (first != last)
        if (pred(*first)) {
            ++first;
        } else {
            return false;
        }
    return true;
}

template <typename InputIterator>
bool none_of(InputIterator first, InputIterator last)
{
    return !any(first, last);
}

template <typename InputIterator, typename UnaryPredicate>
bool none_of(InputIterator first, InputIterator last, UnaryPredicate pred)
{
    return !any(first, last, pred);
}

template <typename InputIterator, typename BinaryOperation>
BinaryOperation for_each_adjacent_pair(InputIterator first, InputIterator last, BinaryOperation op)
{
    typedef typename std::iterator_traits<InputIterator>::value_type ValueType;
    if (first == last) {
        return op;
    }
    ValueType value = *first;
    while (++first != last) {
        ValueType tmp = *first;
        op(value, tmp);
        value = tmp;
    }
    return op;
}

template <typename ForwardIterator, typename UnaryPredicate, typename UnaryFunction>
UnaryFunction for_each_if(ForwardIterator first, ForwardIterator last, UnaryPredicate pred, UnaryFunction func)
{
    return std::for_each(boost::make_filter_iterator(pred, first, last),
                         boost::make_filter_iterator(pred, last, last),
                         func);
}

//@{
/**
   Versions of std::set_intersection optimized for ForwardIterator's
*/
template <typename ForwardIterator, typename ForwardIterator2, typename OutputIterator, typename BinaryPredicate>
OutputIterator set_intersection(ForwardIterator first1, ForwardIterator last1, ForwardIterator2 first2, ForwardIterator2 last2, OutputIterator result)
{
    while (first1 != last1 && first2 != last2) {
        if (*first1 < *first2) {
            first1 = std::lower_bound(++first1, last1, *first2);
        } else if (*first2 < *first1) {
            first2 = std::lower_bound(++first2, last2, *first1);
        } else {
            *result = *first1;
            ++first1;
            ++first2;
            ++result;
        }
    }
    return result;
}

template <typename ForwardIterator, typename ForwardIterator2, typename OutputIterator, typename BinaryPredicate>
OutputIterator set_intersection(ForwardIterator first1, ForwardIterator last1, ForwardIterator2 first2, ForwardIterator2 last2, OutputIterator result, BinaryPredicate pred)
{
    while (first1 != last1 && first2 != last2) {
        if (pred(*first1, *first2)) {
            first1 = std::lower_bound(++first1, last1, *first2, pred);
        } else if (pred(*first2, *first1)) {
            first2 = std::lower_bound(++first2, last2, *first1, pred);
        } else {
            *result = *first1;
            ++first1;
            ++first2;
            ++result;
        }
    }
    return result;
}
//@}

template <typename ForwardIterator, typename ForwardIterator2, typename BinaryPredicate>
bool set_intersects(ForwardIterator first1,  ForwardIterator last1,
                    ForwardIterator2 first2, ForwardIterator2 last2,
                    BinaryPredicate pred)
{
    while (first1 != last1 && first2 != last2) {
        if (pred(*first1, *first2)) {
            first1 = std::lower_bound(++first1, last1, *first2, pred);
        } else if (pred(*first2, *first1)) {
            first2 = std::lower_bound(++first2, last2, *first1, pred);
        } else {
            return true;
        }
    }
    return false;
}

//@{
/*! Versions of std algorithms that take ranges */

template <typename C, typename V>
typename boost::range_iterator<C>::type
find(C &c, const V &v)
{
    return std::find(boost::begin(c), boost::end(c), v);
}

#if BOOST_VERSION < 103500
template <typename C, typename V>
typename boost::range_const_iterator<C>::type
find(const C &c, const V &v)
{
    return std::find(boost::begin(c), boost::end(c), v);
}
#endif

template <typename C, typename P>
typename boost::range_iterator<C>::type
find_if(C &c, P p)
{
    return std::find_if(boost::begin(c), boost::end(c), p);
}

#if BOOST_VERSION < 103500
template <typename C, typename P>
typename boost::range_const_iterator<C>::type
find_if(const C &c, P p)
{
    return std::find_if(boost::begin(c), boost::end(c), p);
}
#endif

template <typename C, typename V>
bool contains(const C &c, const V &v)
{
    return find(c, v) != boost::end(c);
}

template <typename C, typename P>
bool contains_if(const C &c, P p)
{
    return find_if(c, p) != boost::end(c);
}

template <typename C, typename V>
bool binary_search(const C &c, const V &v)
{
    return std::binary_search(boost::begin(c), boost::end(c), v);
}

template <typename C, typename V>
size_t count(const C &c, const V &v)
{
    return std::count(boost::begin(c), boost::end(c), v);
}

template <typename C, typename P>
size_t count_if(const C &c, P p)
{
    return std::count_if(boost::begin(c), boost::end(c), p);
}

template <typename O, typename I, typename P>
O transform(const I &i, P p)
{
    O o;
    std::transform(boost::begin(i), boost::end(i),
                   std::back_inserter(o), p);
    return o;
}

template <typename I, typename OutputIterator, typename P>
OutputIterator transform(const I &i, OutputIterator out, P p)
{
    return std::transform(boost::begin(i), boost::end(i), out, p);
}

template <typename O, typename I, typename P, typename F>
O transform_if(const I &i, P p, F f)
{
    O o;
    transform_if(boost::begin(i), boost::end(i),
                 std::back_inserter(o), p, f);
    return o;
}

template <typename V, typename I, typename F>
V accumulate_if(const I &i, F f, V v = V())
{
    return accumulate_if(boost::begin(i), boost::end(i), f, v);
}

template <typename V, typename I, typename F, typename B>
V accumulate_if(const I &i, F f, V v, B b)
{
    return accumulate_if(boost::begin(i), boost::end(i), f, v, b);
}

template <typename V, typename I, typename F>
V accumulate_transform(const I &i, F f, V v = V())
{
    return accumulate_transform(boost::begin(i), boost::end(i), f, v);
}

template <typename V, typename I, typename F, typename B>
V accumulate_transform(const I &i, F f, V v, B b)
{
    return accumulate_transform(boost::begin(i), boost::end(i), f, v, b);
}

template <typename V, typename I, typename F, typename P>
V accumulate_transform_if(const I &i, F f, P p, V v = V())
{
    return accumulate_transform_if(boost::begin(i), boost::end(i), f, p, v);
}

template <typename V, typename I, typename F, typename P, typename B>
V accumulate_transform_if(const I &i, F f, P p, V v, B b)
{
    return accumulate_transform_if(boost::begin(i), boost::end(i), f, p, v, b);
}

template <typename O, typename I>
O copy(const I &i)
{
    O o;
    std::copy(boost::begin(i), boost::end(i), std::back_inserter(o));
    return o;
}

template <typename O, typename I, typename P>
O copy_if(const I &i, P p)
{
    O o;
    kdtools::copy_if(boost::begin(i), boost::end(i), std::back_inserter(o), p);
    return o;
}

template <typename I, typename P>
P for_each(const I &i, P p)
{
    return std::for_each(boost::begin(i), boost::end(i), p);
}

template <typename I, typename P>
P for_each(I &i, P p)
{
    return std::for_each(boost::begin(i), boost::end(i), p);
}

template <typename C1, typename C2>
bool equal(const C1 &c1, const C2 &c2)
{
    return boost::size(c1) == boost::size(c2)
           && std::equal(boost::begin(c1), boost::end(c1),
                         boost::begin(c2));
}

template <typename C1, typename C2, typename P>
bool equal(const C1 &c1, const C2 &c2, P p)
{
    return boost::size(c1) == boost::size(c2)
           && std::equal(boost::begin(c1), boost::end(c1),
                         boost::begin(c2), p);
}

template <typename C, typename O1, typename O2, typename P>
std::pair<O1, O2> separate_if(const C &c, O1 o1, O2 o2, P p)
{
    return separate_if(boost::begin(c), boost::end(c), o1, o2, p);
}

//@}

template <typename C>
bool any(const C &c)
{
    return any(boost::begin(c), boost::end(c));
}

template <typename C, typename P>
bool any(const C &c, P p)
{
    return any(boost::begin(c), boost::end(c), p);
}

template <typename C>
bool all(const C &c)
{
    return all(boost::begin(c), boost::end(c));
}

template <typename C, typename P>
bool all(const C &c, P p)
{
    return all(boost::begin(c), boost::end(c), p);
}

template <typename C>
bool none_of(const C &c)
{
    return none_of(boost::begin(c), boost::end(c));
}

template <typename C, typename P>
bool none_of(const C &c, P p)
{
    return kdtools::none_of(boost::begin(c), boost::end(c), p);
}

template <typename C, typename B>
B for_each_adjacent_pair(const C &c, B b)
{
    return for_each_adjacent_pair(boost::begin(c), boost::end(c), b);
}

template <typename C, typename B>
B for_each_adjacent_pair(C &c, B b)
{
    return for_each_adjacent_pair(boost::begin(c), boost::end(c), b);
}

template <typename C, typename P, typename F>
P for_each_if(const C &c, P p, F f)
{
    return for_each_if(boost::begin(c), boost::end(c), p, f);
}

template <typename C, typename P, typename F>
P for_each_if(C &c, P p, F f)
{
    return for_each_if(boost::begin(c), boost::end(c), p, f);
}

template <typename C>
void sort(C &c)
{
    return std::sort(boost::begin(c), boost::end(c));
}

template <typename C, typename P>
void sort(C &c, P p)
{
    return std::sort(boost::begin(c), boost::end(c), p);
}

template <typename C>
C sorted(const C &c)
{
    C copy(c);
    kdtools::sort(copy);
    return copy;
}

template <typename C, typename P>
C sorted(const C &c, P p)
{
    C copy(c);
    kdtools::sort(copy, p);
    return copy;
}

}

#endif /* __KDTOOLSCORE_STL_UTIL_H__ */
