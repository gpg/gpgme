/* debug.h - interface to debugging functions
 *      Copyright (C) 2002 g10 Code GmbH
 *
 * This file is part of GPGME.
 *
 * GPGME is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GPGME is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifndef DEBUG_H
#define DEBUG_H

/* Log the formatted string FORMAT at debug level LEVEL or higher.  */
void _gpgme_debug (int level, const char *format, ...);

/* Start a new debug line in *LINE, logged at level LEVEL or higher,
   and starting with the formatted string FORMAT.  */
void _gpgme_debug_begin (void **helper, int level, const char *format, ...);

/* Add the formatted string FORMAT to the debug line *LINE.  */
void _gpgme_debug_add (void **helper, const char *format, ...);

/* Finish construction of *LINE and send it to the debug output
   stream.  */
void _gpgme_debug_end (void **helper);

/* Indirect stringification, requires __STDC__ to work.  */
#define STRINGIFY(v) #v
#define XSTRINGIFY(v) STRINGIFY(v)

#if 0
/* Only works in GNU.  */
#define DEBUG(fmt, arg...) \
  _gpgme_debug (1, "%s:%s: " fmt, __FILE__, XSTRINGIFY (__LINE__) , ##arg)
#define DEBUG_BEGIN(hlp, lvl, fmt, arg...) \
  _gpgme_debug_begin (&(hlp), lvl, "%s:%s: " fmt, __FILE__, \
		      XSTRINGIFY (__LINE__) , ##arg)
#define DEBUG_ADD(hlp, fmt, arg...) \
  _gpgme_debug_add (&(hlp), fmt , ##arg)
#define DEBUG_END(hlp, fmt, arg...) \
  _gpgme_debug_add (&(hlp), fmt , ##arg); \
  _gpgme_debug_end (&(hlp))
#elif 0
/* Only works in C99.  */
#define DEBUG0(fmt) \
  _gpgme_debug (1, "%s:%s: " fmt, __FILE__, XSTRINGIFY (__LINE__))
#define DEBUG(fmt, ...) \
  _gpgme_debug (1, "%s:%s: " fmt, __FILE__, XSTRINGIFY (__LINE__), __VA_ARGS__)
#define DEBUG_BEGIN(hlp, lvl, fmt) \
  _gpgme_debug_begin (&(hlp), lvl, "%s:%s: " fmt, __FILE__, \
		      XSTRINGIFY (__LINE__))
#define DEBUG_BEGINX(hlp, lvl, fmt, ...) \
  _gpgme_debug_begin (&(hlp), lvl, "%s:%s: " fmt, __FILE__, \
		      XSTRINGIFY (__LINE__), __VA_ARGS__)
#define DEBUG_ADD0(hlp, fmt) \
  _gpgme_debug_add (&(hlp), fmt)
#define DEBUG_ADD(hlp, fmt, ...) \
  _gpgme_debug_add (&(hlp), fmt, __VA_ARGS__)
#define DEBUG_END(hlp, fmt) \
  _gpgme_debug_add (&(hlp), fmt); \
  _gpgme_debug_end (&(hlp))
#define DEBUG_ENDX(hlp, fmt, ...) \
  _gpgme_debug_add (&(hlp), fmt, __VA_ARGS__); \
  _gpgme_debug_end (&(hlp))
#else
/* This finally works everywhere, horror.  */
#define DEBUG0(fmt) \
  _gpgme_debug (1, "%s:%s: " fmt, __FILE__, XSTRINGIFY (__LINE__))
#define DEBUG1(fmt,a) \
  _gpgme_debug (1, "%s:%s: " fmt, __FILE__, XSTRINGIFY (__LINE__), (a))
#define DEBUG2(fmt,a,b) \
  _gpgme_debug (1, "%s:%s: " fmt, __FILE__, XSTRINGIFY (__LINE__), (a), (b))
#define DEBUG3(fmt,a,b,c) \
  _gpgme_debug (1, "%s:%s: " fmt, __FILE__, XSTRINGIFY (__LINE__), (a), (b), \
		(c))
#define DEBUG4(fmt,a,b,c,d) \
  _gpgme_debug (1, "%s:%s: " fmt, __FILE__, XSTRINGIFY (__LINE__), (a), (b), \
		(c), (d))
#define DEBUG5(fmt,a,b,c,d,e) \
  _gpgme_debug (1, "%s:%s: " fmt, __FILE__, XSTRINGIFY (__LINE__), (a), (b), \
		(c), (d), (e))
#define DEBUG_BEGIN(hlp,lvl,fmt) \
  _gpgme_debug_begin (&(hlp), lvl, "%s:%s: " fmt, __FILE__, XSTRINGIFY (__LINE__))
#define DEBUG_ADD0(hlp,fmt) \
  _gpgme_debug_add (&(hlp), fmt)
#define DEBUG_ADD1(hlp,fmt,a) \
  _gpgme_debug_add (&(hlp), fmt, (a))
#define DEBUG_ADD2(hlp,fmt,a,b) \
  _gpgme_debug_add (&(hlp), fmt, (a), (b))
#define DEBUG_ADD3(hlp,fmt,a,b,c) \
  _gpgme_debug_add (&(hlp), fmt, (a), (b), (c))
#define DEBUG_END(hlp,fmt) \
  _gpgme_debug_add (&(hlp), fmt); \
  _gpgme_debug_end (&(hlp))
#endif

#define DEBUG_ENABLED(hlp) (!!(hlp))

#endif	/* DEBUG_H */
