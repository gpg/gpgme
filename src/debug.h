/* debug.h - interface to debugging functions
   Copyright (C) 2002, 2004, 2005, 2007 g10 Code GmbH

   This file is part of GPGME.

   GPGME is free software; you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   GPGME is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#ifndef DEBUG_H
#define DEBUG_H

#include <string.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "gpgme.h"  /* Required for gpgme_error stuff.  */


/* Indirect stringification, requires __STDC__ to work.  */
#define STRINGIFY(v) #v
#define XSTRINGIFY(v) STRINGIFY(v)


/*
 * The debug levels.
 *
 * Note that TRACE_LOGBUFX uses the current debug level + 1.
 */

#define DEBUG_INIT	1
#define DEBUG_GLOBAL    2
#define DEBUG_CTX	3
#define DEBUG_ENGINE	4
#define DEBUG_DATA	5
#define DEBUG_ASSUAN	6
#define DEBUG_SYSIO	7


/* Remove path components from filenames (i.e. __FILE__) for cleaner
   logs. */
static inline const char *_gpgme_debug_srcname (const char *file)
                                                GPGME_GCC_A_PURE;

static inline const char *
_gpgme_debug_srcname (const char *file)
{
  const char *s = strrchr (file, '/');
  return s? s+1:file;
}

/* Initialization helper function; see debug.c.  */
int _gpgme_debug_set_debug_envvar (const char *value);

/* Called early to initialize the logging.  */
void _gpgme_debug_subsystem_init (void);

/* Log the formatted string FORMAT at debug level LEVEL or higher.  */
int  _gpgme_debug (int level, int mode,
                   const char *func, const char *tagname, const char *tagvalue,
                   const char *format, ...) GPGRT_ATTR_PRINTF(6,7);


/* Start a new debug line in *LINE, logged at level LEVEL or higher,
   and starting with the formatted string FORMAT.  */
void _gpgme_debug_begin (void **helper, int level, const char *format, ...);

/* Add the formatted string FORMAT to the debug line *LINE.  */
void _gpgme_debug_add (void **helper, const char *format, ...);

/* Finish construction of *LINE and send it to the debug output
   stream.  */
void _gpgme_debug_end (void **helper);

void _gpgme_debug_buffer (int lvl, const char *const fmt,
			  const char *const func, const char *const buffer,
			  size_t len);

void _gpgme_debug_frame_begin (void);
int  _gpgme_debug_frame_end (void);

static inline gpgme_error_t
_gpgme_trace_gpgme_error (gpgme_error_t err, const char *file, int line)
{
  _gpgme_debug (DEBUG_ENGINE, -1, NULL, NULL, NULL,
                "%s:%d: returning error: %s\n",
                _gpgme_debug_srcname (file), line, gpgme_strerror (err));
  return err;
}


/* Trace support.  */

/* FIXME: For now.  */
#define _gpgme_debug_trace() 1

#define _TRACE(lvl, name, tag)					\
  int _gpgme_trace_level = lvl;					\
  const char *const _gpgme_trace_func = name;			\
  const char *const _gpgme_trace_tagname = STRINGIFY (tag);	\
  void *_gpgme_trace_tag = (void *) (uintptr_t) tag; \
  _gpgme_debug_frame_begin ()

#define TRACE_BEG(lvl, name, tag, ...)			   \
  _TRACE (lvl, name, tag);						\
  _gpgme_debug (_gpgme_trace_level, 1,                                 \
                _gpgme_trace_func, _gpgme_trace_tagname, _gpgme_trace_tag, \
                __VA_ARGS__)

#define TRACE(lvl, name, tag, ...)                                      \
  _gpgme_debug_frame_begin (),						\
    _gpgme_debug (lvl, 0,                                              \
                  name, STRINGIFY (tag), (void *) (uintptr_t) tag,      \
                  __VA_ARGS__),                                         \
    _gpgme_debug_frame_end ()

#define TRACE_ERR(err)							\
  err == 0 ? (TRACE_SUC ("")) :						\
    (_gpgme_debug (_gpgme_trace_level, -1, NULL, NULL, NULL,           \
                    "%s:%d: error: %s <%s>\n",                          \
                    _gpgme_trace_func, __LINE__,  gpgme_strerror (err), \
                    gpgme_strsource (err)), _gpgme_debug_frame_end (), (err))


/* The cast to void suppresses GCC warnings.  */
#define TRACE_SYSRES(res)						\
  res >= 0 ? ((void) (TRACE_SUC ("result=%i", res)), (res)) :		\
    (_gpgme_debug (_gpgme_trace_level, -1, NULL, NULL, NULL,           \
                    "%s: error: %s\n",                                  \
                    _gpgme_trace_func, strerror (errno)),               \
     _gpgme_debug_frame_end (), (res))
#define TRACE_SYSERR(res)						\
  res == 0 ? ((void) (TRACE_SUC ("result=%i", res)), (res)) :		\
    (_gpgme_debug (_gpgme_trace_level, -1, NULL, NULL, NULL,           \
                    "%s: error: %s\n",                                  \
		   _gpgme_trace_func, strerror (res)),			\
     _gpgme_debug_frame_end (), (res))
#define TRACE_SYSERR_NR(res)						\
  do { res == 0 ? ((void) (TRACE_SUC ("result=%i", res)), (res)) :      \
      (_gpgme_debug (_gpgme_trace_level, -1, NULL, NULL, NULL,         \
                      "%s: error: %s\n",                                \
		   _gpgme_trace_func, strerror (res)),			\
     _gpgme_debug_frame_end ()); } while (0)

#define TRACE_SUC(...)							\
  _gpgme_debug (_gpgme_trace_level, 3,	_gpgme_trace_func, NULL, NULL,  \
                 __VA_ARGS__), _gpgme_debug_frame_end ()

#define TRACE_LOG(...)                                                  \
  _gpgme_debug (_gpgme_trace_level, 2,                                 \
                 _gpgme_trace_func, _gpgme_trace_tagname, _gpgme_trace_tag, \
                 __VA_ARGS__)

#define TRACE_LOGBUF(buf, len)					\
  _gpgme_debug_buffer (_gpgme_trace_level, "%s: check: %s",	\
		       _gpgme_trace_func, buf, len)

#define TRACE_LOGBUFX(buf, len)					\
  _gpgme_debug_buffer (_gpgme_trace_level+1, "%s: check: %s",	\
		       _gpgme_trace_func, buf, len)

#define TRACE_SEQ(hlp,fmt)						\
  _gpgme_debug_begin (&(hlp), _gpgme_trace_level,			\
                      "%s: check: %s=%p, " fmt, _gpgme_trace_func,	\
                      _gpgme_trace_tagname, _gpgme_trace_tag)
#define TRACE_ADD0(hlp,fmt) \
  _gpgme_debug_add (&(hlp), fmt)
#define TRACE_ADD1(hlp,fmt,a) \
  _gpgme_debug_add (&(hlp), fmt, (a))
#define TRACE_ADD2(hlp,fmt,a,b) \
  _gpgme_debug_add (&(hlp), fmt, (a), (b))
#define TRACE_ADD3(hlp,fmt,a,b,c) \
  _gpgme_debug_add (&(hlp), fmt, (a), (b), (c))
#define TRACE_END(hlp,fmt) \
  _gpgme_debug_add (&(hlp), fmt); \
  _gpgme_debug_end (&(hlp))
#define TRACE_ENABLED(hlp) (!!(hlp))

/* And finally a simple macro to trace the location of an error code.
   This macro is independent of the other trace macros and may be used
   without any preconditions.  */
#define trace_gpg_error(e) \
  _gpgme_trace_gpgme_error (gpg_error (e), __FILE__, __LINE__)


#endif	/* DEBUG_H */
