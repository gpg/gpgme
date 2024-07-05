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
#include <errno.h>

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
int  _gpgme_debug (void **line, int level, int mode,
                   const char *func, const char *tagname, const char *tagvalue,
                   const char *format, ...) GPGRT_ATTR_PRINTF(7,8);


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
  _gpgme_debug (NULL, DEBUG_ENGINE, -1, NULL, NULL, NULL,
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

/* Note: We can't protect this with a do-while block.  */
#define TRACE_BEG(lvl, name, tag, ...)                                  \
  _TRACE (lvl, name, tag);						\
  _gpgme_debug (NULL, _gpgme_trace_level, 1,                             \
                _gpgme_trace_func, _gpgme_trace_tagname, _gpgme_trace_tag, \
                __VA_ARGS__)

#define TRACE(lvl, name, tag, ...) do {                                 \
    _gpgme_debug_frame_begin ();					\
    _gpgme_debug (NULL, lvl, 0, name, STRINGIFY (tag), (void *)(uintptr_t)tag, \
                  __VA_ARGS__);                                         \
    _gpgme_debug_frame_end ();                                          \
  } while (0)


/* Trace a gpg-error and return it.  */
#define TRACE_ERR(err) \
    _trace_err ((err), _gpgme_trace_level, _gpgme_trace_func, __LINE__)
static inline gpg_error_t
_trace_err (gpg_error_t err, int lvl, const char *func, int line)
{
  if (!err)
    _gpgme_debug (NULL, lvl, 3, func, NULL, NULL, "");
  else
    _gpgme_debug (NULL, lvl, -1, NULL, NULL, NULL,
                  "%s:%d: error: %s <%s>\n",
                  func, line,  gpgme_strerror (err), gpgme_strsource (err));
  _gpgme_debug_frame_end ();
  return err;
}

/* Trace a system call result of type int and return it.  */
#define TRACE_SYSRES(res) \
    _trace_sysres ((res), _gpgme_trace_level, _gpgme_trace_func, __LINE__)
static inline int
_trace_sysres (int res, int lvl, const char *func, int line)
{
  if (res >= 0)
    _gpgme_debug (NULL, lvl, 3, func, NULL, NULL, "result=%d", res);
  else
    _gpgme_debug (NULL, lvl, -1, NULL, NULL, NULL,
                  "%s:%d: error: %s (%d)\n",
                  func, line,  strerror (errno), errno);
  _gpgme_debug_frame_end ();
  return res;
}

/* Trace a system call result of type gpgme_off_t and return it.  */
#define TRACE_SYSRES_OFF_T(res) \
    _trace_sysres_off_t ((res), _gpgme_trace_level, _gpgme_trace_func, __LINE__)
static inline gpgme_off_t
_trace_sysres_off_t (gpgme_off_t res, int lvl, const char *func, int line)
{
  if (res >= 0)
    _gpgme_debug (NULL, lvl, 3, func, NULL, NULL, "result=%zd", (size_t)res);
  else
    _gpgme_debug (NULL, lvl, -1, NULL, NULL, NULL,
                  "%s:%d: error: %s (%d)\n",
                  func, line,  strerror (errno), errno);
  _gpgme_debug_frame_end ();
  return res;
}

/* Trace a system call result of type gpgme_ssize_t and return it.  */
#define TRACE_SYSRES_SSIZE_T(res) \
    _trace_sysres_ssize_t ((res), _gpgme_trace_level, _gpgme_trace_func, __LINE__)
static inline gpgme_ssize_t
_trace_sysres_ssize_t (gpgme_ssize_t res, int lvl, const char *func, int line)
{
  if (res >= 0)
    _gpgme_debug (NULL, lvl, 3, func, NULL, NULL, "result=%zd", (ssize_t)res);
  else
    _gpgme_debug (NULL, lvl, -1, NULL, NULL, NULL,
                  "%s:%d: error: %s (%d)\n",
                  func, line,  strerror (errno), errno);
  _gpgme_debug_frame_end ();
  return res;
}

/* Trace a system call error and return it.  */
#define TRACE_SYSERR(rc) \
    _trace_syserr ((rc), _gpgme_trace_level, _gpgme_trace_func, __LINE__)
static inline int
_trace_syserr (int rc, int lvl, const char *func, int line)
{
  if (!rc)
    _gpgme_debug (NULL, lvl, 3, func, NULL, NULL, "result=0");
  else
    _gpgme_debug (NULL, lvl, -1, NULL, NULL, NULL,
                  "%s:%d: error: %s (%d)\n",
                  func, line, strerror (rc), rc);
  _gpgme_debug_frame_end ();
  return rc;
}

#define TRACE_SUC(...) do {                                             \
    _gpgme_debug (NULL, _gpgme_trace_level, 3, _gpgme_trace_func, NULL, NULL, \
                  __VA_ARGS__);                                         \
    _gpgme_debug_frame_end ();                                          \
  } while (0)

#define TRACE_LOG(...) do {                                             \
    _gpgme_debug (NULL, _gpgme_trace_level, 2,                           \
                  _gpgme_trace_func, _gpgme_trace_tagname, _gpgme_trace_tag, \
                  __VA_ARGS__);                                         \
  } while (0)

#define TRACE_LOGBUF(buf, len) do {                             \
    _gpgme_debug_buffer (_gpgme_trace_level, "%s: check: %s",	\
                         _gpgme_trace_func, buf, len);          \
  } while (0)

#define TRACE_LOGBUFX(buf, len) do {                                    \
    _gpgme_debug_buffer (_gpgme_trace_level+1, "%s: check: %s",         \
                         _gpgme_trace_func, buf, len); \
  } while (0)

#define TRACE_SEQ(hlp,...) do {						      \
    _gpgme_debug (&(hlp), _gpgme_trace_level, 2, _gpgme_trace_func,            \
                         _gpgme_trace_tagname, _gpgme_trace_tag, __VA_ARGS__); \
  } while (0)

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
