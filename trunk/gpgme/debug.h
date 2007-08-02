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

/* Indirect stringification, requires __STDC__ to work.  */
#define STRINGIFY(v) #v
#define XSTRINGIFY(v) STRINGIFY(v)


/* The debug levels.  */

#define DEBUG_INIT	1
#define DEBUG_CTX	2
#define DEBUG_ENGINE	3
#define DEBUG_DATA	4
#define DEBUG_ASSUAN	5
#define DEBUG_SYSIO	6


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

/* Called early to initialize the logging.  */
void _gpgme_debug_subsystem_init (void);

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

void _gpgme_debug_buffer (int lvl, const char *const fmt,
			  const char *const func, const char *const tagname,
			  void *tag, const char *const buffer, size_t len);


/* Trace support.  */

/* FIXME: For now.  */
#define _gpgme_debug_trace() 1

#define _TRACE(lvl, name, tag)					\
  int _gpgme_trace_level = lvl;					\
  const char *const _gpgme_trace_func = name;			\
  const char *const _gpgme_trace_tagname = STRINGIFY (tag);	\
  void *_gpgme_trace_tag = (void *) tag

#define TRACE_BEG(lvl, name, tag)			   \
  _TRACE (lvl, name, tag);				   \
  _gpgme_debug (_gpgme_trace_level, "%s (%s=0x%x): enter\n", \
		_gpgme_trace_func, _gpgme_trace_tagname,   \
		_gpgme_trace_tag), 0
#define TRACE_BEG0(lvl, name, tag, fmt)					\
  _TRACE (lvl, name, tag);						\
  _gpgme_debug (_gpgme_trace_level, "%s (%s=0x%x): enter: " fmt "\n",	\
		_gpgme_trace_func, _gpgme_trace_tagname,		\
		_gpgme_trace_tag), 0
#define TRACE_BEG1(lvl, name, tag, fmt, arg1)				\
  _TRACE (lvl, name, tag);						\
  _gpgme_debug (_gpgme_trace_level, "%s (%s=0x%x): enter: " fmt "\n",	\
		_gpgme_trace_func, _gpgme_trace_tagname,		\
		_gpgme_trace_tag, arg1), 0
#define TRACE_BEG2(lvl, name, tag, fmt, arg1, arg2)		    \
  _TRACE (lvl, name, tag);					    \
  _gpgme_debug (_gpgme_trace_level, "%s (%s=0x%x): enter: " fmt "\n", \
		_gpgme_trace_func, _gpgme_trace_tagname,	    \
		_gpgme_trace_tag, arg1, arg2), 0
#define TRACE_BEG3(lvl, name, tag, fmt, arg1, arg2, arg3)	    \
  _TRACE (lvl, name, tag);					    \
  _gpgme_debug (_gpgme_trace_level, "%s (%s=0x%x): enter: " fmt "\n", \
		_gpgme_trace_func, _gpgme_trace_tagname,	    \
		_gpgme_trace_tag, arg1, arg2, arg3), 0
#define TRACE_BEG4(lvl, name, tag, fmt, arg1, arg2, arg3, arg4)	    \
  _TRACE (lvl, name, tag);					    \
  _gpgme_debug (_gpgme_trace_level, "%s (%s=0x%x): enter: " fmt "\n", \
		_gpgme_trace_func, _gpgme_trace_tagname,	    \
		_gpgme_trace_tag, arg1, arg2, arg3, arg4), 0

#define TRACE(lvl, name, tag)						\
  _gpgme_debug (lvl, "%s (%s=0x%x): call\n",				\
		name, STRINGIFY (tag), (void *) tag), 0
#define TRACE0(lvl, name, tag, fmt)					\
  _gpgme_debug (lvl, "%s (%s=0x%x): call: " fmt "\n",			\
		name, STRINGIFY (tag), (void *) tag), 0
#define TRACE1(lvl, name, tag, fmt, arg1)			       \
  _gpgme_debug (lvl, "%s (%s=0x%x): call: " fmt "\n",		       \
		name, STRINGIFY (tag), (void *) tag, arg1), 0
#define TRACE2(lvl, name, tag, fmt, arg1, arg2)			       \
  _gpgme_debug (lvl, "%s (%s=0x%x): call: " fmt "\n",		       \
		name, STRINGIFY (tag), (void *) tag, arg1, arg2), 0
#define TRACE3(lvl, name, tag, fmt, arg1, arg2, arg3)		       \
  _gpgme_debug (lvl, "%s (%s=0x%x): call: " fmt "\n",		       \
		name, STRINGIFY (tag), (void *) tag, arg1, arg2,       \
		arg3), 0
#define TRACE6(lvl, name, tag, fmt, arg1, arg2, arg3, arg4, arg5, arg6)	\
  _gpgme_debug (lvl, "%s (%s=0x%x): call: " fmt "\n",			\
		name, STRINGIFY (tag), (void *) tag, arg1, arg2, arg3,	\
		arg4, arg5, arg6), 0

#define TRACE_ERR(err)							\
  err == 0 ? (TRACE_SUC ()) :						\
    (_gpgme_debug (_gpgme_trace_level, "%s (%s=0x%x): error: %s <%s>\n",	\
		   _gpgme_trace_func, _gpgme_trace_tagname,		\
		   _gpgme_trace_tag, gpgme_strerror (err),		\
		   gpgme_strsource (err)), (err))
/* The cast to void suppresses GCC warnings.  */
#define TRACE_SYSRES(res)						\
  res >= 0 ? ((void) (TRACE_SUC1 ("result=%i", res)), (res)) :		\
    (_gpgme_debug (_gpgme_trace_level, "%s (%s=0x%x): error: %s\n",	\
		   _gpgme_trace_func, _gpgme_trace_tagname,		\
		   _gpgme_trace_tag, strerror (errno)), (res))
#define TRACE_SYSERR(res)						\
  res == 0 ? ((void) (TRACE_SUC1 ("result=%i", res)), (res)) :		\
    (_gpgme_debug (_gpgme_trace_level, "%s (%s=0x%x): error: %s\n",	\
		   _gpgme_trace_func, _gpgme_trace_tagname,		\
		   _gpgme_trace_tag, strerror (res)), (res))

#define TRACE_SUC()						 \
  _gpgme_debug (_gpgme_trace_level, "%s (%s=0x%x): leave\n",       \
		_gpgme_trace_func, _gpgme_trace_tagname,	 \
		_gpgme_trace_tag), 0
#define TRACE_SUC0(fmt)							\
  _gpgme_debug (_gpgme_trace_level, "%s (%s=0x%x): leave: " fmt "\n",	\
		_gpgme_trace_func, _gpgme_trace_tagname,		\
		_gpgme_trace_tag), 0
#define TRACE_SUC1(fmt, arg1)						\
  _gpgme_debug (_gpgme_trace_level, "%s (%s=0x%x): leave: " fmt "\n",	\
		_gpgme_trace_func, _gpgme_trace_tagname,		\
		_gpgme_trace_tag, arg1), 0
#define TRACE_SUC2(fmt, arg1, arg2)					\
  _gpgme_debug (_gpgme_trace_level, "%s (%s=0x%x): leave: " fmt "\n",	\
		_gpgme_trace_func, _gpgme_trace_tagname,		\
		_gpgme_trace_tag, arg1, arg2), 0
#define TRACE_SUC5(fmt, arg1, arg2, arg3, arg4, arg5)			\
  _gpgme_debug (_gpgme_trace_level, "%s (%s=0x%x): leave: " fmt "\n",	\
		_gpgme_trace_func, _gpgme_trace_tagname,		\
		_gpgme_trace_tag, arg1, arg2, arg3, arg4, arg5), 0

#define TRACE_LOG(fmt)							\
  _gpgme_debug (_gpgme_trace_level, "%s (%s=0x%x): check: " fmt "\n",	\
		_gpgme_trace_func, _gpgme_trace_tagname,		\
		_gpgme_trace_tag), 0
#define TRACE_LOG1(fmt, arg1)						\
  _gpgme_debug (_gpgme_trace_level, "%s (%s=0x%x): check: " fmt "\n",	\
		_gpgme_trace_func, _gpgme_trace_tagname,		\
		_gpgme_trace_tag, arg1), 0
#define TRACE_LOG2(fmt, arg1, arg2)				    \
  _gpgme_debug (_gpgme_trace_level, "%s (%s=0x%x): check: " fmt "\n", \
		_gpgme_trace_func, _gpgme_trace_tagname,	    \
		_gpgme_trace_tag, arg1, arg2), 0
#define TRACE_LOG3(fmt, arg1, arg2, arg3)			    \
  _gpgme_debug (_gpgme_trace_level, "%s (%s=0x%x): check: " fmt "\n", \
		_gpgme_trace_func, _gpgme_trace_tagname,	    \
		_gpgme_trace_tag, arg1, arg2, arg3), 0
#define TRACE_LOG4(fmt, arg1, arg2, arg3, arg4)			    \
  _gpgme_debug (_gpgme_trace_level, "%s (%s=0x%x): check: " fmt "\n", \
		_gpgme_trace_func, _gpgme_trace_tagname,	    \
		_gpgme_trace_tag, arg1, arg2, arg3, arg4), 0
#define TRACE_LOG6(fmt, arg1, arg2, arg3, arg4, arg5, arg6)	    \
  _gpgme_debug (_gpgme_trace_level, "%s (%s=0x%x): check: " fmt "\n", \
		_gpgme_trace_func, _gpgme_trace_tagname,	    \
		_gpgme_trace_tag, arg1, arg2, arg3, arg4, arg5,	    \
		arg6), 0

#define TRACE_LOGBUF(buf, len)						\
  _gpgme_debug_buffer (_gpgme_trace_level, "%s (%s=0x%x): check: %s",	\
		       _gpgme_trace_func, _gpgme_trace_tagname,		\
		       _gpgme_trace_tag, buf, len)

#define TRACE_SEQ(hlp,fmt)						\
  _gpgme_debug_begin (&(hlp), _gpgme_trace_level,			\
		      "%s (%s=0x%x): check: " fmt,			\
		      _gpgme_trace_func, _gpgme_trace_tagname,		\
		      _gpgme_trace_tag)
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

#endif	/* DEBUG_H */
