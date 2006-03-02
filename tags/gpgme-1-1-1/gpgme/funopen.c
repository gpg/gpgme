/* funopen.c - Replacement for funopen.
   Copyright (C) 2004 g10 Code GmbH

   This file is part of GPGME

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>

#ifdef HAVE_FOPENCOOKIE
FILE *
funopen(const void *cookie, cookie_read_function_t *readfn,
	cookie_write_function_t *writefn,
	cookie_seek_function_t *seekfn,
	cookie_close_function_t *closefn)
{
  cookie_io_functions_t io = { read: readfn, write: writefn, 
			       seek: seekfn, close: closefn };

  return fopencookie ((void *) cookie,
		      readfn ? (writefn ? "rw" : "r")
		      : (writefn ? "w" : ""), io);
}
#else
#error No known way to implement funopen.
#endif
