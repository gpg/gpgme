/* assuan-logging.c - Default logging function.
 *	Copyright (C) 2002, 2003 Free Software Foundation, Inc.
 *
 * This file is part of Assuan.
 *
 * Assuan is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Assuan is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA 
 */

#include "assuan-defs.h"
#include <stdio.h>

static FILE *_assuan_log;

void
assuan_set_assuan_log_stream (FILE *fp)
{
  _assuan_log = fp;
}

FILE *
assuan_get_assuan_log_stream (void)
{
  return _assuan_log ? _assuan_log : stderr;
}

const char *
assuan_get_assuan_log_prefix (void)
{
  return "";
}
