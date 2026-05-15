/* pinentry.c - Dummy pinentry program for testing
 * Copyright (C) 2026  g10 Code GmbH
 *
 * This file is part of GPGME.
 *
 * GPGME is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * GPGME is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <https://gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <stdio.h>
#include <string.h>

#define MAX_LINE 256

int
main (int argc, const char *argv[])
{
  char line[MAX_LINE+1];

  (void)argc;
  (void)argv;
  puts ("OK Your orders please");
  fflush (stdout);
  while (fgets (line, sizeof (line), stdin))
    {
      if (strncmp (line, "GETPIN", 6) == 0)
        puts ("D abc");
      else if (strncmp (line, "BYE", 3) == 0)
        break;
      puts ("OK");
      fflush (stdout);
    }
  puts ("OK closing connection");
  fflush (stdout);
  return 0;
}
