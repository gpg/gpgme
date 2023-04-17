/* gpgme-w32spawn.c - Wrapper to spawn a process under Windows.
 * Copyright (C) 2008 g10 Code GmbH
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


#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif
#include <stdint.h>
#include <process.h>

#include "priv-io.h"

/* #define DEBUG_TO_FILE 1 */


/* Name of this program.  */
#define PGM "gpgme-w32spawn"

#ifdef DEBUG_TO_FILE
static FILE *mystderr;
#else
#define mystderr stderr
#endif



static char *
build_commandline (char **argv)
{
  int i;
  int n = 0;
  char *buf;
  char *p;

  /* We have to quote some things because under Windows the program
     parses the commandline and does some unquoting.  We enclose the
     whole argument in double-quotes, and escape literal double-quotes
     as well as backslashes with a backslash.  We end up with a
     trailing space at the end of the line, but that is harmless.  */
  for (i = 0; argv[i]; i++)
    {
      p = argv[i];
      /* The leading double-quote.  */
      n++;
      while (*p)
	{
	  /* An extra one for each literal that must be escaped.  */
	  if (*p == '\\' || *p == '"')
	    n++;
	  n++;
	  p++;
	}
      /* The trailing double-quote and the delimiter.  */
      n += 2;
    }
  /* And a trailing zero.  */
  n++;

  buf = p = malloc (n);
  if (!buf)
    return NULL;
  for (i = 0; argv[i]; i++)
    {
      char *argvp = argv[i];

      *(p++) = '"';
      while (*argvp)
	{
	  if (*argvp == '\\' || *argvp == '"')
	    *(p++) = '\\';
	  *(p++) = *(argvp++);
	}
      *(p++) = '"';
      *(p++) = ' ';
    }
  *(p++) = 0;

  return buf;
}


int
my_spawn (char **argv, struct spawn_fd_item_s *fd_list, unsigned int flags)
{
  SECURITY_ATTRIBUTES sec_attr;
  PROCESS_INFORMATION pi =
    {
      NULL,      /* returns process handle */
      0,         /* returns primary thread handle */
      0,         /* returns pid */
      0          /* returns tid */
    };
  STARTUPINFO si;
  char *envblock = NULL;
  int cr_flags = CREATE_DEFAULT_ERROR_MODE
    | GetPriorityClass (GetCurrentProcess ());
  int i;
  char *arg_string;
  int duped_stdin = 0;
  int duped_stdout = 0;
  int duped_stderr = 0;
  HANDLE hnul = INVALID_HANDLE_VALUE;

  i = 0;
  while (argv[i])
    {
      fprintf (mystderr, PGM": argv[%2i] = %s\n", i, argv[i]);
      i++;
    }

  memset (&sec_attr, 0, sizeof sec_attr);
  sec_attr.nLength = sizeof sec_attr;
  sec_attr.bInheritHandle = FALSE;

  arg_string = build_commandline (argv);
  if (!arg_string)
    return -1;

  memset (&si, 0, sizeof si);
  si.cb = sizeof (si);
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = (flags & IOSPAWN_FLAG_SHOW_WINDOW) ? SW_SHOW : SW_HIDE;
  si.hStdInput = GetStdHandle (STD_INPUT_HANDLE);
  si.hStdOutput = GetStdHandle (STD_OUTPUT_HANDLE);
  si.hStdError = GetStdHandle (STD_ERROR_HANDLE);

  for (i = 0; fd_list[i].fd != -1; i++)
    {
      /* The handle already is inheritable.  */
      if (fd_list[i].dup_to == 0)
	{
	  si.hStdInput = (HANDLE) fd_list[i].peer_name;
	  duped_stdin = 1;
	  fprintf (mystderr, PGM": dup 0x%x to stdin\n", fd_list[i].peer_name);
        }
      else if (fd_list[i].dup_to == 1)
	{
	  si.hStdOutput = (HANDLE) fd_list[i].peer_name;
	  duped_stdout = 1;
	  fprintf (mystderr, PGM": dup 0x%x to stdout\n", fd_list[i].peer_name);
        }
      else if (fd_list[i].dup_to == 2)
	{
	  si.hStdError = (HANDLE) fd_list[i].peer_name;
	  duped_stderr = 1;
	  fprintf (mystderr, PGM":dup 0x%x to stderr\n", fd_list[i].peer_name);
        }
    }

  if (!duped_stdin || !duped_stdout || !duped_stderr)
    {
      SECURITY_ATTRIBUTES sa;

      memset (&sa, 0, sizeof sa);
      sa.nLength = sizeof sa;
      sa.bInheritHandle = TRUE;
      hnul = CreateFile ("nul",
			 GENERIC_READ|GENERIC_WRITE,
			 FILE_SHARE_READ|FILE_SHARE_WRITE,
			 &sa,
			 OPEN_EXISTING,
			 FILE_ATTRIBUTE_NORMAL,
			 NULL);
      if (hnul == INVALID_HANDLE_VALUE)
	{
	  free (arg_string);
	  /* FIXME: Should translate the error code.  */
	  errno = EIO;
	  return -1;
        }
      /* Make sure that the process has a connected stdin.  */
      if (!duped_stdin)
	si.hStdInput = hnul;
      /* Make sure that the process has a connected stdout.  */
      if (!duped_stdout)
	si.hStdOutput = hnul;
      /* We normally don't want all the normal output.  */
      if (!duped_stderr)
	si.hStdError = hnul;
    }

  cr_flags |= CREATE_SUSPENDED;
  if (!CreateProcessA (argv[0],
		       arg_string,
		       &sec_attr,     /* process security attributes */
		       &sec_attr,     /* thread security attributes */
		       TRUE,          /* inherit handles */
		       cr_flags,      /* creation flags */
		       envblock,      /* environment */
		       NULL,          /* use current drive/directory */
		       &si,           /* startup information */
		       &pi))          /* returns process information */
    {
      free (arg_string);
      fprintf (mystderr, PGM": spawn error: %d\n", (int)GetLastError ());
      /* FIXME: Should translate the error code.  */
      errno = EIO;
      return -1;
    }

  free (arg_string);

  /* Close the /dev/nul handle if used.  */
  if (hnul != INVALID_HANDLE_VALUE)
    CloseHandle (hnul);

  for (i = 0; fd_list[i].fd != -1; i++)
    CloseHandle ((HANDLE) fd_list[i].fd);

  if (flags & IOSPAWN_FLAG_ALLOW_SET_FG)
    {
      static int initialized;
      static BOOL (WINAPI * func)(DWORD);
      void *handle;

      if (!initialized)
        {
          /* Available since W2000; thus we dynload it.  */
          initialized = 1;
          handle = LoadLibrary ("user32.dll");
          if (handle)
            {
              func = GetProcAddress (handle, "AllowSetForegroundWindow");
              if (!func)
                FreeLibrary (handle);
            }
        }

      if (func)
        {
          int rc = func (pi.dwProcessId);
          fprintf (mystderr, PGM": AllowSetForegroundWindow(%d): rc=%d\n",
                   (int)pi.dwProcessId, rc);
        }
    }

  ResumeThread (pi.hThread);
  CloseHandle (pi.hThread);
  CloseHandle (pi.hProcess);

  return 0;
}


#define MAX_TRANS 10

int
translate_get_from_file (const char *trans_file,
			 struct spawn_fd_item_s *fd_list,
                         unsigned int *r_flags)
{
  /* Hold roughly MAX_TRANS triplets of 64 bit numbers in hex
     notation: "0xFEDCBA9876543210".  10*19*4 - 1 = 759.  This plans
     ahead for a time when a HANDLE is 64 bit.  */
#define BUFFER_MAX 810

  char line[BUFFER_MAX + 1];
  char *linep;
  int idx;
  int res;
  int fd;

  *r_flags = 0;

  fd = open (trans_file, O_RDONLY);
  if (fd < 0)
    return -1;

  /* We always read one line from stdin.  */
  res = read (fd, line, BUFFER_MAX);
  close (fd);
  if (res < 0)
    return -1;

  line[BUFFER_MAX] = '\0';
  linep = strchr (line, '\n');
  if (linep)
    {
      if (linep > line && linep[-1] == '\r')
        linep--;
      *linep = '\0';
    }
  linep = line;

  /* Now start to read mapping pairs.  */
  for (idx = 0; idx < MAX_TRANS; idx++)
    {
      unsigned long from;
      long dup_to;
      unsigned long to;
      unsigned long loc;
      char *tail;

      /* FIXME: Maybe could use scanf.  */
      while (isspace (*((unsigned char *)linep)))
	linep++;
      if (*linep == '\0')
	break;
      if (!idx && *linep == '~')
        {
          /* Spawn flags have been passed.  */
          linep++;
          *r_flags = strtoul (linep, &tail, 0);
          if (tail == NULL || ! (*tail == '\0' || isspace (*tail)))
            break;
          linep = tail;

          while (isspace (*((unsigned char *)linep)))
            linep++;
          if (*linep == '\0')
            break;
        }

      from = strtoul (linep, &tail, 0);
      if (tail == NULL || ! (*tail == '\0' || isspace (*tail)))
	break;
      linep = tail;

      while (isspace (*linep))
	linep++;
      if (*linep == '\0')
	break;
      dup_to = strtol (linep, &tail, 0);
      if (tail == NULL || ! (*tail == '\0' || isspace (*tail)))
	break;
      linep = tail;

      while (isspace (*linep))
	linep++;
      if (*linep == '\0')
	break;
      to = strtoul (linep, &tail, 0);
      if (tail == NULL || ! (*tail == '\0' || isspace (*tail)))
	break;
      linep = tail;

      while (isspace (*linep))
	linep++;
      if (*linep == '\0')
	break;
      loc = strtoul (linep, &tail, 0);
      if (tail == NULL || ! (*tail == '\0' || isspace (*tail)))
	break;
      linep = tail;

      fd_list[idx].fd = from;
      fd_list[idx].dup_to = dup_to;
      fd_list[idx].peer_name = to;
      fd_list[idx].arg_loc = loc;
    }
  fd_list[idx].fd = -1;
  fd_list[idx].dup_to = -1;
  fd_list[idx].peer_name = -1;
  fd_list[idx].arg_loc = 0;
  return 0;
}


/* Read the translated handles from TRANS_FILE and do a substitution
   in ARGV.  Returns the new argv and the list of substitutions in
   FD_LIST (which must be MAX_TRANS+1 large).  */
char **
translate_handles (const char *trans_file, const char * const *argv,
		   struct spawn_fd_item_s *fd_list, unsigned int *r_flags)
{
  int res;
  int idx;
  int n_args;
  char **args;

  res = translate_get_from_file (trans_file, fd_list, r_flags);
  if (res < 0)
    return NULL;

  for (idx = 0; argv[idx]; idx++)
    ;
  args = malloc (sizeof (*args) * (idx + 1));
  for (idx = 0; argv[idx]; idx++)
    {
      args[idx] = strdup (argv[idx]);
      if (!args[idx])
	return NULL;
    }
  args[idx] = NULL;
  n_args = idx;

  for (idx = 0; fd_list[idx].fd != -1; idx++)
    {
      char buf[25];
      int aidx;

      aidx = fd_list[idx].arg_loc;
      if (aidx == 0)
	continue;

      if (aidx >= n_args)
        {
	  fprintf (mystderr, PGM": translation file does not match args\n");
          return NULL;
        }

      args[aidx] = malloc (sizeof (buf));
      /* We currently disable translation for stdin/stdout/stderr.  We
	 assume that the spawned program handles 0/1/2 specially
	 already.  FIXME: Check if this is true.  */
      if (!args[idx] || fd_list[idx].dup_to != -1)
	return NULL;

      /* NOTE: Here is the part where application specific knowledge
	 comes in.  GPGME/GnuPG uses two forms of descriptor
	 specification, a plain number and a "-&" form.  */
      if (argv[aidx][0] == '-' && argv[aidx][1] == '&')
	snprintf (args[aidx], sizeof (buf), "-&%d", fd_list[idx].peer_name);
      else
	snprintf (args[aidx], sizeof (buf), "%d", fd_list[idx].peer_name);
    }
  return args;
}


int
main (int argc, const char * const *argv)
{
  int rc = 0;
  char **argv_spawn;
  struct spawn_fd_item_s fd_list[MAX_TRANS + 1];
  unsigned int flags;

  if (argc < 3)
    {
      rc = 2;
      goto leave;
    }

#ifdef DEBUG_TO_FILE
  mystderr = fopen ("h:/gpgme-w32spawn.log", "w");
#endif

  argv_spawn = translate_handles (argv[1], &argv[2], fd_list, &flags);
  if (!argv_spawn)
    {
      rc = 2;
      goto leave;
    }

  /* Using execv does not replace the existing program image, but
     spawns a new one and daemonizes it, confusing the command line
     interpreter.  So we have to use spawnv.  */
  rc = my_spawn (argv_spawn, fd_list, flags);
  if (rc < 0)
    {
      fprintf (mystderr, PGM": executing `%s' failed: %s\n",
	       argv[0], strerror (errno));
      rc = 2;
      goto leave;
    }

 leave:
  if (rc)
    fprintf (mystderr, PGM": internal error\n");
  /* Always try to delete the temporary file.  */
  if (argc >= 2)
    {
      if (DeleteFile (argv[1]) == 0)
	fprintf (mystderr, PGM": failed to delete %s: ec=%ld\n",
		 argv[1], GetLastError ());
    }
  return rc;
}
