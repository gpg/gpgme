/* w32-util.c - Utility functions for the W32 API
   Copyright (C) 1999 Free Software Foundation, Inc
   Copyright (C) 2001 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003, 2004, 2007 g10 Code GmbH

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <windows.h>
#include <shlobj.h>
#include <io.h>

#include "util.h"
#include "sema.h"
#include "debug.h"

DEFINE_STATIC_LOCK (get_path_lock);


#define RTLD_LAZY 0

static __inline__ void *
dlopen (const char * name, int flag)
{
  void * hd = LoadLibrary (name);
  return hd;
}

static __inline__ void *
dlsym (void * hd, const char * sym)
{
  if (hd && sym)
    {
      void * fnc = GetProcAddress (hd, sym);
      if (!fnc)
        return NULL;
      return fnc;
    }
  return NULL;
}

static __inline__ int
dlclose (void * hd)
{
  if (hd)
    {
      FreeLibrary (hd);
      return 0;
    }
  return -1;
}  


/* Return a string from the W32 Registry or NULL in case of error.
   Caller must release the return value.  A NULL for root is an alias
   for HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE in turn. */
static char *
read_w32_registry_string (const char *root, const char *dir, const char *name)
{
  HKEY root_key, key_handle;
  DWORD n1, nbytes, type;
  char *result = NULL;
	
  if ( !root )
    root_key = HKEY_CURRENT_USER;
  else if ( !strcmp( root, "HKEY_CLASSES_ROOT" ) )
    root_key = HKEY_CLASSES_ROOT;
  else if ( !strcmp( root, "HKEY_CURRENT_USER" ) )
    root_key = HKEY_CURRENT_USER;
  else if ( !strcmp( root, "HKEY_LOCAL_MACHINE" ) )
    root_key = HKEY_LOCAL_MACHINE;
  else if ( !strcmp( root, "HKEY_USERS" ) )
    root_key = HKEY_USERS;
  else if ( !strcmp( root, "HKEY_PERFORMANCE_DATA" ) )
    root_key = HKEY_PERFORMANCE_DATA;
  else if ( !strcmp( root, "HKEY_CURRENT_CONFIG" ) )
    root_key = HKEY_CURRENT_CONFIG;
  else
    return NULL;
	
  if ( RegOpenKeyEx ( root_key, dir, 0, KEY_READ, &key_handle ) )
    {
      if (root)
        return NULL; /* no need for a RegClose, so return direct */
      /* It seems to be common practise to fall back to HKLM. */
      if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, dir, 0, KEY_READ, &key_handle) )
        return NULL; /* still no need for a RegClose, so return direct */
    }

  nbytes = 1;
  if ( RegQueryValueEx( key_handle, name, 0, NULL, NULL, &nbytes ) )
    {
      if (root)
        goto leave;
      /* Try to fallback to HKLM also vor a missing value.  */
      RegCloseKey (key_handle);
      if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, dir, 0, KEY_READ, &key_handle) )
        return NULL; /* Nope.  */
      if (RegQueryValueEx ( key_handle, name, 0, NULL, NULL, &nbytes))
        goto leave;
    }
  result = malloc ( (n1=nbytes+1) );
  if ( !result )
    goto leave;
  if ( RegQueryValueEx ( key_handle, name, 0, &type, result, &n1 ) )
    {
      free(result); result = NULL;
      goto leave;
    }
  result[nbytes] = 0; /* Make sure it is really a string.  */
  if (type == REG_EXPAND_SZ && strchr (result, '%')) 
    {
      char *tmp;
        
      n1 += 1000;
      tmp = malloc (n1+1);
      if (!tmp)
        goto leave;
      nbytes = ExpandEnvironmentStrings (result, tmp, n1);
      if (nbytes && nbytes > n1)
        {
          free (tmp);
          n1 = nbytes;
          tmp = malloc (n1 + 1);
          if (!tmp)
            goto leave;
          nbytes = ExpandEnvironmentStrings (result, tmp, n1);
          if (nbytes && nbytes > n1) {
            free (tmp); /* Oops - truncated, better don't expand at all. */
            goto leave;
          }
          tmp[nbytes] = 0;
          free (result);
          result = tmp;
        }
      else if (nbytes)  /* Okay, reduce the length. */
        {
          tmp[nbytes] = 0;
          free (result);
          result = malloc (strlen (tmp)+1);
          if (!result)
            result = tmp;
          else 
            {
              strcpy (result, tmp);
              free (tmp);
            }
        }
      else  /* Error - don't expand. */
        {
          free (tmp);
        }
    }

 leave:
  RegCloseKey( key_handle );
  return result;
}


/* This is a helper function to load and run a Windows function from
   either of one DLLs. */
static HRESULT
w32_shgetfolderpath (HWND a, int b, HANDLE c, DWORD d, LPSTR e)
{
  static int initialized;
  static HRESULT (WINAPI * func)(HWND,int,HANDLE,DWORD,LPSTR);

  if (!initialized)
    {
      static char *dllnames[] = { "shell32.dll", "shfolder.dll", NULL };
      void *handle;
      int i;

      initialized = 1;

      for (i=0, handle = NULL; !handle && dllnames[i]; i++)
        {
          handle = dlopen (dllnames[i], RTLD_LAZY);
          if (handle)
            {
              func = dlsym (handle, "SHGetFolderPathA");
              if (!func)
                {
                  dlclose (handle);
                  handle = NULL;
                }
            }
        }
    }

  if (func)
    return func (a,b,c,d,e);
  else
    return -1;
}


#if 0
static char *
find_program_in_registry (const char *name)
{
  char *program = NULL;
    
  program = read_w32_registry_string (NULL, "Software\\GNU\\GnuPG", name);
  if (program)
    {
      int i;

      TRACE2 (DEBUG_CTX, "gpgme:find_program_in_registry", 0,
	      "found %s in registry: `%s'", name, program);
      for (i = 0; program[i]; i++)
	{
	  if (program[i] == '/')
	    program[i] = '\\';
	}
    }
  return program;
}
#endif


static char *
find_program_in_inst_dir (const char *name)
{
  char *result = NULL;
  char *tmp;

  tmp = read_w32_registry_string ("HKEY_LOCAL_MACHINE",
				  "Software\\GNU\\GnuPG",
				  "Install Directory");
  if (!tmp)
    return NULL;

  result = malloc (strlen (tmp) + 1 + strlen (name) + 1);
  if (!result)
    {
      free (tmp);
      return NULL;
    }

  strcpy (stpcpy (stpcpy (result, tmp), "\\"), name);
  free (tmp);
  if (access (result, F_OK))
    {
      free (result);
      return NULL;
    }

  return result;
}


static char *
find_program_at_standard_place (const char *name)
{
  char path[MAX_PATH];
  char *result = NULL;
      
  if (w32_shgetfolderpath (NULL, CSIDL_PROGRAM_FILES, NULL, 0, path) >= 0) 
    {
      result = malloc (strlen (path) + 1 + strlen (name) + 1);
      if (result)
        {
          strcpy (stpcpy (stpcpy (result, path), "\\"), name);
          if (access (result, F_OK))
            {
              free (result);
              result = NULL;
            }
        }
    }
  return result;
}


const char *
_gpgme_get_gpg_path (void)
{
  static char *gpg_program;

  LOCK (get_path_lock);
#if 0
  if (!gpg_program)
    gpg_program = find_program_in_registry ("gpgProgram");
#endif
  if (!gpg_program)
    gpg_program = find_program_in_inst_dir ("gpg.exe");
  if (!gpg_program)
    gpg_program = find_program_at_standard_place ("GNU\\GnuPG\\gpg.exe");
  UNLOCK (get_path_lock);
  return gpg_program;
}


const char *
_gpgme_get_gpgsm_path (void)
{
  static char *gpgsm_program;

  LOCK (get_path_lock);
#if 0
  if (!gpgsm_program)
    gpgsm_program = find_program_in_registry ("gpgsmProgram");
#endif
  if (!gpgsm_program)
    gpgsm_program = find_program_in_inst_dir ("gpgsm.exe");
  if (!gpgsm_program)
    gpgsm_program = find_program_at_standard_place ("GNU\\GnuPG\\gpgsm.exe");
  UNLOCK (get_path_lock);
  return gpgsm_program;
}


const char *
_gpgme_get_gpgconf_path (void)
{
  static char *gpgconf_program;

  LOCK (get_path_lock);
#if 0
  if (!gpgconf_program)
    gpgconf_program = find_program_in_registry ("gpgconfProgram");
#endif
  if (!gpgconf_program)
    gpgconf_program = find_program_in_inst_dir ("gpgconf.exe");
  if (!gpgconf_program)
    gpgconf_program
      = find_program_at_standard_place ("GNU\\GnuPG\\gpgconf.exe");
  UNLOCK (get_path_lock);
  return gpgconf_program;
}


const char *
_gpgme_get_w32spawn_path (void)
{
  static char *w32spawn_program;

  LOCK (get_path_lock);
  if (!w32spawn_program)
    w32spawn_program = find_program_in_inst_dir ("gpgme-w32spawn.exe");
  if (!w32spawn_program)
    w32spawn_program
      = find_program_at_standard_place ("GNU\\GnuPG\\gpgme-w32spawn.exe");
  UNLOCK (get_path_lock);
  return w32spawn_program;
}


/* Return an integer value from gpgme specific configuration
   entries. VALUE receives that value; function returns true if a value
   has been configured and false if not. */
int
_gpgme_get_conf_int (const char *key, int *value)
{
  char *tmp = read_w32_registry_string (NULL, "Software\\GNU\\gpgme", key);
  if (!tmp)
    return 0;
  *value = atoi (tmp);
  free (tmp);
  return 1;
}


void 
_gpgme_allow_set_foregound_window (pid_t pid)
{
  static int initialized;
  static BOOL (WINAPI * func)(DWORD);
  void *handle;

  if (!initialized)
    {
      /* Available since W2000; thus we dynload it.  */
      initialized = 1;
      handle = dlopen ("user32.dll", RTLD_LAZY);
      if (handle)
        {
          func = dlsym (handle, "AllowSetForegroundWindow");
          if (!func)
            {
              dlclose (handle);
              handle = NULL;
            }
        }
    }

  if (!pid || pid == (pid_t)(-1))
    ;
  else if (func)
    func (pid);

}



/* mkstemp extracted from libc/sysdeps/posix/tempname.c.  Copyright
   (C) 1991-1999, 2000, 2001, 2006 Free Software Foundation, Inc.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.  */

static const char letters[] =
"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* Generate a temporary file name based on TMPL.  TMPL must match the
   rules for mk[s]temp (i.e. end in "XXXXXX").  The name constructed
   does not exist at the time of the call to mkstemp.  TMPL is
   overwritten with the result.  */
static int
mkstemp (char *tmpl)
{
  int len;
  char *XXXXXX;
  static uint64_t value;
  uint64_t random_time_bits;
  unsigned int count;
  int fd = -1;
  int save_errno = errno;

  /* A lower bound on the number of temporary files to attempt to
     generate.  The maximum total number of temporary file names that
     can exist for a given template is 62**6.  It should never be
     necessary to try all these combinations.  Instead if a reasonable
     number of names is tried (we define reasonable as 62**3) fail to
     give the system administrator the chance to remove the problems.  */
#define ATTEMPTS_MIN (62 * 62 * 62)

  /* The number of times to attempt to generate a temporary file.  To
     conform to POSIX, this must be no smaller than TMP_MAX.  */
#if ATTEMPTS_MIN < TMP_MAX
  unsigned int attempts = TMP_MAX;
#else
  unsigned int attempts = ATTEMPTS_MIN;
#endif

  len = strlen (tmpl);
  if (len < 6 || strcmp (&tmpl[len - 6], "XXXXXX"))
    {
      errno = EINVAL;
      return -1;
    }

  /* This is where the Xs start.  */
  XXXXXX = &tmpl[len - 6];

  /* Get some more or less random data.  */
  {
    FILETIME ft;

    GetSystemTimeAsFileTime (&ft);
    random_time_bits = (((uint64_t)ft.dwHighDateTime << 32)
                        | (uint64_t)ft.dwLowDateTime);
  }
  value += random_time_bits ^ getpid ();

  for (count = 0; count < attempts; value += 7777, ++count)
    {
      uint64_t v = value;

      /* Fill in the random bits.  */
      XXXXXX[0] = letters[v % 62];
      v /= 62;
      XXXXXX[1] = letters[v % 62];
      v /= 62;
      XXXXXX[2] = letters[v % 62];
      v /= 62;
      XXXXXX[3] = letters[v % 62];
      v /= 62;
      XXXXXX[4] = letters[v % 62];
      v /= 62;
      XXXXXX[5] = letters[v % 62];

      fd = open (tmpl, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
      if (fd >= 0)
	{
	  errno = save_errno;
	  return fd;
	}
      else if (errno != EEXIST)
	return -1;
    }

  /* We got out of the loop because we ran out of combinations to try.  */
  errno = EEXIST;
  return -1;
}


int
_gpgme_mkstemp (int *fd, char **name)
{
  char tmp[MAX_PATH + 2];
  char *tmpname;
  int err;

  *fd = -1;
  *name = NULL;

  err = GetTempPath (MAX_PATH + 1, tmp);
  if (err == 0 || err > MAX_PATH + 1)
    strcpy (tmp,"c:\\windows\\temp");
  else
    {
      int len = strlen(tmp);
      
      /* GetTempPath may return with \ on the end */
      while(len > 0 && tmp[len - 1] == '\\')
	{
	  tmp[len-1] = '\0';
	  len--;
	}
    }

  tmpname = malloc (strlen (tmp) + 13 + 1);
  if (!tmpname)
    return -1;
  strcpy (stpcpy (tmpname, tmp), "\\gpgme-XXXXXX");
  *fd = mkstemp (tmpname);
  if (fd < 0)
    return -1;

  *name = tmpname;
  return 0;
}
