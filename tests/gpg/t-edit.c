/* t-edit.c  - regression test
 *	Copyright (C) 2000 Werner Koch (dd9jn)
 *      Copyright (C) 2001, 2002 g10 Code GmbH
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <gpgme.h>

struct passphrase_cb_info_s {
    GpgmeCtx c;
    int did_it;
};


#define fail_if_err(a) do { if(a) { int my_errno = errno; \
            fprintf (stderr, "%s:%d: GpgmeError %s\n", \
                 __FILE__, __LINE__, gpgme_strerror(a));   \
            if ((a) == GPGME_File_Error)                       \
                   fprintf (stderr, "\terrno=`%s'\n", strerror (my_errno)); \
                   exit (1); }                               \
                             } while(0)

static void
flush_data (GpgmeData dh)
{
  char buf[100];
  size_t nread;
  GpgmeError err;

  while (!(err = gpgme_data_read (dh, buf, 100, &nread)))
    fwrite (buf, nread, 1, stdout);
  if (err != GPGME_EOF) 
    fail_if_err (err);
}


static const char *
passphrase_cb (void *opaque, const char *desc, void **r_hd)
{
  const char *pass;

  if (!desc)
    {
      /* cleanup by looking at *r_hd */
      return NULL;
    }

  pass = "abc";
  fprintf (stderr, "%% requesting passphrase for `%s': ", desc);
  fprintf (stderr, "sending `%s'\n", pass );

  return pass;
}


GpgmeError
edit_fnc (void *opaque, GpgmeStatusCode status, const char *args, const char **result)
{
  GpgmeData out = (GpgmeData) opaque;

  fputs ("[-- Response --]\n", stdout);
  flush_data (out); 

  fprintf (stdout, "[-- Code: %i, %s --]\n", status, args);
 
  if (result)
    {
      if (!strcmp (args, "keyedit.prompt"))
	{
	  static int step = 0;

	  switch (step)
	    {
	    case 0:
	      *result = "fpr";
	      break;
	    case 1:
	      *result = "expire";
	      break;
	    default:
	      *result = "quit";
	      break;
	    }
	  step++;
	}
      else if (!strcmp (args, "keyedit.save.okay"))
	{
	  *result = "Y";
	}
      else if (!strcmp (args, "keygen.valid"))
	{
	  *result = "0";
	}
    }

  return 0;
}


int 
main (int argc, char **argv)
{
  GpgmeCtx ctx;
  GpgmeError err;
  GpgmeData out = NULL;
  GpgmeKey key = NULL;
  struct passphrase_cb_info_s info;
  const char *pattern = "Alpha";
  char *p;

  do
    {
      err = gpgme_new (&ctx);
      fail_if_err (err);
      err = gpgme_data_new (&out);
      fail_if_err (err);

      p = getenv("GPG_AGENT_INFO");
      if (!(p && strchr (p, ':')))
	{
	  memset (&info, 0, sizeof info);
	  info.c = ctx;
	  gpgme_set_passphrase_cb (ctx, passphrase_cb, &info);
	} 

      err = gpgme_op_keylist_start (ctx, pattern, 0);
      fail_if_err (err);
      err = gpgme_op_keylist_next (ctx, &key);
      fail_if_err (err);
      err = gpgme_op_keylist_end (ctx);
      fail_if_err (err);

      p = gpgme_key_get_as_xml (key);
      if (p)
	{
	  fputs (p, stdout);
	  free (p);
	}

      err = gpgme_op_edit (ctx, key, edit_fnc, out, out);
      fail_if_err (err);

      fputs ("[-- Last response --]\n", stdout);
      flush_data (out);

      gpgme_data_release (out);
      gpgme_key_release (key);
      gpgme_release (ctx);
    }
  while (argc > 1 && !strcmp( argv[1], "--loop"));

  return 0;
}


