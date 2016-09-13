/* t-data - Regression tests for the gpgme_data_t abstraction.
   Copyright (C) 2001, 2004 g10 Code GmbH

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

/* We need to include config.h so that we know whether we are building
   with large file system (LFS) support. */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <gpgme.h>

#define fail_if_err(a) do { if(a) {                                          \
                               fprintf (stderr, "%s:%d: (%i) gpgme_error_t " \
                                "%s\n", __FILE__, __LINE__, round,           \
                                gpgme_strerror(a));                          \
                                exit (1); }                                  \
                             } while(0)

static char *
make_filename (const char *fname)
{
  const char *srcdir = getenv ("srcdir");
  char *buf;

  if (!srcdir)
    srcdir = ".";
  buf = malloc (strlen(srcdir) + strlen(fname) + 2 );
  if (!buf)
    {
      fprintf (stderr, "%s:%d: could not allocate string: %s\n",
	       __FILE__, __LINE__, strerror (errno));
      exit (1);
    }
  strcpy (buf, srcdir);
  strcat (buf, "/");
  strcat (buf, fname);
  return buf;
}

typedef enum
  {
    TEST_INITIALIZER,
    TEST_INVALID_ARGUMENT,
    TEST_INOUT_NONE,
    TEST_INOUT_MEM_NO_COPY,
    TEST_INOUT_MEM_COPY,
    TEST_INOUT_MEM_FROM_FILE_COPY,
    TEST_INOUT_MEM_FROM_INEXISTANT_FILE,
    TEST_INOUT_MEM_FROM_FILE_NO_COPY,
    TEST_INOUT_MEM_FROM_FILE_PART_BY_NAME,
    TEST_INOUT_MEM_FROM_INEXISTANT_FILE_PART,
    TEST_INOUT_MEM_FROM_FILE_PART_BY_FP,
    TEST_END
  } round_t;

const char *text = "Just GNU it!\n";
const char *text2 = "Just GNU it!\nJust GNU it!\n";

int
read_cb (void *cb_value, char *buffer, size_t count, size_t *nread)
{
  static int off = 0;
  unsigned int amount = strlen (text) - off;
  /*  round_t round = *((round_t *) cb_value);  */

  (void)cb_value;

  if (!buffer && !count && !nread)
    {
      /* Rewind requested.  */
      off = 0;
      return 0;
    }
  if (! buffer || !nread)
    return -1;
  if (amount <= 0)
    {
      /* End of file.  */
      *nread = 0;
      return -1;
    }
  if (amount > count)
    amount = count;
  memcpy (buffer, text, amount);
  off += amount;
  *nread = amount;
  return 0;
}

void
read_once_test (round_t round, gpgme_data_t data)
{
  char buffer[1024];
  size_t read;

  read = gpgme_data_read (data, buffer, sizeof (buffer));

  if (read != strlen (text) || strncmp (buffer, text, strlen (text)))
    {
      fprintf (stderr, "%s:%d: (%i) gpgme_data_read returned wrong data\n",
	       __FILE__, __LINE__, round);
      exit (1);
    }

  read = gpgme_data_read (data, buffer, sizeof (buffer));
  if (read)
    {
      fprintf (stderr, "%s:%d: (%i) gpgme_data_read did not signal EOF\n",
	       __FILE__, __LINE__, round);
      exit (1);
    }
}

void
read_test (round_t round, gpgme_data_t data)
{
  char buffer[1024];
  size_t read;

  if (round == TEST_INOUT_NONE)
    {
      read = gpgme_data_read (data, buffer, sizeof (buffer));
      if (read > 0)
	{
	  fprintf (stderr, "%s:%d: (%i) gpgme_data_read succeeded unexpectedly\n",
		   __FILE__, __LINE__, round);
	  exit (1);
	}
      return;
    }

  read_once_test (round, data);
  gpgme_data_seek (data, 0, SEEK_SET);
  read_once_test (round, data);
}

void
write_test (round_t round, gpgme_data_t data)
{
  char buffer[1024];
  size_t amt;

  amt = gpgme_data_write (data, text, strlen (text));
  if (amt != strlen (text))
    fail_if_err (gpgme_error_from_errno (errno));

  gpgme_data_seek (data, 0, SEEK_SET);

  if (round == TEST_INOUT_NONE)
    read_once_test (round, data);
  else
    {
      amt = gpgme_data_read (data, buffer, sizeof (buffer));

      if (amt != strlen (text2) || strncmp (buffer, text2, strlen (text2)))
	{
	  fprintf (stderr, "%s:%d: (%i) gpgme_data_read returned wrong data\n",
		   __FILE__, __LINE__, round);
	  exit (1);
	}

      amt = gpgme_data_read (data, buffer, sizeof (buffer));
      if (amt)
	{
	  fprintf (stderr, "%s:%d: (%i) gpgme_data_read did not signal EOF\n",
		   __FILE__, __LINE__, round);
	  exit (1);
	}
    }
}


int
main (void)
{
  round_t round = TEST_INITIALIZER;
  char *text_filename = make_filename ("t-data-1.txt");
  char *longer_text_filename = make_filename ("t-data-2.txt");
  const char *missing_filename = "this-file-surely-does-not-exist";
  gpgme_error_t err = 0;
  gpgme_data_t data;

  while (++round)
    {
      switch (round)
	{
	case TEST_INVALID_ARGUMENT:
	  err = gpgme_data_new (NULL);
	  if (!err)
	    {
	      fprintf (stderr, "%s:%d: gpgme_data_new on NULL pointer succeeded "
		       "unexpectedly\n", __FILE__, __LINE__);
	      exit (1);
	    }
	  continue;
	case TEST_INOUT_NONE:
	  err = gpgme_data_new (&data);
	  break;
	case TEST_INOUT_MEM_NO_COPY:
	  err = gpgme_data_new_from_mem (&data, text, strlen (text), 0);
	  break;
	case TEST_INOUT_MEM_COPY:
	  err = gpgme_data_new_from_mem (&data, text, strlen (text), 1);
	  break;
	case TEST_INOUT_MEM_FROM_FILE_COPY:
	  err = gpgme_data_new_from_file (&data, text_filename, 1);
	  break;
	case TEST_INOUT_MEM_FROM_INEXISTANT_FILE:
	  err = gpgme_data_new_from_file (&data, missing_filename, 1);
	  if (!err)
	    {
	      fprintf (stderr, "%s:%d: gpgme_data_new_from_file on inexistant "
		       "file succeeded unexpectedly\n", __FILE__, __LINE__);
	      exit (1);
	    }
	  continue;
	case TEST_INOUT_MEM_FROM_FILE_NO_COPY:
	  err = gpgme_data_new_from_file (&data, text_filename, 0);
	  /* This is not implemented yet.  */
	  if (gpgme_err_code (err) == GPG_ERR_NOT_IMPLEMENTED
	      || gpgme_err_code (err) == GPG_ERR_INV_VALUE)
	    continue;
	  break;
	case TEST_INOUT_MEM_FROM_FILE_PART_BY_NAME:
	  err = gpgme_data_new_from_filepart (&data, longer_text_filename, 0,
					      strlen (text), strlen (text));
	  break;
	case TEST_INOUT_MEM_FROM_INEXISTANT_FILE_PART:
	  err = gpgme_data_new_from_filepart (&data, missing_filename, 0,
					      strlen (text), strlen (text));
	  if (!err)
	    {
	      fprintf (stderr, "%s:%d: gpgme_data_new_from_file on inexistant "
		       "file succeeded unexpectedly\n", __FILE__, __LINE__);
	      exit (1);
	    }
	  continue;
	case TEST_INOUT_MEM_FROM_FILE_PART_BY_FP:
	  {
	    FILE *fp = fopen (longer_text_filename, "rb");
	    if (! fp)
	      {
		fprintf (stderr, "%s:%d: fopen: %s\n", __FILE__, __LINE__,
			 strerror (errno));
		exit (1);
	      }
	    err = gpgme_data_new_from_filepart (&data, 0, fp,
						strlen (text), strlen (text));
	  }
	  break;
	case TEST_END:
	  goto out;
	case TEST_INITIALIZER:
	  /* Shouldn't happen.  */
	  fprintf (stderr, "%s:%d: impossible condition\n", __FILE__, __LINE__);
	  exit (1);
	}
      fail_if_err (err);

      read_test (round, data);
      write_test (round, data);
      gpgme_data_release (data);
    }
 out:
  free (text_filename);
  free (longer_text_filename);
  return 0;
}
