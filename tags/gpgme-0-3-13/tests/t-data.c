/* t-data - Regression tests for the GpgmeData abstraction.
 *      Copyright (C) 2001 g10 Code GmbH
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

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <gpgme.h>

#define fail_if_err(a) do { if(a) {                                       \
                               fprintf (stderr, "%s:%d: (%i) GpgmeError " \
                                "%s\n", __FILE__, __LINE__, round,        \
                                gpgme_strerror(a));                       \
                                exit (1); }                               \
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
    TEST_OUT_CB,
    TEST_END
  } round_t;

const char *text = "Just GNU it!\n";
const char *text2 = "Just GNU it!\nJust GNU it!\n";

int
read_cb (void *cb_value, char *buffer, size_t count, size_t *nread)
{
  static int off = 0;
  int amount = strlen (text) - off;
  /*  round_t round = *((round_t *) cb_value);  */

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
read_once_test (round_t round, GpgmeData data)
{
  GpgmeError err;
  char buffer[1024];
  size_t read;

  err = gpgme_data_read (data, buffer, sizeof (buffer), &read);
  fail_if_err (err);

  if (read != strlen (text) || strncmp (buffer, text, strlen (text)))
    {
      fprintf (stderr, "%s:%d: (%i) gpgme_data_read returned wrong data\n",
	       __FILE__, __LINE__, round);
      exit (1);
    }

  err = gpgme_data_read (data, buffer, sizeof (buffer), &read);
  if (err != GPGME_EOF)
    {
      fprintf (stderr, "%s:%d: (%i) gpgme_data_read did not signal EOF\n",
	       __FILE__, __LINE__, round);
      exit (1);
    }
}

void
read_test (round_t round, GpgmeData data)
{
  GpgmeError err;
  char buffer[1024];
  size_t read;

  if (round == TEST_INOUT_NONE)
    {
      err = gpgme_data_read (data, buffer, sizeof (buffer), &read);
      if (!err)
	{
	  fprintf (stderr, "%s:%d: (%i) gpgme_data_read succeded unexpectedly\n",
		   __FILE__, __LINE__, round);
	  exit (1);
	}
      return;
    }

  read_once_test (round, data);
  err = gpgme_data_rewind (data);
  fail_if_err (err);
  read_once_test (round, data);
}

void
write_test (round_t round, GpgmeData data)
{
  GpgmeError err;
  char buffer[1024];
  size_t read;

  err = gpgme_data_write (data, text, strlen (text));
  fail_if_err (err);

  read_once_test (round, data);
  err = gpgme_data_rewind (data);
  fail_if_err (err);

  if (round == TEST_INOUT_NONE)
    read_once_test (round, data);
  else
    {
      err = gpgme_data_read (data, buffer, sizeof (buffer), &read);
      fail_if_err (err);

      if (read != strlen (text2) || strncmp (buffer, text2, strlen (text2)))
	{
	  fprintf (stderr, "%s:%d: (%i) gpgme_data_read returned wrong data\n",
		   __FILE__, __LINE__, round);
	  exit (1);
	}

      err = gpgme_data_read (data, buffer, sizeof (buffer), &read);
      if (err != GPGME_EOF)
	{
	  fprintf (stderr, "%s:%d: (%i) gpgme_data_read did not signal EOF\n",
		   __FILE__, __LINE__, round);
	  exit (1);
	}
    }
}

int 
main (int argc, char **argv )
{
  round_t round = TEST_INITIALIZER;
  const char *text_filename = make_filename ("t-data-1.txt");
  const char *longer_text_filename = make_filename ("t-data-2.txt");
  const char *missing_filename = "this-file-surely-does-not-exist";
  GpgmeError err = GPGME_No_Error;
  GpgmeData data;

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
	  if (gpgme_data_get_type (NULL) != GPGME_DATA_TYPE_NONE)
	    {
	      fprintf (stderr, "%s:%d: gpgme_data_get_type on NULL incorrect\n",
		       __FILE__, __LINE__);
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
	  if (err == GPGME_Not_Implemented)
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
	case TEST_OUT_CB:
	  err = gpgme_data_new_with_read_cb (&data, read_cb, &round);
	  break;
	case TEST_END:
	  return 0;
	case TEST_INITIALIZER:
	  /* Shouldn't happen.  */
	  fprintf (stderr, "%s:%d: impossible condition\n", __FILE__, __LINE__);
	  exit (1);
	}
      fail_if_err (err);

      switch (round)
	{
	case TEST_INOUT_NONE:
	  if (gpgme_data_get_type (data) != GPGME_DATA_TYPE_NONE)
	    err = GPGME_Invalid_Type;
	  break;
	case TEST_INOUT_MEM_NO_COPY:
	case TEST_INOUT_MEM_COPY:
	case TEST_INOUT_MEM_FROM_FILE_COPY:
	case TEST_INOUT_MEM_FROM_FILE_NO_COPY:
	case TEST_INOUT_MEM_FROM_FILE_PART_BY_NAME:
	case TEST_INOUT_MEM_FROM_FILE_PART_BY_FP:
	  if (gpgme_data_get_type (data) != GPGME_DATA_TYPE_MEM)
	    err = GPGME_Invalid_Type;
	  break;
	case TEST_OUT_CB:
	  if (gpgme_data_get_type (data) != GPGME_DATA_TYPE_CB)
	    err = GPGME_Invalid_Type;
	  break;
	case TEST_INITIALIZER:
	case TEST_INVALID_ARGUMENT:
	case TEST_INOUT_MEM_FROM_INEXISTANT_FILE:
	case TEST_INOUT_MEM_FROM_INEXISTANT_FILE_PART:
	case TEST_END:
	  /* Shouldn't happen.  */
	  fprintf (stderr, "%s:%d: impossible condition\n", __FILE__, __LINE__);
	  exit (1);
	}
      read_test (round, data);
      if (round != TEST_OUT_CB)
	write_test (round, data);
      gpgme_data_release (data);
    }
  return 0;
}
