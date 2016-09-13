/* t-command.c - Regression test.
   Copyright (C) 2009 g10 Code GmbH

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
   License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <assert.h>

#include <gpgme.h>

#define fail_if_err(err)					\
  do								\
    {								\
      if (err)							\
        {							\
          fprintf (stderr, "%s:%d: %s: %s (%d.%d)\n",        	\
                   __FILE__, __LINE__, gpgme_strsource (err),	\
		   gpgme_strerror (err),                        \
                   gpgme_err_source (err), gpgme_err_code (err)); \
          exit (1);						\
        }							\
    }								\
  while (0)


static gpgme_error_t
data_cb (void *opaque, const void *data, size_t datalen)
{
  (void)opaque;
  (void)data;

  printf ("DATA_CB: datalen=%d\n", (int)datalen);
  return 0;
}


static gpgme_error_t
inq_cb (void *opaque, const char *name, const char *args,
        gpgme_data_t *r_data)
{
  gpgme_data_t data;
  gpgme_error_t err;

  (void)opaque;

  if (name)
    {
      printf ("INQ_CB: name=`%s' args=`%s'\n", name, args);
      /* There shall be no data object.  */
      assert (!*r_data);

      err = gpgme_data_new (&data);
      fail_if_err (err);
      *r_data = data;
      printf ("        sending data object %p\n", data);
    }
  else /* Finished using the formerly returned data object.  */
    {
      printf ("INQ_CB: data object %p finished\n", *r_data);
      /* There shall be a data object so that it can be cleaned up. */
      assert (r_data);

      gpgme_data_release (*r_data);
    }

  /* Uncomment the next lines and send a "SCD LEARN" to test sending
     cancel from in inquiry.  */
  /* if (name && !strcmp (name, "KNOWNCARDP")) */
  /*   return gpgme_error (GPG_ERR_ASS_CANCELED); */


  return 0;
}


static gpgme_error_t
status_cb (void *opaque, const char *status, const char *args)
{
  (void)opaque;

  printf ("STATUS_CB: status=`%s'  args=`%s'\n", status, args);
  return 0;
}



int
main (int argc, char **argv)
{
  gpgme_error_t err;
  gpgme_error_t op_err;
  gpgme_ctx_t ctx;
  const char *command;

  gpgme_check_version (NULL);
#ifndef HAVE_W32_SYSTEM
  setlocale (LC_ALL, "");
  gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
  gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
#endif

  if (argc)
    {
      argc--;
      argv++;
    }
  command = argc? *argv : "NOP";


  err = gpgme_new (&ctx);
  fail_if_err (err);

  err = gpgme_set_protocol (ctx, GPGME_PROTOCOL_ASSUAN);
  fail_if_err (err);

  err = gpgme_op_assuan_transact_ext (ctx, command, data_cb, NULL,
                                  inq_cb, NULL, status_cb, NULL, &op_err);
  fail_if_err (err || op_err);

  gpgme_release (ctx);

  return 0;
}

