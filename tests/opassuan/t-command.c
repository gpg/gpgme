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

#include <gpgme.h>

#define fail_if_err(err)					\
  do								\
    {								\
      if (err)							\
        {							\
          fprintf (stderr, "%s:%d: %s: %s (%d.%d)\n",        	\
                   __FILE__, __LINE__, gpg_strsource (err),	\
		   gpg_strerror (err),                          \
                   gpg_err_source (err), gpg_err_code (err));	\
          exit (1);						\
        }							\
    }								\
  while (0)


static gpg_error_t
data_cb (void *opaque, const void *data, size_t datalen)
{
  printf ("DATA_CB: datalen=%d\n", (int)datalen);
  return 0;
}     


static gpg_error_t
inq_cb (void *opaque, const char *name, const char *args,
        gpgme_assuan_sendfnc_t sendfnc,
        gpgme_assuan_sendfnc_ctx_t sendfnc_value)
{
  printf ("INQ_CB: name=`%s' args=`%s'\n", name, args);

  return 0;
}     


static gpg_error_t
status_cb (void *opaque, const char *status, const char *args)
{
  printf ("STATUS_CB: status=`%s'  args=`%s'\n", status, args);
  return 0;
}     






int 
main (int argc, char **argv)
{
  gpgme_error_t err;
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

  err = gpgme_op_assuan_transact (ctx, command,
                                  data_cb, NULL,
                                  inq_cb, NULL,
                                  status_cb, NULL);
  fail_if_err (err);
  err = gpgme_op_assuan_result (ctx);
  if (err)
    fprintf (stderr, "assuan command `%s' failed: %s <%s> (%d)\n", 
             command, gpg_strerror (err), gpg_strsource (err), err);
  else
    fprintf (stderr, "assuan command `%s' succeeded\n", command);


  gpgme_release (ctx);

  return 0;
}

