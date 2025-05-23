/* gpgme-json.c - JSON based interface to gpgme (stdio-server)
 * Copyright (C) 2018, 2025 g10 Code GmbH
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

/* This tool implements the Native Messaging protocol of web
 * browsers and provides the server part of it.  A Javascript based
 * client can be found in lang/javascript.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif
#include <stdint.h>
#include <sys/stat.h>

#include "json-common.h"


/* We don't allow a request with more than 64 MiB.  */
#define MAX_REQUEST_SIZE (64 * 1024 * 1024)

/* True is debug mode is active.  */
static int opt_debug;


/*
 *  Driver code
 */

static char *
get_file (const char *fname)
{
  gpg_error_t err;
  estream_t fp;
  struct stat st;
  char *buf;
  size_t buflen;

  fp = es_fopen (fname, "r");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      log_error ("can't open '%s': %s\n", fname, gpg_strerror (err));
      return NULL;
    }

  if (fstat (es_fileno(fp), &st))
    {
      err = gpg_error_from_syserror ();
      log_error ("can't stat '%s': %s\n", fname, gpg_strerror (err));
      es_fclose (fp);
      return NULL;
    }

  buflen = st.st_size;
  buf = xmalloc (buflen+1);
  if (es_fread (buf, buflen, 1, fp) != 1)
    {
      err = gpg_error_from_syserror ();
      log_error ("error reading '%s': %s\n", fname, gpg_strerror (err));
      es_fclose (fp);
      xfree (buf);
      return NULL;
    }
  buf[buflen] = 0;
  es_fclose (fp);

  return buf;
}


/* Return a malloced line or NULL on EOF.  Terminate on read
 * error.  */
static char *
get_line (void)
{
  char *line = NULL;
  size_t linesize = 0;
  gpg_error_t err;
  size_t maxlength = 2048;
  int n;
  const char *s;
  char *p;

 again:
  n = es_read_line (es_stdin, &line, &linesize, &maxlength);
  if (n < 0)
    {
      err = gpg_error_from_syserror ();
      log_error ("error reading line: %s\n", gpg_strerror (err));
      exit (1);
    }
  if (!n)
    {
      xfree (line);
      line = NULL;
      return NULL;  /* EOF */
    }
  if (!maxlength)
    {
      log_info ("line too long - skipped\n");
      goto again;
    }
  if (memchr (line, 0, n))
    log_info ("warning: line shortened due to embedded Nul character\n");

  if (line[n-1] == '\n')
    line[n-1] = 0;

  /* Trim leading spaces.  */
  for (s=line; spacep (s); s++)
    ;
  if (s != line)
    {
      for (p=line; *s;)
        *p++ = *s++;
      *p = 0;
      n = p - line;
    }

  return line;
}


/* Process meta commands used with the standard REPL.  */
static char *
process_meta_commands (ctrl_t ctrl, const char *request)
{
  char *result = NULL;

  while (spacep (request))
    request++;

  if (!strncmp (request, "help", 4) && (spacep (request+4) || !request[4]))
    {
      if (request[4])
        {
          char *buf = xstrconcat ("{ \"help\":true, \"op\":\"", request+5,
                                  "\" }", NULL);
          result = json_core_process_request (ctrl, buf);
          xfree (buf);
        }
      else
        result = json_core_process_request (ctrl,
                                  "{ \"op\": \"help\","
                                  " \"interactive_help\": "
                                  "\"\\nMeta commands:\\n"
                                  "  ,read FNAME Process data from FILE\\n"
                                  "  ,help CMD   Print help for a command\\n"
                                  "  ,quit       Terminate process\""
                                  "}");
    }
  else if (!strncmp (request, "quit", 4) && (spacep (request+4) || !request[4]))
    exit (0);
  else if (!strncmp (request, "read", 4) && (spacep (request+4) || !request[4]))
    {
      if (!request[4])
        log_info ("usage: ,read FILENAME\n");
      else
        {
          char *buffer = get_file (request + 5);
          if (buffer)
            {
              result = json_core_process_request (ctrl, buffer);
              xfree (buffer);
            }
        }
    }
  else
    log_info ("invalid meta command\n");

  return result;
}


/* If STRING has a help response, return the MSG property in a human
 * readable format.  */
static char *
get_help_msg (const char *string)
{
  cjson_t json, j_type, j_msg;
  const char *msg;
  char *buffer = NULL;
  char *p;

  json = cJSON_Parse (string, NULL);
  if (json)
    {
      j_type = cJSON_GetObjectItem (json, "type");
      if (j_type && cjson_is_string (j_type)
          && !strcmp (j_type->valuestring, "help"))
        {
          j_msg = cJSON_GetObjectItem (json, "msg");
          if (j_msg || cjson_is_string (j_msg))
            {
              msg = j_msg->valuestring;
              buffer = malloc (strlen (msg)+1);
              if (buffer)
                {
                  for (p=buffer; *msg; msg++)
                    {
                      if (*msg == '\\' && msg[1] == '\n')
                        *p++ = '\n';
                      else
                        *p++ = *msg;
                    }
                  *p = 0;
                }
            }
        }
      cJSON_Delete (json);
    }
  return buffer;
}


/* An interactive standard REPL.  */
static void
interactive_repl (ctrl_t ctrl)
{
  char *line = NULL;
  char *request = NULL;
  char *response = NULL;
  char *p;
  int first;

  es_setvbuf (es_stdin, NULL, _IONBF, 0);
  es_fprintf (es_stderr, "%s %s ready (enter \",help\" for help)\n",
              gpgrt_strusage (11), gpgrt_strusage (13));
  do
    {
      es_fputs ("> ", es_stderr);
      es_fflush (es_stderr);
      es_fflush (es_stdout);
      xfree (line);
      line = get_line ();
      es_fflush (es_stderr);
      es_fflush (es_stdout);

      first = !request;
      if (line && *line)
        {
          if (!request)
            request = xstrdup (line);
          else
            {
              char *tmp = xstrconcat (request, "\n", line, NULL);
              xfree (request);
              request = tmp;
            }
        }

      if (!line)
        es_fputs ("\n", es_stderr);

      if (!line || !*line || (first && *request == ','))
        {
          /* Process the input.  */
          xfree (response);
          response = NULL;
          if (request && *request == ',')
            {
              response = process_meta_commands (ctrl, request+1);
            }
          else if (request)
            {
              response = json_core_process_request (ctrl, request);
            }
          xfree (request);
          request = NULL;

          if (response)
            {
              if (ctrl->interactive)
                {
                  char *msg = get_help_msg (response);
                  if (msg)
                    {
                      xfree (response);
                      response = msg;
                    }
                }

              es_fputs ("===> ", es_stderr);
              es_fflush (es_stderr);
              for (p=response; *p; p++)
                {
                  if (*p == '\n')
                    {
                      es_fflush (es_stdout);
                      es_fputs ("\n===> ", es_stderr);
                      es_fflush (es_stderr);
                    }
                  else
                    es_putc (*p, es_stdout);
                }
              es_fflush (es_stdout);
              es_fputs ("\n", es_stderr);
            }
        }
    }
  while (line);

  xfree (request);
  xfree (response);
  xfree (line);
}


/* Read and process a single request.  */
static void
read_and_process_single_request (ctrl_t ctrl)
{
  char *line = NULL;
  char *request = NULL;
  char *response = NULL;
  size_t n;

  for (;;)
    {
      xfree (line);
      line = get_line ();
      if (line && *line)
        request = (request? xstrconcat (request, "\n", line, NULL)
                   /**/   : xstrdup (line));
      if (!line)
        {
          if (request)
            {
              xfree (response);
              response = json_core_process_request (ctrl, request);
              if (response)
                {
                  es_fputs (response, es_stdout);
                  if ((n = strlen (response)) && response[n-1] != '\n')
                    es_fputc ('\n', es_stdout);
                }
              es_fflush (es_stdout);
            }
          break;
        }
    }

  xfree (response);
  xfree (request);
  xfree (line);
}


/* The Native Messaging processing loop.  */
static void
native_messaging_repl (ctrl_t ctrl)
{
  gpg_error_t err;
  uint32_t nrequest, nresponse;
  char *request = NULL;
  char *response = NULL;
  size_t n;

  /* Due to the length octets we need to switch the I/O stream into
   * binary mode.  */
  es_set_binary (es_stdin);
  es_set_binary (es_stdout);
  es_setbuf (es_stdin, NULL);  /* stdin needs to be unbuffered! */

  for (;;)
    {
      /* Read length.  Note that the protocol uses native endianness.
       * Is it allowed to call such a thing a well thought out
       * protocol?  */
      if (es_read (es_stdin, &nrequest, sizeof nrequest, &n))
        {
          err = gpg_error_from_syserror ();
          log_error ("error reading request header: %s\n", gpg_strerror (err));
          break;
        }
      if (!n)
        break;  /* EOF */
      if (n != sizeof nrequest)
        {
          log_error ("error reading request header: short read\n");
          break;
        }
      if (nrequest > MAX_REQUEST_SIZE)
        {
          log_error ("error reading request: request too long (%zu MiB)\n",
                     (size_t)nrequest / (1024*1024));
          /* Fixme: Shall we read the request to the bit bucket and
           * return an error response or just return an error response
           * and terminate?  Needs some testing.  */
          break;
        }

      /* Read request.  */
      request = xtrymalloc (nrequest + 1);
      if (!request)
        {
          err = gpg_error_from_syserror ();
          log_error ("error reading request: Not enough memory for %zu MiB)\n",
                     (size_t)nrequest / (1024*1024));
          /* FIXME: See comment above.  */
          break;
        }
      if (es_read (es_stdin, request, nrequest, &n))
        {
          err = gpg_error_from_syserror ();
          log_error ("error reading request: %s\n", gpg_strerror (err));
          break;
        }
      if (n != nrequest)
        {
          /* That is a protocol violation.  */
          xfree (response);
          response = error_object_string ("Invalid request:"
                                          " short read (%zu of %zu bytes)\n",
                                          n, (size_t)nrequest);
        }
      else /* Process request  */
        {
          request[n] = '\0'; /* Ensure that request has an end */
          if (opt_debug)
            log_debug ("request='%s'\n", request);
          xfree (response);
          response = json_core_process_request (ctrl, request);
          if (opt_debug)
            log_debug ("response='%s'\n", response);
        }
      nresponse = strlen (response);

      /* Write response */
      if (es_write (es_stdout, &nresponse, sizeof nresponse, &n))
        {
          err = gpg_error_from_syserror ();
          log_error ("error writing request header: %s\n", gpg_strerror (err));
          break;
        }
      if (n != sizeof nresponse)
        {
          log_error ("error writing request header: short write\n");
          break;
        }
      if (es_write (es_stdout, response, nresponse, &n))
        {
          err = gpg_error_from_syserror ();
          log_error ("error writing request: %s\n", gpg_strerror (err));
          break;
        }
      if (n != nresponse)
        {
          log_error ("error writing request: short write\n");
          break;
        }
      if (es_fflush (es_stdout) || es_ferror (es_stdout))
        {
          err = gpg_error_from_syserror ();
          log_error ("error writing request: %s\n", gpg_strerror (err));
          break;
        }
      xfree (response);
      response = NULL;
      xfree (request);
      request = NULL;
    }

  xfree (response);
  xfree (request);
}


/* Run the --identify command.   */
static gpg_error_t
cmd_identify (const char *fname)
{
  gpg_error_t err;
  estream_t fp;
  gpgme_data_t data;
  gpgme_data_type_t dt;

  if (fname)
    {
      fp = es_fopen (fname, "rb");
      if (!fp)
        {
          err = gpg_error_from_syserror ();
          log_error ("can't open '%s': %s\n", fname, gpg_strerror (err));
          return err;
        }
      err = gpgme_data_new_from_estream (&data, fp);
    }
  else
    {
      char *buffer;
      int n;

      fp = NULL;
      es_set_binary (es_stdin);

      /* Urgs: gpgme_data_identify does a seek and that fails for stdin.  */
      buffer = xmalloc (2048+1);
      n = es_fread (buffer, 1, 2048, es_stdin);
      if (n < 0 || es_ferror (es_stdin))
        {
          err = gpg_error_from_syserror ();
          log_error ("error reading '%s': %s\n", "[stdin]", gpg_strerror (err));
          xfree (buffer);
          return err;
        }
      buffer[n] = 0;
      err = gpgme_data_new_from_mem (&data, buffer, n, 1);
      xfree (buffer);
    }

  if (err)
    {
      log_error ("error creating data object: %s\n", gpg_strerror (err));
      return err;
    }

  dt = gpgme_data_identify (data, 0);
  if (dt == GPGME_DATA_TYPE_INVALID)
    log_error ("error identifying data\n");
  printf ("%s\n", data_type_to_string (dt));
  gpgme_data_release (data);
  es_fclose (fp);
  return 0;
}


static const char *
my_strusage( int level )
{
  const char *p;

  switch (level)
    {
    case  9: p = "LGPL-2.1-or-later"; break;
    case 11: p = "gpgme-json"; break;
    case 13: p = PACKAGE_VERSION; break;
    case 14: p = "Copyright (C) 2018 g10 Code GmbH"; break;
    case 19: p = "Please report bugs to <" PACKAGE_BUGREPORT ">.\n"; break;
    case 1:
    case 40:
      p = "Usage: gpgme-json [OPTIONS]";
      break;
    case 41:
      p = "Native messaging based GPGME operations.\n";
      break;
    case 42:
      p = "1"; /* Flag print 40 as part of 41. */
      break;
    default: p = NULL; break;
    }
  return p;
}


int
main (int argc, char *argv[])
{
  enum { CMD_DEFAULT     = 0,
         CMD_INTERACTIVE = 'i',
         CMD_SINGLE      = 's',
         CMD_LIBVERSION  = 501,
         CMD_IDENTIFY
  } cmd = CMD_DEFAULT;
  enum {
    OPT_DEBUG = 600
  };

  static gpgrt_opt_t opts[] = {
    ARGPARSE_c  (CMD_INTERACTIVE, "interactive", "Interactive REPL"),
    ARGPARSE_c  (CMD_SINGLE,      "single",      "Single request mode"),
    ARGPARSE_c  (CMD_IDENTIFY,    "identify",    "Identify the input"),
    ARGPARSE_c  (CMD_LIBVERSION,  "lib-version", "Show library version"),
    ARGPARSE_s_n(OPT_DEBUG,       "debug",       "Flyswatter"),

    ARGPARSE_end()
  };
  gpgrt_argparse_t pargs = { &argc, &argv};
  int log_file_set = 0;
  struct json_common_s ctrl_buffer;
  ctrl_t ctrl = &ctrl_buffer;

  memset (&ctrl_buffer, 0, sizeof ctrl_buffer);

  gpgrt_set_strusage (my_strusage);

#ifdef HAVE_SETLOCALE
  setlocale (LC_ALL, "");
#endif
  gpgme_check_version (NULL);
#ifdef LC_CTYPE
  gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
#endif
#ifdef LC_MESSAGES
  gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
#endif

  while (gpgrt_argparse (NULL, &pargs, opts))
    {
      switch (pargs.r_opt)
        {
        case CMD_INTERACTIVE:
          ctrl->interactive = 1;
          /*FALLTHROUGH*/
        case CMD_SINGLE:
        case CMD_IDENTIFY:
        case CMD_LIBVERSION:
          cmd = pargs.r_opt;
          break;

        case OPT_DEBUG: opt_debug = 1; break;

        default:
          pargs.err = ARGPARSE_PRINT_WARNING;
	  break;
        }
    }
  gpgrt_argparse (NULL, &pargs, NULL);

  if (!opt_debug)
    {
      /* Handling is similar to GPGME_DEBUG */
      const char *s = getenv ("GPGME_JSON_DEBUG");
      const char *s1;

      if (s && atoi (s) > 0)
        {
          opt_debug = 1;
          s1 = strchr (s, PATHSEP_C);
          if (s1 && strlen (s1) > 2)
            {
              s1++;
              log_set_file (s1);
              log_file_set = 1;
            }
        }
    }

  if (opt_debug && !log_file_set)
    {
      const char *home = getenv ("HOME");
      char *file = xstrconcat ("socket://",
                               home? home:"/tmp",
                               "/.gnupg/S.gpgme-json.log", NULL);
      log_set_file (file);
      xfree (file);
    }

  if (opt_debug)
    { int i;
      for (i=0; argv[i]; i++)
        log_debug ("argv[%d]='%s'\n", i, argv[i]);
    }

  switch (cmd)
    {
    case CMD_DEFAULT:
      native_messaging_repl (ctrl);
      break;

    case CMD_SINGLE:
      read_and_process_single_request (ctrl);
      break;

    case CMD_INTERACTIVE:
      interactive_repl (ctrl);
      break;

    case CMD_IDENTIFY:
      if (argc > 1)
        {
          log_error ("usage: %s --identify [filename|-]\n",
                     gpgrt_strusage (11));
          exit (1);
        }
      cmd_identify (argc && strcmp (*argv, "-")? *argv : NULL);
      break;

    case CMD_LIBVERSION:
      printf ("Version from header: %s (0x%06x)\n",
              GPGME_VERSION, GPGME_VERSION_NUMBER);
      printf ("Version from binary: %s\n", gpgme_check_version (NULL));
      printf ("Copyright blurb ...:%s\n", gpgme_check_version ("\x01\x01"));
      break;
    }

  if (opt_debug)
    log_debug ("ready");

  return 0;
}
