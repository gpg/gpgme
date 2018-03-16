/* gpgme-json.c - JSON based interface to gpgme (server)
 * Copyright (C) 2018 g10 Code GmbH
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
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1+
 */

/* This is tool implements the Native Messaging protocol of web
 * browsers and provides the server part of it.  A Javascript based
 * client can be found in lang/javascript.  The used data format is
 * similar to the API of openpgpjs.
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

#define GPGRT_ENABLE_ES_MACROS 1
#define GPGRT_ENABLE_LOG_MACROS 1
#include "gpgme.h"
#include "argparse.h"
#include "cJSON.h"


/* We don't allow a request with more than 64 MiB.  */
#define MAX_REQUEST_SIZE (64 * 1024 * 1024)


static void xoutofcore (const char *type) GPGRT_ATTR_NORETURN;
static cjson_t error_object_v (const char *message,
                              va_list arg_ptr) GPGRT_ATTR_PRINTF(1,0);
static cjson_t error_object (const char *message,
                            ...) GPGRT_ATTR_PRINTF(1,2);
static char *error_object_string (const char *message,
                                  ...) GPGRT_ATTR_PRINTF(1,2);


/* True if interactive mode is active.  */
static int opt_interactive;



/*
 * Helper functions and macros
 */

#define xtrymalloc(a)  gpgrt_malloc ((a))
#define xstrdup(a) ({                           \
      char *_r = gpgrt_strdup ((a));            \
      if (!_r)                                  \
        xoutofcore ("strdup");                  \
      _r; })
#define xstrconcat(a, ...) ({                           \
      char *_r = gpgrt_strconcat ((a), __VA_ARGS__);    \
      if (!_r)                                          \
        xoutofcore ("strconcat");                       \
      _r; })
#define xfree(a) gpgrt_free ((a))

#define spacep(p)   (*(p) == ' ' || *(p) == '\t')


static void
xoutofcore (const char *type)
{
  gpg_error_t err = gpg_error_from_syserror ();
  log_error ("%s failed: %s\n", type, gpg_strerror (err));
  exit (2);
}


/* Call cJSON_CreateObject but terminate in case of an error.  */
static cjson_t
xjson_CreateObject (void)
{
  cjson_t json = cJSON_CreateObject ();
  if (!json)
    xoutofcore ("cJSON_CreateObject");
  return json;
}


/* Wrapper around cJSON_AddStringToObject which returns an gpg-error
 * code instead of the NULL or the object.  */
static gpg_error_t
cjson_AddStringToObject (cjson_t object, const char *name, const char *string)
{
  if (!cJSON_AddStringToObject (object, name, string))
    return gpg_error_from_syserror ();
  return 0;
}


/* Same as cjson_AddStringToObject but prints an error message and
 * terminates. the process.  */
static void
xjson_AddStringToObject (cjson_t object, const char *name, const char *string)
{
  if (!cJSON_AddStringToObject (object, name, string))
    xoutofcore ("cJSON_AddStringToObject");
}


/* Create a JSON error object.  */
static cjson_t
error_object_v (const char *message, va_list arg_ptr)
{
  cjson_t response;
  char *msg;

  msg = gpgrt_vbsprintf (message, arg_ptr);
  if (!msg)
    xoutofcore ("error_object");

  response = xjson_CreateObject ();
  xjson_AddStringToObject (response, "type", "error");
  xjson_AddStringToObject (response, "msg", msg);

  xfree (msg);
  return response;
}


/* Call cJSON_Print but terminate in case of an error.  */
static char *
xjson_Print (cjson_t object)
{
  char *buf;
  buf = cJSON_Print (object);
  if (!buf)
    xoutofcore ("cJSON_Print");
  return buf;
}


static cjson_t
error_object (const char *message, ...)
{
  cjson_t response;
  va_list arg_ptr;

  va_start (arg_ptr, message);
  response = error_object_v (message, arg_ptr);
  va_end (arg_ptr);
  return response;
}


static char *
error_object_string (const char *message, ...)
{
  cjson_t response;
  va_list arg_ptr;
  char *msg;

  va_start (arg_ptr, message);
  response = error_object_v (message, arg_ptr);
  va_end (arg_ptr);

  msg = xjson_Print (response);
  cJSON_Delete (response);
  return msg;
}



/*
 * Implementaion of the commands.
 */


static const char hlp_encrypt[] =
  "op:     \"encrypt\"\n"
  "keys:   Array of strings with the fingerprints or user-ids\n"
  "        of the keys to encrypt the data.  For a single key\n"
  "        a String may be used instead of an array.\n"
  "data:   Base64 encoded input data.\n"
  "\n"
  "Optional parameters:\n"
  "protocol:      Either \"openpgp\" (default) or \"cms\".\n"
  "\n"
  "Optional boolean flags (default is false):\n"
  "armor:         Request output in armored format.\n"
  "always-trust:  Request --always-trust option.\n"
  "no-encrypt-to: Do not use a default recipient.\n"
  "no-compress:   Do not compress the plaintext first.\n"
  "throw-keyids:  Request the --throw-keyids option.\n"
  "wrap:          Assume the input is an OpenPGP message.\n"
  "\n"
  "Response on success:\n"
  "type:   \"ciphertext\"\n"
  "data:   Unless armor mode is used a Base64 encoded binary\n"
  "        ciphertext.  In armor mode a string with an armored\n"
  "        OpenPGP or a PEM message.\n"
  "base64: Boolean indicating whether data is base64 encoded.";
static gpg_error_t
op_encrypt (cjson_t request, cjson_t *r_result)
{


  return 0;
}



static const char hlp_help[] =
  "The tool expects a JSON object with the request and responds with\n"
  "another JSON object.  Even on error a JSON object is returned.  The\n"
  "property \"op\" is mandatory and its string value selects the\n"
  "operation; if the property \"help\" with the value \"true\" exists, the\n"
  "operation is not performned but a string with the documentation\n"
  "returned.  To list all operations it is allowed to leave out \"op\" in\n"
  "help mode.  Supported values for \"op\" are:\n\n"
  "  encrypt     Encrypt data.\n"
  "  help        Help overview.";
static gpg_error_t
op_help (cjson_t request, cjson_t *r_result)
{
  gpg_error_t err = 0;
  cjson_t result = NULL;
  cjson_t j_tmp;
  char *buffer = NULL;
  const char *msg;

  j_tmp = cJSON_GetObjectItem (request, "interactive_help");
  if (opt_interactive && j_tmp && cjson_is_string (j_tmp))
    msg = buffer = xstrconcat (hlp_help, "\n", j_tmp->valuestring, NULL);
  else
    msg = hlp_help;

  result = cJSON_CreateObject ();
  if (!result)
    err = gpg_error_from_syserror ();
  if (!err)
    err = cjson_AddStringToObject (result, "type", "help");
  if (!err)
    err = cjson_AddStringToObject (result, "msg", msg);

  xfree (buffer);
  if (err)
    xfree (result);
  else
    *r_result = result;
  return err;
}



/* Process a request and return the response.  The response is a newly
 * allocated staring or NULL in case of an error.  */
static char *
process_request (const char *request)
{
  static struct {
    const char *op;
    gpg_error_t (*handler)(cjson_t request, cjson_t *r_result);
    const char * const helpstr;
  } optbl[] = {
    { "encrypt", op_encrypt, hlp_encrypt },


    { "help",    op_help,    hlp_help },
    { NULL }
  };
  gpg_error_t err = 0;
  size_t erroff;
  cjson_t json;
  cjson_t j_tmp, j_op;
  cjson_t response = NULL;
  int helpmode;
  const char *op;
  char *res;
  int idx;

  json = cJSON_Parse (request, &erroff);
  if (!json)
    {
      log_string (GPGRT_LOGLVL_INFO, request);
      log_info ("invalid JSON object at offset %zu\n", erroff);
      response = error_object ("invalid JSON object at offset %zu\n", erroff);
      goto leave;
    }

  j_tmp = cJSON_GetObjectItem (json, "help");
  helpmode = (j_tmp && cjson_is_true (j_tmp));

  j_op = cJSON_GetObjectItem (json, "op");
  if (!j_op || !cjson_is_string (j_op))
    {
      if (!helpmode)
        {
          response = error_object ("Property \"op\" missing");
          goto leave;
        }
      op = "help";  /* Help summary.  */
    }
  else
    op = j_op->valuestring;

  for (idx=0; optbl[idx].op; idx++)
    if (!strcmp (op, optbl[idx].op))
      break;
  if (optbl[idx].op)
    {
      if (helpmode && strcmp (op, "help"))
        {
          response = cJSON_CreateObject ();
          if (!response)
            err = gpg_error_from_syserror ();
          if (!err)
            err = cjson_AddStringToObject (response, "type", "help");
          if (!err)
            err = cjson_AddStringToObject (response, "op", op);
          if (!err)
            err = cjson_AddStringToObject (response, "msg", optbl[idx].helpstr);
        }
      else
        err = optbl[idx].handler (json, &response);
    }
  else  /* Operation not supported.  */
    {
      response = error_object ("Unknown operation '%s'", op);
      err = cjson_AddStringToObject (response, "op", op);
    }

 leave:
  cJSON_Delete (json);
  json = NULL;
  if (err)
    log_error ("failed to create the response: %s\n", gpg_strerror (err));
  if (response)
    {
      res = cJSON_Print (response);
      if (!res)
        log_error ("Printing JSON data failed\n");
      cJSON_Delete (response);
    }
  else
    res = NULL;

  return res;
}



/*
 *  Driver code
 */

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
process_meta_commands (const char *request)
{
  char *result = NULL;

  while (spacep (request))
    request++;

  if (!strncmp (request, "help", 4) && (spacep (request+4) || !request[4]))
    result = process_request ("{ \"op\": \"help\","
                              " \"interactive_help\": "
                              "\"\\nMeta commands:\\n"
                              "  ,help       This help\\n"
                              "  ,quit       Terminate process\""
                              "}");
  else if (!strncmp (request, "quit", 4) && (spacep (request+4) || !request[4]))
    exit (0);
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
interactive_repl (void)
{
  char *line = NULL;
  char *request = NULL;
  char *response = NULL;
  char *p;
  int first;

  es_setvbuf (es_stdin, NULL, _IONBF, 0);
  es_fprintf (es_stderr, "%s %s ready (enter \",help\" for help)\n",
              strusage (11), strusage (13));
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
            request = xstrconcat (request, "\n", line, NULL);
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
              response = process_meta_commands (request+1);
            }
          else if (request)
            {
              response = process_request (request);
            }
          xfree (request);
          request = NULL;

          if (response)
            {
              if (opt_interactive)
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


/* Read and process  asingle request.  */
static void
read_and_process_single_request (void)
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
              response = process_request (request);
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
native_messaging_repl (void)
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

  for (;;)
    {
      /* Read length.  Note that the protocol uses native endianess.
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
          /* Fixme: Shall we read the request t the bit bucket and
           * return an error reponse or just return an error reponse
           * and terminate?  Needs some testing.  */
          break;
        }

      /* Read request.  */
      request = xtrymalloc (nrequest);
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
          xfree (response);
          response = process_request (request);
        }
      nresponse = strlen (response);

      /* Write response */
      if (es_write (es_stdout, &nresponse, sizeof nresponse, &n))
        {
          err = gpg_error_from_syserror ();
          log_error ("error writing request header: %s\n", gpg_strerror (err));
          break;
        }
      if (n != sizeof nrequest)
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
    }

  xfree (response);
  xfree (request);
}



static const char *
my_strusage( int level )
{
  const char *p;

  switch (level)
    {
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
         CMD_LIBVERSION  = 501
  } cmd = CMD_DEFAULT;
  static ARGPARSE_OPTS opts[] = {
    ARGPARSE_c  (CMD_INTERACTIVE, "interactive", "Interactive REPL"),
    ARGPARSE_c  (CMD_SINGLE,      "single",      "Single request mode"),
    ARGPARSE_c  (CMD_LIBVERSION,  "lib-version", "Show library version"),
    ARGPARSE_end()
  };
  ARGPARSE_ARGS pargs = { &argc, &argv, 0 };

  set_strusage (my_strusage);

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

  while (arg_parse  (&pargs, opts))
    {
      switch (pargs.r_opt)
        {
        case CMD_INTERACTIVE:
          opt_interactive = 1;
          /* Fall trough.  */
        case CMD_SINGLE:
        case CMD_LIBVERSION:
          cmd = pargs.r_opt;
          break;

        default:
          pargs.err = ARGPARSE_PRINT_WARNING;
	  break;
        }
    }

  switch (cmd)
    {
    case CMD_DEFAULT:
      native_messaging_repl ();
      break;

    case CMD_SINGLE:
      read_and_process_single_request ();
      break;

    case CMD_INTERACTIVE:
      interactive_repl ();
      break;

    case CMD_LIBVERSION:
      printf ("Version from header: %s (0x%06x)\n",
              GPGME_VERSION, GPGME_VERSION_NUMBER);
      printf ("Version from binary: %s\n", gpgme_check_version (NULL));
      printf ("Copyright blurb ...:%s\n", gpgme_check_version ("\x01\x01"));
      break;
    }

  return 0;
}
