/* assuan-handler.c - dispatch commands 
 *	Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.
 *
 * This file is part of Assuan.
 *
 * Assuan is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Assuan is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA. 
 */

#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "assuan-defs.h"



#define spacep(p)  (*(p) == ' ' || *(p) == '\t')
#define digitp(a) ((a) >= '0' && (a) <= '9')

static int my_strcasecmp (const char *a, const char *b);



static int
dummy_handler (assuan_context_t ctx, char *line)
{
  return set_error (ctx, Server_Fault, "no handler registered");
}


static int
std_handler_nop (assuan_context_t ctx, char *line)
{
  return 0; /* okay */
}
  
static int
std_handler_cancel (assuan_context_t ctx, char *line)
{
  if (ctx->cancel_notify_fnc)
    ctx->cancel_notify_fnc (ctx);
  return set_error (ctx, Not_Implemented, NULL); 
}

static int
std_handler_option (assuan_context_t ctx, char *line)
{
  char *key, *value, *p;

  for (key=line; spacep (key); key++)
    ;
  if (!*key)
    return set_error (ctx, Syntax_Error, "argument required");
  if (*key == '=')
    return set_error (ctx, Syntax_Error, "no option name given");
  for (value=key; *value && !spacep (value) && *value != '='; value++)
    ;
  if (*value)
    {
      if (spacep (value))
        *value++ = 0; /* terminate key */
      for (; spacep (value); value++)
        ;
      if (*value == '=')
        {
          *value++ = 0; /* terminate key */
          for (; spacep (value); value++)
            ;
          if (!*value)
            return set_error (ctx, Syntax_Error, "option argument expected");
        }
      if (*value)
        {
          for (p = value + strlen(value) - 1; p > value && spacep (p); p--)
            ;
          if (p > value)
            *++p = 0; /* strip trailing spaces */
        }
    }

  if (*key == '-' && key[1] == '-' && key[2])
    key += 2; /* the double dashes are optional */
  if (*key == '-')
    return set_error (ctx, Syntax_Error,
                      "option should not begin with one dash");

  if (ctx->option_handler_fnc)
    return ctx->option_handler_fnc (ctx, key, value);
  return 0;
}
  
static int
std_handler_bye (assuan_context_t ctx, char *line)
{
  if (ctx->bye_notify_fnc)
    ctx->bye_notify_fnc (ctx);
  assuan_close_input_fd (ctx);
  assuan_close_output_fd (ctx);
  return -1; /* pretty simple :-) */
}
  
static int
std_handler_auth (assuan_context_t ctx, char *line)
{
  return set_error (ctx, Not_Implemented, NULL); 
}
  
static int
std_handler_reset (assuan_context_t ctx, char *line)
{
  if (ctx->reset_notify_fnc)
    ctx->reset_notify_fnc (ctx);
  assuan_close_input_fd (ctx);
  assuan_close_output_fd (ctx);
  _assuan_uds_close_fds (ctx);
  return 0;
}
  
static int
std_handler_end (assuan_context_t ctx, char *line)
{
  return set_error (ctx, Not_Implemented, NULL); 
}

assuan_error_t
assuan_command_parse_fd (assuan_context_t ctx, char *line, int *rfd)
{
  char *endp;

  if ((strncmp (line, "FD", 2) && strncmp (line, "fd", 2))
      || (line[2] != '=' && line[2] != '\0' && !spacep(&line[2])))
    return set_error (ctx, Syntax_Error, "FD[=<n>] expected");
  line += 2;
  if (*line == '=')
    {
      line ++;
      if (!digitp (*line))
	return set_error (ctx, Syntax_Error, "number required");
      *rfd = strtoul (line, &endp, 10);
      /* Remove that argument so that a notify handler won't see it. */
      memset (line, ' ', endp? (endp-line):strlen(line));

      if (*rfd == ctx->inbound.fd)
	return set_error (ctx, Parameter_Conflict, "fd same as inbound fd");
      if (*rfd == ctx->outbound.fd)
	return set_error (ctx, Parameter_Conflict, "fd same as outbound fd");
      return 0;
    }
  else
    /* Our peer has sent the file descriptor.  */
    return assuan_receivefd (ctx, rfd);
}

/* Format is INPUT FD=<n> */
static int
std_handler_input (assuan_context_t ctx, char *line)
{
  int rc, fd;

  rc = assuan_command_parse_fd (ctx, line, &fd);
  if (rc)
    return rc;
  ctx->input_fd = fd;
  if (ctx->input_notify_fnc)
    ctx->input_notify_fnc (ctx, line);
  return 0;
}

/* Format is OUTPUT FD=<n> */
static int
std_handler_output (assuan_context_t ctx, char *line)
{
  int rc, fd;

  rc = assuan_command_parse_fd (ctx, line, &fd);
  if (rc)
    return rc;
  ctx->output_fd = fd;
  if (ctx->output_notify_fnc)
    ctx->output_notify_fnc (ctx, line);
  return 0;
}



  

/* This is a table with the standard commands and handler for them.
   The table is used to initialize a new context and associate strings
   with default handlers */
static struct {
  const char *name;
  int (*handler)(assuan_context_t, char *line);
  int always; /* always initialize this command */
} std_cmd_table[] = {
  { "NOP",    std_handler_nop, 1 },
  { "CANCEL", std_handler_cancel, 1 },
  { "OPTION", std_handler_option, 1 },
  { "BYE",    std_handler_bye, 1 },
  { "AUTH",   std_handler_auth, 1 },
  { "RESET",  std_handler_reset, 1 },
  { "END",    std_handler_end, 1 },
              
  { "INPUT",  std_handler_input },
  { "OUTPUT", std_handler_output },
  { "OPTION", std_handler_option, 1 },
  { NULL }
};


/**
 * assuan_register_command:
 * @ctx: the server context
 * @cmd_name: A string with the command name
 * @handler: The handler function to be called or NULL to use a default
 *           handler.
 * 
 * Register a handler to be used for a given command.  Note that
 * several default handlers are already regsitered with a new context.
 * This function however allows to override them.
 * 
 * Return value: 0 on success or an error code
 **/
int
assuan_register_command (assuan_context_t ctx,
                         const char *cmd_name,
                         int (*handler)(assuan_context_t, char *))
{
  int i;
  const char *s;

  if (cmd_name && !*cmd_name)
    cmd_name = NULL;

  if (!cmd_name)
    return _assuan_error (ASSUAN_Invalid_Value);

  if (!handler)
    { /* find a default handler. */
      for (i=0; (s=std_cmd_table[i].name) && strcmp (cmd_name, s); i++)
        ;
      if (!s)
        { /* Try again but case insensitive. */
          for (i=0; (s=std_cmd_table[i].name)
                    && my_strcasecmp (cmd_name, s); i++)
            ;
        }
      if (s)
        handler = std_cmd_table[i].handler;
      if (!handler)
        handler = dummy_handler; /* Last resort is the dummy handler. */
    }
  
  if (!ctx->cmdtbl)
    {
      ctx->cmdtbl_size = 50;
      ctx->cmdtbl = xtrycalloc ( ctx->cmdtbl_size, sizeof *ctx->cmdtbl);
      if (!ctx->cmdtbl)
        return _assuan_error (ASSUAN_Out_Of_Core);
      ctx->cmdtbl_used = 0;
    }
  else if (ctx->cmdtbl_used >= ctx->cmdtbl_size)
    {
      struct cmdtbl_s *x;

      x = xtryrealloc ( ctx->cmdtbl, (ctx->cmdtbl_size+10) * sizeof *x);
      if (!x)
        return _assuan_error (ASSUAN_Out_Of_Core);
      ctx->cmdtbl = x;
      ctx->cmdtbl_size += 50;
    }

  ctx->cmdtbl[ctx->cmdtbl_used].name = cmd_name;
  ctx->cmdtbl[ctx->cmdtbl_used].handler = handler;
  ctx->cmdtbl_used++;
  return 0;
}

int
assuan_register_post_cmd_notify (assuan_context_t ctx,
                                 void (*fnc)(assuan_context_t, int))
{
  if (!ctx)
    return _assuan_error (ASSUAN_Invalid_Value);
  ctx->post_cmd_notify_fnc = fnc;
  return 0;
}

int
assuan_register_bye_notify (assuan_context_t ctx,
                            void (*fnc)(assuan_context_t))
{
  if (!ctx)
    return _assuan_error (ASSUAN_Invalid_Value);
  ctx->bye_notify_fnc = fnc;
  return 0;
}

int
assuan_register_reset_notify (assuan_context_t ctx,
                              void (*fnc)(assuan_context_t))
{
  if (!ctx)
    return _assuan_error (ASSUAN_Invalid_Value);
  ctx->reset_notify_fnc = fnc;
  return 0;
}

int
assuan_register_cancel_notify (assuan_context_t ctx,
                               void (*fnc)(assuan_context_t))
{
  if (!ctx)
    return _assuan_error (ASSUAN_Invalid_Value);
  ctx->cancel_notify_fnc = fnc;
  return 0;
}

int
assuan_register_option_handler (assuan_context_t ctx,
                               int (*fnc)(assuan_context_t,
                                          const char*, const char*))
{
  if (!ctx)
    return _assuan_error (ASSUAN_Invalid_Value);
  ctx->option_handler_fnc = fnc;
  return 0;
}

int
assuan_register_input_notify (assuan_context_t ctx,
                              void (*fnc)(assuan_context_t, const char *))
{
  if (!ctx)
    return _assuan_error (ASSUAN_Invalid_Value);
  ctx->input_notify_fnc = fnc;
  return 0;
}

int
assuan_register_output_notify (assuan_context_t ctx,
                              void (*fnc)(assuan_context_t, const char *))
{
  if (!ctx)
    return _assuan_error (ASSUAN_Invalid_Value);
  ctx->output_notify_fnc = fnc;
  return 0;
}


/* Helper to register the standards commands */
int
_assuan_register_std_commands (assuan_context_t ctx)
{
  int i, rc;

  for (i=0; std_cmd_table[i].name; i++)
    {
      if (std_cmd_table[i].always)
        {
          rc = assuan_register_command (ctx, std_cmd_table[i].name, NULL);
          if (rc)
            return rc;
        }
    } 
  return 0;
}



/* Process the special data lines.  The "D " has already been removed
   from the line.  As all handlers this function may modify the line.  */
static int
handle_data_line (assuan_context_t ctx, char *line, int linelen)
{
  return set_error (ctx, Not_Implemented, NULL);
}

/* like ascii_strcasecmp but assume that B is already uppercase */
static int
my_strcasecmp (const char *a, const char *b)
{
    if (a == b)
        return 0;

    for (; *a && *b; a++, b++)
      {
	if (((*a >= 'a' && *a <= 'z')? (*a&~0x20):*a) != *b)
	    break;
      }
    return *a == *b? 0 : (((*a >= 'a' && *a <= 'z')? (*a&~0x20):*a) - *b);
}

/* Parse the line, break out the command, find it in the command
   table, remove leading and white spaces from the arguments, call the
   handler with the argument line and return the error */
static int 
dispatch_command (assuan_context_t ctx, char *line, int linelen)
{
  char *p;
  const char *s;
  int shift, i;

  if (*line == 'D' && line[1] == ' ') /* divert to special handler */
    return handle_data_line (ctx, line+2, linelen-2);

  for (p=line; *p && *p != ' ' && *p != '\t'; p++)
    ;
  if (p==line)
    return set_error (ctx, Syntax_Error, "leading white-space"); 
  if (*p) 
    { /* Skip over leading WS after the keyword */
      *p++ = 0;
      while ( *p == ' ' || *p == '\t')
        p++;
    }
  shift = p - line;

  for (i=0; (s=ctx->cmdtbl[i].name); i++)
    {
      if (!strcmp (line, s))
        break;
    }
  if (!s)
    { /* and try case insensitive */
      for (i=0; (s=ctx->cmdtbl[i].name); i++)
        {
          if (!my_strcasecmp (line, s))
            break;
        }
    }
  if (!s)
    return set_error (ctx, Unknown_Command, NULL);
  line += shift;
  linelen -= shift;

/*    fprintf (stderr, "DBG-assuan: processing %s `%s'\n", s, line); */
  return ctx->cmdtbl[i].handler (ctx, line);
}




static int
process_request (assuan_context_t ctx)
{
  int rc;

  if (ctx->in_inquire)
    return _assuan_error (ASSUAN_Nested_Commands);

  rc = _assuan_read_line (ctx);
  if (rc)
    return rc;
  if (*ctx->inbound.line == '#' || !ctx->inbound.linelen)
    return 0; /* comment line - ignore */

  ctx->outbound.data.error = 0;
  ctx->outbound.data.linelen = 0;
  /* dispatch command and return reply */
  rc = dispatch_command (ctx, ctx->inbound.line, ctx->inbound.linelen);
  /* check from data write errors */
  if (ctx->outbound.data.fp)
    { /* Flush the data lines */
      fclose (ctx->outbound.data.fp);
      ctx->outbound.data.fp = NULL;
      if (!rc && ctx->outbound.data.error)
        rc = ctx->outbound.data.error;
    }
  else /* flush any data send w/o using the data fp */
    {
      assuan_send_data (ctx, NULL, 0);
      if (!rc && ctx->outbound.data.error)
        rc = ctx->outbound.data.error;
    }
  /* Error handling */
  if (!rc)
    {
      rc = assuan_write_line (ctx, ctx->okay_line? ctx->okay_line : "OK");
    }
  else if (err_is_eof (rc))
    { /* No error checking because the peer may have already disconnect. */ 
      assuan_write_line (ctx, "OK closing connection");
      ctx->finish_handler (ctx);
    }
  else 
    {
      char errline[300];

      if (rc < 100)
        sprintf (errline, "ERR %d server fault (%.50s)",
                 _assuan_error (ASSUAN_Server_Fault), assuan_strerror (rc));
      else
        {
          const char *text = ctx->err_no == rc? ctx->err_str:NULL;

#if defined(HAVE_W32_SYSTEM)
          unsigned int source, code;
          char ebuf[50];
          const char *esrc;

          source = ((rc >> 24) & 0xff);
          code = (rc & 0x00ffffff);
          if (source
              && !_assuan_gpg_strerror_r (rc, ebuf, sizeof ebuf)
              && (esrc=_assuan_gpg_strsource (rc)))
            {
              /* Assume this is an libgpg-error. */
              sprintf (errline, "ERR %d %.50s <%.30s>%s%.100s",
                       rc, ebuf, esrc,
                       text? " - ":"", text?text:"");
            }
          else
#elif defined(__GNUC__) && defined(__ELF__)
          /* If we have weak symbol support we try to use the error
             strings from libgpg-error without creating a dependency.
             They are used for debugging purposes only, so there is no
             problem if they are not available.  We need to make sure
             that we are using ELF because only this guarantees that
             weak symbol support is available in case GNU ld is not
             used.  It seems that old gcc versions don't implement the
             weak attribute properly but it works with the weak
             pragma. */

          unsigned int source, code;

          int gpg_strerror_r (unsigned int err, char *buf, size_t buflen)
            __attribute__ ((weak));
          const char *gpg_strsource (unsigned int err)
            __attribute__ ((weak));
#if __GNUC__ < 3
#pragma weak gpg_strerror_r
#pragma weak gpg_strsource
#endif

          source = ((rc >> 24) & 0xff);
          code = (rc & 0x00ffffff);
          if (source && gpg_strsource && gpg_strerror_r)
            {
              /* Assume this is an libgpg-error. */
              char ebuf[50];

              gpg_strerror_r (rc, ebuf, sizeof ebuf );
              sprintf (errline, "ERR %d %.50s <%.30s>%s%.100s",
                       rc,
                       ebuf,
                       gpg_strsource (rc),
                       text? " - ":"", text?text:"");
            }
          else
#endif /* __GNUC__  && __ELF__ */
            sprintf (errline, "ERR %d %.50s%s%.100s",
                     rc, assuan_strerror (rc), text? " - ":"", text?text:"");
        }
      rc = assuan_write_line (ctx, errline);
    }

  if (ctx->post_cmd_notify_fnc)
    ctx->post_cmd_notify_fnc (ctx, rc);

  ctx->confidential = 0;
  if (ctx->okay_line)
    {
      xfree (ctx->okay_line);
      ctx->okay_line = NULL;
    }
  return rc;
}

/**
 * assuan_process:
 * @ctx: assuan context
 * 
 * This function is used to handle the assuan protocol after a
 * connection has been established using assuan_accept().  This is the
 * main protocol handler.
 * 
 * Return value: 0 on success or an error code if the assuan operation
 * failed.  Note, that no error is returned for operational errors.
 **/
int
assuan_process (assuan_context_t ctx)
{
  int rc;

  do {
    rc = process_request (ctx);
  } while (!rc);

  if (err_is_eof (rc))
    rc = 0;

  return rc;
}


/**
 * assuan_process_next:
 * @ctx: Assuan context
 * 
 * Same as assuan_process() but the user has to provide the outer
 * loop.  He should loop as long as the return code is zero and stop
 * otherwise; -1 is regular end.
 * 
 * See also: assuan_get_active_fds()
 * Return value: -1 for end of server, 0 on success or an error code
 **/
int 
assuan_process_next (assuan_context_t ctx)
{
  return process_request (ctx);
}


/**
 * assuan_get_active_fds:
 * @ctx: Assuan context
 * @what: 0 for read fds, 1 for write fds
 * @fdarray: Caller supplied array to store the FDs
 * @fdarraysize: size of that array
 * 
 * Return all active filedescriptors for the given context.  This
 * function can be used to select on the fds and call
 * assuan_process_next() if there is an active one.  The first fd in
 * the array is the one used for the command connection.
 *
 * Note, that write FDs are not yet supported.
 * 
 * Return value: number of FDs active and put into @fdarray or -1 on
 * error which is most likely a too small fdarray.
 **/
int 
assuan_get_active_fds (assuan_context_t ctx, int what,
                       int *fdarray, int fdarraysize)
{
  int n = 0;

  if (!ctx || fdarraysize < 2 || what < 0 || what > 1)
    return -1;

  if (!what)
    {
      if (ctx->inbound.fd != -1)
        fdarray[n++] = ctx->inbound.fd;
    }
  else
    {
      if (ctx->outbound.fd != -1)
        fdarray[n++] = ctx->outbound.fd;
      if (ctx->outbound.data.fp)
        fdarray[n++] = fileno (ctx->outbound.data.fp);
    }

  return n;
}


/* Two simple wrappers to make the expected function types match. */
#ifdef HAVE_FUNOPEN
static int
fun1_cookie_write (void *cookie, const char *buffer, int orig_size)
{
  return _assuan_cookie_write_data (cookie, buffer, orig_size);
}
#endif /*HAVE_FUNOPEN*/
#ifdef HAVE_FOPENCOOKIE
static ssize_t
fun2_cookie_write (void *cookie, const char *buffer, size_t orig_size)
{
  return _assuan_cookie_write_data (cookie, buffer, orig_size);
}
#endif /*HAVE_FOPENCOOKIE*/

/* Return a FP to be used for data output.  The FILE pointer is valid
   until the end of a handler.  So a close is not needed.  Assuan does
   all the buffering needed to insert the status line as well as the
   required line wappping and quoting for data lines.

   We use GNU's custom streams here.  There should be an alternative
   implementaion for systems w/o a glibc, a simple implementation
   could use a child process */
FILE *
assuan_get_data_fp (assuan_context_t ctx)
{
#if defined (HAVE_FOPENCOOKIE) || defined (HAVE_FUNOPEN)
  if (ctx->outbound.data.fp)
    return ctx->outbound.data.fp;
  
#ifdef HAVE_FUNOPEN
  ctx->outbound.data.fp = funopen (ctx, 0, fun1_cookie_write,
				   0, _assuan_cookie_write_flush);
#else
  ctx->outbound.data.fp = funopen (ctx, 0, fun2_cookie_write,
				   0, _assuan_cookie_write_flush);
#endif                                   

  ctx->outbound.data.error = 0;
  return ctx->outbound.data.fp;
#else
  errno = ENOSYS;
  return NULL;
#endif
}


/* Set the text used for the next OK reponse.  This string is
   automatically reset to NULL after the next command. */
assuan_error_t
assuan_set_okay_line (assuan_context_t ctx, const char *line)
{
  if (!ctx)
    return _assuan_error (ASSUAN_Invalid_Value);
  if (!line)
    {
      xfree (ctx->okay_line);
      ctx->okay_line = NULL;
    }
  else
    {
      /* FIXME: we need to use gcry_is_secure() to test whether
         we should allocate the entire line in secure memory */
      char *buf = xtrymalloc (3+strlen(line)+1);
      if (!buf)
        return _assuan_error (ASSUAN_Out_Of_Core);
      strcpy (buf, "OK ");
      strcpy (buf+3, line);
      xfree (ctx->okay_line);
      ctx->okay_line = buf;
    }
  return 0;
}



assuan_error_t
assuan_write_status (assuan_context_t ctx,
                     const char *keyword, const char *text)
{
  char buffer[256];
  char *helpbuf;
  size_t n;
  assuan_error_t ae;

  if ( !ctx || !keyword)
    return _assuan_error (ASSUAN_Invalid_Value);
  if (!text)
    text = "";

  n = 2 + strlen (keyword) + 1 + strlen (text) + 1;
  if (n < sizeof (buffer))
    {
      strcpy (buffer, "S ");
      strcat (buffer, keyword);
      if (*text)
        {
          strcat (buffer, " ");
          strcat (buffer, text);
        }
      ae = assuan_write_line (ctx, buffer);
    }
  else if ( (helpbuf = xtrymalloc (n)) )
    {
      strcpy (helpbuf, "S ");
      strcat (helpbuf, keyword);
      if (*text)
        {
          strcat (helpbuf, " ");
          strcat (helpbuf, text);
        }
      ae = assuan_write_line (ctx, helpbuf);
      xfree (helpbuf);
    }
  else
    ae = 0;
  return ae;
}
