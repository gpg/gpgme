/* gpgme-tool.c - Assuan server exposing GnuPG Made Easy operations.
   Copyright (C) 2009, 2010 g10 Code GmbH

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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <ctype.h>
#include <stdarg.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif
#ifdef HAVE_ARGP_H
#include <argp.h>
#endif

#include <assuan.h>

#include "gpgme.h"

/* GCC attributes.  */
#if __GNUC__ >= 4 
# define GT_GCC_A_SENTINEL(a) __attribute__ ((sentinel(a)))
#else
# define GT_GCC_A_SENTINEL(a) 
#endif

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 5 )
# define GT_GCC_A_PRINTF(f, a)  __attribute__ ((format (printf,f,a)))
#else
# define GT_GCC_A_PRINTF(f, a)
#endif

#define DIM(v) (sizeof(v)/sizeof((v)[0]))
#define xtoi_1(p)   (*(p) <= '9'? (*(p)- '0'): \
                     *(p) <= 'F'? (*(p)-'A'+10):(*(p)-'a'+10))
#define xtoi_2(p)   ((xtoi_1(p) * 16) + xtoi_1((p)+1))



#ifndef HAVE_ARGP_H
/* Minimal argp implementation.  */

/* Differences to ARGP:
   argp_program_version: Required.
   argp_program_bug_address: Required.
   argp_program_version_hook: Not supported.
   argp_err_exit_status: Required.
   struct argp: Children and help_filter not supported.
   argp_domain: Not supported.
   struct argp_option: Group not supported.  Options are printed in
   order given.  Flags OPTION_ALIAS, OPTION_DOC and OPTION_NO_USAGE
   are not supported.
   argp_parse: No flags are supported (ARGP_PARSE_ARGV0, ARGP_NO_ERRS,
   ARGP_NO_ARGS, ARGP_IN_ORDER, ARGP_NO_HELP, ARGP_NO_EXIT,
   ARGP_LONG_ONLY, ARGP_SILENT).  ARGP must not be NULL.
   argp_help: Flag ARGP_HELP_LONG_ONLY not supported.
   argp_state: argc, argv, next may not be modified and should not be used.  */

extern const char *argp_program_version;
extern const char *argp_program_bug_address;
extern error_t argp_err_exit_status;

struct argp_option
{
  const char *name;
  int key;
  const char *arg;
#define OPTION_ARG_OPTIONAL 0x1
#define OPTION_HIDDEN 0x2
  int flags;
  const char *doc;
  int group;
};

struct argp;
struct argp_state
{
  const struct argp *const root_argp;
  int argc;
  char **argv;
  int next;
  unsigned flags;
  unsigned arg_num;
  int quoted;
  void *input;
  void **child_inputs;
  void *hook;
  char *name;
  FILE *err_stream;
  FILE *out_stream;
  void *pstate;
};

#ifdef EDEADLK
# define ARGP_ERR_UNKNOWN EDEADLK /* POSIX */
#else
# define ARGP_ERR_UNKNOWN EDEADLOCK /* *GNU/kFreebsd does not define this) */
#endif
#define ARGP_KEY_ARG 0
#define ARGP_KEY_ARGS 0x1000006
#define ARGP_KEY_END 0x1000001
#define ARGP_KEY_NO_ARGS 0x1000002
#define ARGP_KEY_INIT 0x1000003
#define ARGP_KEY_FINI 0x1000007
#define ARGP_KEY_SUCCESS 0x1000004
#define ARGP_KEY_ERROR 0x1000005
typedef error_t (*argp_parser_t) (int key, char *arg, struct argp_state *state);

struct argp
{
  const struct argp_option *options;
  argp_parser_t parser;
  const char *args_doc;
  const char *doc;

  const struct argp_child *children;
  char *(*help_filter) (int key, const char *text, void *input);
  const char *argp_domain;
};

#define ARGP_HELP_USAGE ARGP_HELP_SHORT_USAGE
#define ARGP_HELP_SHORT_USAGE 0x02
#define ARGP_HELP_SEE 0x04
#define ARGP_HELP_LONG 0x08
#define ARGP_HELP_PRE_DOC 0x10
#define ARGP_HELP_POST_DOC 0x20
#define ARGP_HELP_DOC (ARGP_HELP_PRE_DOC | ARGP_HELP_POST_DOC)
#define ARGP_HELP_BUG_ADDR 0x40
#define ARGP_HELP_EXIT_ERR 0x100
#define ARGP_HELP_EXIT_OK 0x200
#define ARGP_HELP_STD_ERR (ARGP_HELP_SEE | ARGP_HELP_EXIT_ERR)
#define ARGP_HELP_STD_USAGE \
  (ARGP_HELP_SHORT_USAGE | ARGP_HELP_SEE | ARGP_HELP_EXIT_ERR)
#define ARGP_HELP_STD_HELP \
  (ARGP_HELP_SHORT_USAGE | ARGP_HELP_LONG | ARGP_HELP_EXIT_OK	\
   | ARGP_HELP_DOC | ARGP_HELP_BUG_ADDR)


void argp_error (const struct argp_state *state, 
                 const char *fmt, ...) GT_GCC_A_PRINTF(2, 3);
  


char *
_argp_pname (char *name)
{
  char *pname = name;
  char *bname = strrchr (pname, '/');
  if (! bname)
    bname = strrchr (pname, '\\');
  if (bname)
    pname = bname + 1;
  return pname;
}


void
_argp_state_help (const struct argp *argp, const struct argp_state *state,
		  FILE *stream, unsigned flags, char *name)
{
  if (state)
    name = state->name;

  if (flags & ARGP_HELP_SHORT_USAGE)
    fprintf (stream, "Usage: %s [OPTIONS...] %s\n", name, argp->args_doc);
  if (flags & ARGP_HELP_SEE)
    fprintf (stream, "Try `%s --help' or `%s --usage' for more information.\n",
	     name, name);
  if (flags & ARGP_HELP_PRE_DOC)
    {
      char buf[1024];
      char *end;
      strncpy (buf, argp->doc, sizeof (buf));
      buf[sizeof (buf) - 1] = '\0';
      end = strchr (buf, '\v');
      if (end)
	*end = '\0';
      fprintf (stream, "%s\n%s", buf, buf[0] ? "\n" : "");
    }
  if (flags & ARGP_HELP_LONG)
    {
      const struct argp_option *opt = argp->options;
      while (opt->key)
	{
	  #define NSPACES 29
	  char spaces[NSPACES + 1] = "                              ";
	  int len = 0;
	  fprintf (stream, "  ");
	  len += 2;
	  if (isascii (opt->key))
	    {
	      fprintf (stream, "-%c", opt->key);
	      len += 2;
	      if (opt->name)
		{
		  fprintf (stream, ", ");
		  len += 2;
		}
	    }
	  if (opt->name)
	    {
	      fprintf (stream, "--%s", opt->name);
	      len += 2 + strlen (opt->name);
	    }
	  if (opt->arg && (opt->flags & OPTION_ARG_OPTIONAL))
	    {
	      fprintf (stream, "[=%s]", opt->arg);
	      len += 3 + strlen (opt->arg);
	    }
	  else if (opt->arg)
	    {
	      fprintf (stream, "=%s", opt->arg);
	      len += 1 + strlen (opt->arg);
	    }
	  if (len >= NSPACES)
	    len = NSPACES - 1;
	  spaces[NSPACES - len] = '\0';
	  fprintf (stream, "%s%s\n", spaces, opt->doc);
	  opt++;
	}
      fprintf (stream, "  -?, --help                 Give this help list\n");
      fprintf (stream, "      --usage                Give a short usage "
	       "message\n");
    }
  if (flags & ARGP_HELP_POST_DOC)
    {
      char buf[1024];
      char *end;
      strncpy (buf, argp->doc, sizeof (buf));
      buf[sizeof (buf) - 1] = '\0';
      end = strchr (buf, '\v');
      if (end)
	{
	  end++;
	  if (*end)
	    fprintf (stream, "\n%s\n", end);
	}
      fprintf (stream, "\nMandatory or optional arguments to long options are also mandatory or optional\n");
      fprintf (stream, "for any corresponding short options.\n");
    }
  if (flags & ARGP_HELP_BUG_ADDR)
    fprintf (stream, "\nReport bugs to %s.\n", argp_program_bug_address);

  if (flags & ARGP_HELP_EXIT_ERR)
    exit (argp_err_exit_status);
  if (flags & ARGP_HELP_EXIT_OK)
    exit (0);
}


void
argp_usage (const struct argp_state *state)
{
  _argp_state_help (state->root_argp, state, state->err_stream,
		    ARGP_HELP_STD_USAGE, state->name);
}


void
argp_state_help (const struct argp_state *state, FILE *stream, unsigned flags)
{
  _argp_state_help (state->root_argp, state, stream, flags, state->name);
}


void
argp_error (const struct argp_state *state, const char *fmt, ...)
{
  va_list ap;

  fprintf (state->err_stream, "%s: ", state->name);
  va_start (ap, fmt);
  vfprintf (state->err_stream, fmt, ap);
  va_end (ap);
  fprintf (state->err_stream, "\n");
  argp_state_help (state, state->err_stream, ARGP_HELP_STD_ERR);
  exit (argp_err_exit_status);
}


void
argp_help (const struct argp *argp, FILE *stream, unsigned flags, char *name)
{
  _argp_state_help (argp, NULL, stream, flags, name);
}


error_t
argp_parse (const struct argp *argp, int argc,
	    char **argv, unsigned flags, int *arg_index, void *input)
{
  int rc = 0;
  struct argp_state state = { argp, argc, argv, 1, flags, 0, 0, input,
			      NULL, NULL, _argp_pname (argv[0]),
			      stderr, stdout, NULL };
  /* All non-option arguments are collected at the beginning of
     &argv[1] during processing.  This is a counter for their number.  */
  int non_opt_args = 0;

  rc = argp->parser (ARGP_KEY_INIT, NULL, &state);
  if (rc && rc != ARGP_ERR_UNKNOWN)
    goto argperror;

  while (state.next < state.argc - non_opt_args)
    {
      int idx = state.next;
      state.next++;

      if (! strcasecmp (state.argv[idx], "--"))
	{
	  state.quoted = idx;
	  continue;
	}

      if (state.quoted || state.argv[idx][0] != '-')
	{
	  char *arg_saved = state.argv[idx];
	  non_opt_args++;
	  memmove (&state.argv[idx], &state.argv[idx + 1],
		   (state.argc - 1 - idx) * sizeof (char *));
	  state.argv[argc - 1] = arg_saved;
	  state.next--;
	}
      else if (! strcasecmp (state.argv[idx], "--help")
	       || !strcmp (state.argv[idx], "-?"))
	{
	  argp_state_help (&state, state.out_stream, ARGP_HELP_STD_HELP);
	}
      else if (! strcasecmp (state.argv[idx], "--usage"))
	{
	  argp_state_help (&state, state.out_stream,
			   ARGP_HELP_USAGE | ARGP_HELP_EXIT_OK);
	}
      else if (! strcasecmp (state.argv[idx], "--version")
	       || !strcmp (state.argv[idx], "-V"))
	{
	  fprintf (state.out_stream, "%s\n", argp_program_version);
	  exit (0);
	}
      else
	{
	  /* Search for option and call parser with its KEY.  */
	  int key = ARGP_KEY_ARG; /* Just some dummy value.  */
	  const struct argp_option *opt = argp->options;
	  char *arg = NULL;
	  int found = 0;

	  /* Check for --opt=value syntax.  */
	  arg = strchr (state.argv[idx], '=');
	  if (arg)
	    {
	      *arg = '\0';
	      arg++;
	    }
	    
	  if (state.argv[idx][1] != '-')
	    key = state.argv[idx][1];
	  
	  while (! found && opt->key)
	    {
	      if (key == opt->key
		  || (key == ARGP_KEY_ARG
		      && ! strcasecmp (&state.argv[idx][2], opt->name)))
		{
		  if (arg && !opt->arg)
		    argp_error (&state, "Option %s does not take an argument",
				state.argv[idx]);
		  if (opt->arg && state.next < state.argc
		      && state.argv[idx + 1][0] != '-')
		    {
		      arg = state.argv[idx + 1];
		      state.next++;
		    }
		  if (opt->arg && !(opt->flags & OPTION_ARG_OPTIONAL))
		    argp_error (&state, "Option %s requires an argument",
				state.argv[idx]);

		  rc = argp->parser (opt->key, arg, &state);
		  if (rc == ARGP_ERR_UNKNOWN)
		    break;
		  else if (rc)
		    goto argperror;
		  found = 1;
		}
	      opt++;
	    }
	  if (! found)
	    argp_error (&state, "Unknown option %s", state.argv[idx]);
	}
    }

  while (state.next < state.argc)
    {
      /* Call parser for all non-option args.  */
      int idx = state.next;
      state.next++;
      rc = argp->parser (ARGP_KEY_ARG, state.argv[idx], &state);
      if (rc && rc != ARGP_ERR_UNKNOWN)
	goto argperror;
      if (rc == ARGP_ERR_UNKNOWN)
	{
	  int old_next = state.next;
	  rc = argp->parser (ARGP_KEY_ARGS, NULL, &state);
	  if (rc == ARGP_ERR_UNKNOWN)
	    {
	      argp_error (&state, "Too many arguments");
	      goto argperror;
	    }
	  if (! rc && state.next == old_next)
	    {
	      state.arg_num += state.argc - state.next;
	      state.next = state.argc;
	    }
	}
      else
	state.arg_num++;
    }

  if (state.arg_num == 0)
    {
      rc = argp->parser (ARGP_KEY_NO_ARGS, NULL, &state);
      if (rc && rc != ARGP_ERR_UNKNOWN)
	goto argperror;
    }
  if (state.next == state.argc)
    {
      rc = argp->parser (ARGP_KEY_END, NULL, &state);
      if (rc && rc != ARGP_ERR_UNKNOWN)
	goto argperror;
    }
  rc = argp->parser (ARGP_KEY_FINI, NULL, &state);
  if (rc && rc != ARGP_ERR_UNKNOWN)
    goto argperror;
  
  rc = 0;
  argp->parser (ARGP_KEY_SUCCESS, NULL, &state);

 argperror:
  if (rc)
    {
      argp_error (&state, "unexpected error: %s", strerror (rc));
      argp->parser (ARGP_KEY_ERROR, NULL, &state);
    }

  argp->parser (ARGP_KEY_FINI, NULL, &state);

  if (arg_index)
    *arg_index = state.next - 1;

  return 0;
}
#endif


/* SUPPORT.  */
FILE *log_stream;
char *program_name = "gpgme-tool";

#define spacep(p)   (*(p) == ' ' || *(p) == '\t')


void log_error (int status, gpg_error_t errnum, 
                const char *fmt, ...) GT_GCC_A_PRINTF(3,4);


void
log_init (void)
{
  log_stream = stderr;
}


void
log_error (int status, gpg_error_t errnum, const char *fmt, ...)
{
  va_list ap;

  fprintf (log_stream, "%s: ", program_name);
  va_start (ap, fmt);
  vfprintf (log_stream, fmt, ap);
  va_end (ap);
  if (errnum)
    fprintf (log_stream, ": %s <%s>", gpg_strerror (errnum),
	     gpg_strsource (errnum));
  fprintf (log_stream, "\n");
  if (status)
    exit (status);
}


/* Note that it is sufficient to allocate the target string D as long
   as the source string S, i.e.: strlen(s)+1;.  D == S is allowed.  */
static void
strcpy_escaped_plus (char *d, const char *s)
{
  while (*s)
    {
      if (*s == '%' && s[1] && s[2])
        { 
          s++;
          *d++ = xtoi_2 (s);
          s += 2;
        }
      else if (*s == '+')
        *d++ = ' ', s++;
      else
        *d++ = *s++;
    }
  *d = 0; 
}


/* Check whether the option NAME appears in LINE.  */
static int
has_option (const char *line, const char *name)
{
  const char *s;
  int n = strlen (name);

  s = strstr (line, name);
  return (s && (s == line || spacep (s-1)) && (!s[n] || spacep (s+n)));
}

/* Skip over options.  It is assumed that leading spaces have been
   removed (this is the case for lines passed to a handler from
   assuan).  Blanks after the options are also removed.  */
static char *
skip_options (char *line)
{
  while ( *line == '-' && line[1] == '-' )
    {
      while (*line && !spacep (line))
        line++;
      while (spacep (line))
        line++;
    }
  return line;
}




typedef gpg_error_t (*result_xml_write_cb_t) (void *hook, const void *buf,
					      size_t len);

struct result_xml_state
{
  int indent;
  result_xml_write_cb_t cb;
  void *hook;

#define MAX_TAGS 20
  int next_tag;
  char *tag[MAX_TAGS];
  int had_data[MAX_TAGS];
};


void
result_init (struct result_xml_state *state, int indent,
	     result_xml_write_cb_t cb, void *hook)
{
  memset (state, '\0', sizeof (*state));
  state->indent = indent;
  state->cb = cb;
  state->hook = hook;
}


gpg_error_t
result_xml_indent (struct result_xml_state *state)
{
  char spaces[state->indent + 1];
  int i;
  for (i = 0; i < state->indent; i++)
    spaces[i] = ' ';
  spaces[i] = '\0';
  return (*state->cb) (state->hook, spaces, i);
}


gpg_error_t
result_xml_tag_start (struct result_xml_state *state, char *name, ...)
{
  result_xml_write_cb_t cb = state->cb;
  void *hook = state->hook;
  va_list ap;
  char *attr;
  char *attr_val;

  va_start (ap, name);

  if (state->next_tag > 0)
    {
      if (! state->had_data[state->next_tag - 1])
	{
	  (*cb) (hook, ">\n", 2);
	  (*cb) (hook, NULL, 0);
	}
      state->had_data[state->next_tag - 1] = 1;
    }

  result_xml_indent (state);
  (*cb) (hook, "<", 1);
  (*cb) (hook, name, strlen (name));

  state->tag[state->next_tag] = name;
  state->had_data[state->next_tag] = 0;
  state->indent += 2;
  state->next_tag++;
  
  while (1)
    {
      attr = va_arg (ap, char *);
      if (attr == NULL)
	break;

      attr_val = va_arg (ap, char *);
      if (attr_val == NULL)
	attr_val = "(null)";

      (*cb) (hook, " ", 1);
      (*cb) (hook, attr, strlen (attr));
      (*cb) (hook, "=\"", 2);
      (*cb) (hook, attr_val, strlen (attr_val));
      (*cb) (hook, "\"", 1);
    }
  va_end (ap);
  return 0;
}


gpg_error_t
result_xml_tag_data (struct result_xml_state *state, char *data)
{
  result_xml_write_cb_t cb = state->cb;
  void *hook = state->hook;

  if (state->had_data[state->next_tag - 1])
    {
      (*cb) (hook, "\n", 2);
      (*cb) (hook, NULL, 0);
      result_xml_indent (state);
    }
  else
    (*cb) (hook, ">", 1);
  state->had_data[state->next_tag - 1] = 2;

  (*cb) (hook, data, strlen (data));

  return 0;
}


gpg_error_t
result_xml_tag_end (struct result_xml_state *state)
{
  result_xml_write_cb_t cb = state->cb;
  void *hook = state->hook;

  state->next_tag--;
  state->indent -= 2;

  if (state->had_data[state->next_tag])
    {
      if (state->had_data[state->next_tag] == 1)
	result_xml_indent (state);
      (*cb) (hook, "</", 2);
      (*cb) (hook, state->tag[state->next_tag],
	     strlen (state->tag[state->next_tag]));
      (*cb) (hook, ">\n", 2);
      (*cb) (hook, NULL, 0);
    }
  else
    {
      (*cb) (hook, " />\n", 4);
      (*cb) (hook, NULL, 0);
    }
  return 0;
}


gpg_error_t
result_add_error (struct result_xml_state *state, char *name, gpg_error_t err)
{		  
  char code[20];
  char msg[1024];
  snprintf (code, sizeof (code) - 1, "0x%x", err);
  snprintf (msg, sizeof (msg) - 1, "%s &lt;%s&gt;",
	    gpg_strerror (err), gpg_strsource (err));
  result_xml_tag_start (state, name, "value", code, NULL);
  result_xml_tag_data (state, msg);
  result_xml_tag_end (state);
  return 0;
}


gpg_error_t
result_add_pubkey_algo (struct result_xml_state *state,
			char *name, gpgme_pubkey_algo_t algo)
{		  
  char code[20];
  char msg[80];
  snprintf (code, sizeof (code) - 1, "0x%x", algo);
  snprintf (msg, sizeof (msg) - 1, "%s",
	    gpgme_pubkey_algo_name (algo));
  result_xml_tag_start (state, name, "value", code, NULL);
  result_xml_tag_data (state, msg);
  result_xml_tag_end (state);
  return 0;
}


gpg_error_t
result_add_hash_algo (struct result_xml_state *state,
			 char *name, gpgme_hash_algo_t algo)
{		  
  char code[20];
  char msg[80];
  snprintf (code, sizeof (code) - 1, "0x%x", algo);
  snprintf (msg, sizeof (msg) - 1, "%s",
	    gpgme_hash_algo_name (algo));
  result_xml_tag_start (state, name, "value", code, NULL);
  result_xml_tag_data (state, msg);
  result_xml_tag_end (state);
  return 0;
}


gpg_error_t
result_add_keyid (struct result_xml_state *state, char *name, char *keyid)
{		  
  result_xml_tag_start (state, name, NULL);
  result_xml_tag_data (state, keyid);
  result_xml_tag_end (state);
  return 0;
}


gpg_error_t
result_add_fpr (struct result_xml_state *state, char *name, char *fpr)
{		  
  result_xml_tag_start (state, name, NULL);
  result_xml_tag_data (state, fpr);
  result_xml_tag_end (state);
  return 0;
}


gpg_error_t
result_add_timestamp (struct result_xml_state *state, char *name,
		      unsigned int timestamp)
{
  char code[20];

  snprintf (code, sizeof (code) - 1, "%ui", timestamp);
  result_xml_tag_start (state, name, "unix", code, NULL);
  result_xml_tag_end (state);
  return 0;
}


gpg_error_t
result_add_sig_mode (struct result_xml_state *state, char *name,
		     gpgme_sig_mode_t sig_mode)
{		  
  char *mode;
  char code[20];

  snprintf (code, sizeof (code) - 1, "%i", sig_mode);
  switch (sig_mode)
    {
    case GPGME_SIG_MODE_NORMAL:
      mode = "normal";
      break;
    case GPGME_SIG_MODE_DETACH:
      mode = "detach";
      break;
    case GPGME_SIG_MODE_CLEAR:
      mode = "clear";
      break;
    default:
      mode = "unknown";
    }

  result_xml_tag_start (state, name, "type", mode, "value", code, NULL);
  result_xml_tag_data (state, mode);
  result_xml_tag_end (state);
  return 0;
}


gpg_error_t
result_add_value (struct result_xml_state *state,
		  char *name, unsigned int val)
{		  
  char code[20];

  snprintf (code, sizeof (code) - 1, "0x%x", val);
  result_xml_tag_start (state, name, "value", code, NULL);
  result_xml_tag_end (state);
  return 0;
}


gpg_error_t
result_add_string (struct result_xml_state *state,
		   char *name, char *str)
{		  
  result_xml_tag_start (state, name, NULL);
  result_xml_tag_data (state, str);
  result_xml_tag_end (state);
  return 0;
}


gpg_error_t
result_encrypt_to_xml (gpgme_ctx_t ctx, int indent,
		       result_xml_write_cb_t cb, void *hook)
{
  struct result_xml_state state;
  gpgme_encrypt_result_t res = gpgme_op_encrypt_result (ctx);
  gpgme_invalid_key_t inv_recp;

  if (! res)
    return 0;

  result_init (&state, indent, cb, hook);
  result_xml_tag_start (&state, "encrypt-result", NULL);

  inv_recp = res->invalid_recipients;
  if (inv_recp)
    {
      result_xml_tag_start (&state, "invalid-recipients", NULL);
      
      while (inv_recp)
	{
	  result_xml_tag_start (&state, "invalid-key", NULL);
	  if (inv_recp->fpr)
	    result_add_fpr (&state, "fpr", inv_recp->fpr);
	  result_add_error (&state, "reason", inv_recp->reason);
	  result_xml_tag_end (&state);
	  inv_recp = inv_recp->next;
	}
      result_xml_tag_end (&state);
    }
  result_xml_tag_end (&state);
  
  return 0;
}


gpg_error_t
result_decrypt_to_xml (gpgme_ctx_t ctx, int indent,
		       result_xml_write_cb_t cb, void *hook)
{
  struct result_xml_state state;
  gpgme_decrypt_result_t res = gpgme_op_decrypt_result (ctx);
  gpgme_recipient_t recp;

  if (! res)
    return 0;

  result_init (&state, indent, cb, hook);
  result_xml_tag_start (&state, "decrypt-result", NULL);

  if (res->file_name)
    {
      result_xml_tag_start (&state, "file-name", NULL);
      result_xml_tag_data (&state, res->file_name);
      result_xml_tag_end (&state);
    }
  if (res->unsupported_algorithm)
    {
      result_xml_tag_start (&state, "unsupported-alogorithm", NULL);
      result_xml_tag_data (&state, res->unsupported_algorithm);
      result_xml_tag_end (&state);
    }
  if (res->wrong_key_usage)
    {
      result_xml_tag_start (&state, "wrong-key-usage", NULL);
      result_xml_tag_end (&state);
    }

  recp = res->recipients;
  if (recp)
    {
      result_xml_tag_start (&state, "recipients", NULL);
      while (recp)
	{
	  result_xml_tag_start (&state, "recipient", NULL);
	  result_add_keyid (&state, "keyid", recp->keyid);
	  result_add_pubkey_algo (&state, "pubkey-algo", recp->pubkey_algo);
	  result_add_error (&state, "status", recp->status);
	  result_xml_tag_end (&state);
	  recp = recp->next;
	}
      result_xml_tag_end (&state);
    }
  result_xml_tag_end (&state);
  
  return 0;
}


gpg_error_t
result_sign_to_xml (gpgme_ctx_t ctx, int indent,
		    result_xml_write_cb_t cb, void *hook)
{
  struct result_xml_state state;
  gpgme_sign_result_t res = gpgme_op_sign_result (ctx);
  gpgme_invalid_key_t inv_key;
  gpgme_new_signature_t new_sig;

  if (! res)
    return 0;

  result_init (&state, indent, cb, hook);
  result_xml_tag_start (&state, "sign-result", NULL);

  inv_key = res->invalid_signers;
  if (inv_key)
    {
      result_xml_tag_start (&state, "invalid-signers", NULL);
      
      while (inv_key)
	{
	  result_xml_tag_start (&state, "invalid-key", NULL);
	  if (inv_key->fpr)
	    result_add_fpr (&state, "fpr", inv_key->fpr);
	  result_add_error (&state, "reason", inv_key->reason);
	  result_xml_tag_end (&state);
	  inv_key = inv_key->next;
	}
      result_xml_tag_end (&state);
    }

  new_sig = res->signatures;
  if (new_sig)
    {
      result_xml_tag_start (&state, "signatures", NULL);

      while (new_sig)
	{
	  result_xml_tag_start (&state, "new-signature", NULL);
	  result_add_sig_mode (&state, "type", new_sig->type);
	  result_add_pubkey_algo (&state, "pubkey-algo", new_sig->pubkey_algo);
	  result_add_hash_algo (&state, "hash-algo", new_sig->hash_algo);
	  result_add_timestamp (&state, "timestamp", new_sig->timestamp);
	  if (new_sig->fpr)
	    result_add_fpr (&state, "fpr", new_sig->fpr);
	  result_add_value (&state, "sig-class", new_sig->sig_class);

	  result_xml_tag_end (&state);
	  new_sig = new_sig->next;
	}
      result_xml_tag_end (&state);
    }

  result_xml_tag_end (&state);
  
  return 0;
}


gpg_error_t
result_verify_to_xml (gpgme_ctx_t ctx, int indent,
		      result_xml_write_cb_t cb, void *hook)
{
  struct result_xml_state state;
  gpgme_verify_result_t res = gpgme_op_verify_result (ctx);
  gpgme_signature_t sig;

  if (! res)
    return 0;

  result_init (&state, indent, cb, hook);
  result_xml_tag_start (&state, "verify-result", NULL);

  if (res->file_name)
    {
      result_xml_tag_start (&state, "file-name", NULL);
      result_xml_tag_data (&state, res->file_name);
      result_xml_tag_end (&state);
    }

  sig = res->signatures;
  if (sig)
    {
      result_xml_tag_start (&state, "signatures", NULL);

      while (sig)
	{
	  result_xml_tag_start (&state, "signature", NULL);
	  
	  /* FIXME: Could be done better. */
	  result_add_value (&state, "summary", sig->summary);
	  if (sig->fpr)
	    result_add_fpr (&state, "fpr", sig->fpr);
	  result_add_error (&state, "status", sig->status);
	  /* FIXME: notations */
	  result_add_timestamp (&state, "timestamp", sig->timestamp);
	  result_add_timestamp (&state, "exp-timestamp", sig->exp_timestamp);
	  result_add_value (&state, "wrong-key-usage", sig->wrong_key_usage);
	  result_add_value (&state, "pka-trust", sig->pka_trust);
	  result_add_value (&state, "chain-model", sig->chain_model);
	  result_add_value (&state, "validity", sig->validity);
	  result_add_error (&state, "validity-reason", sig->validity_reason);
	  result_add_pubkey_algo (&state, "pubkey-algo", sig->pubkey_algo);
	  result_add_hash_algo (&state, "hash-algo", sig->hash_algo);
	  if (sig->pka_address)
	    result_add_string (&state, "pka_address", sig->pka_address);
	  
	  result_xml_tag_end (&state);
	  sig = sig->next;
	}
      result_xml_tag_end (&state);
    }

  result_xml_tag_end (&state);
  
  return 0;
}


gpg_error_t
result_import_to_xml (gpgme_ctx_t ctx, int indent,
		      result_xml_write_cb_t cb, void *hook)
{
  struct result_xml_state state;
  gpgme_import_result_t res = gpgme_op_import_result (ctx);
  gpgme_import_status_t stat;

  if (! res)
    return 0;

  result_init (&state, indent, cb, hook);
  result_xml_tag_start (&state, "import-result", NULL);

  result_add_value (&state, "considered", res->considered);
  result_add_value (&state, "no-user-id", res->no_user_id);
  result_add_value (&state, "imported", res->imported);
  result_add_value (&state, "imported-rsa", res->imported_rsa);
  result_add_value (&state, "unchanged", res->unchanged);
  result_add_value (&state, "new-user-ids", res->new_user_ids);
  result_add_value (&state, "new-sub-keys", res->new_sub_keys);
  result_add_value (&state, "new-signatures", res->new_signatures);
  result_add_value (&state, "new-revocations", res->new_revocations);
  result_add_value (&state, "secret-read", res->secret_read);
  result_add_value (&state, "secret-imported", res->secret_imported);
  result_add_value (&state, "secret-unchanged", res->secret_unchanged);
  result_add_value (&state, "skipped-new-keys", res->skipped_new_keys);
  result_add_value (&state, "not-imported", res->not_imported);

  stat = res->imports;
  if (stat)
    {
      result_xml_tag_start (&state, "imports", NULL);
      
      while (stat)
	{
	  result_xml_tag_start (&state, "import-status", NULL);

	  if (stat->fpr)
	    result_add_fpr (&state, "fpr", stat->fpr);
	  result_add_error (&state, "result", stat->result);
	  /* FIXME: Could be done better. */
	  result_add_value (&state, "status", stat->status);

	  result_xml_tag_end (&state);
	  stat = stat->next;
	}
      result_xml_tag_end (&state);
    }

  result_xml_tag_end (&state);
  
  return 0;
}


gpg_error_t
result_genkey_to_xml (gpgme_ctx_t ctx, int indent,
		      result_xml_write_cb_t cb, void *hook)
{
  struct result_xml_state state;
  gpgme_genkey_result_t res = gpgme_op_genkey_result (ctx);

  if (! res)
    return 0;

  result_init (&state, indent, cb, hook);
  result_xml_tag_start (&state, "genkey-result", NULL);

  result_add_value (&state, "primary", res->primary);
  result_add_value (&state, "sub", res->sub);
  if (res->fpr)
    result_add_fpr (&state, "fpr", res->fpr);

  result_xml_tag_end (&state);
  
  return 0;
}


gpg_error_t
result_keylist_to_xml (gpgme_ctx_t ctx, int indent,
		      result_xml_write_cb_t cb, void *hook)
{
  struct result_xml_state state;
  gpgme_keylist_result_t res = gpgme_op_keylist_result (ctx);

  if (! res)
    return 0;

  result_init (&state, indent, cb, hook);
  result_xml_tag_start (&state, "keylist-result", NULL);

  result_add_value (&state, "truncated", res->truncated);

  result_xml_tag_end (&state);
  
  return 0;
}


gpg_error_t
result_vfs_mount_to_xml (gpgme_ctx_t ctx, int indent,
			 result_xml_write_cb_t cb, void *hook)
{
  struct result_xml_state state;
  gpgme_vfs_mount_result_t res = gpgme_op_vfs_mount_result (ctx);

  if (! res)
    return 0;

  result_init (&state, indent, cb, hook);
  result_xml_tag_start (&state, "vfs-mount-result", NULL);

  result_add_string (&state, "mount-dir", res->mount_dir);

  result_xml_tag_end (&state);
  
  return 0;
}


typedef enum status
  {
    STATUS_PROTOCOL,
    STATUS_PROGRESS,
    STATUS_ENGINE,
    STATUS_ARMOR,
    STATUS_TEXTMODE,
    STATUS_INCLUDE_CERTS,
    STATUS_KEYLIST_MODE,
    STATUS_RECIPIENT,
    STATUS_ENCRYPT_RESULT
  } status_t;

const char *status_string[] =
  {
    "PROTOCOL",
    "PROGRESS",
    "ENGINE",
    "ARMOR",
    "TEXTMODE",
    "INCLUDE_CERTS",
    "KEYLIST_MODE",
    "RECIPIENT",
    "ENCRYPT_RESULT"
  };

struct gpgme_tool
{
  gpgme_ctx_t ctx;
#define MAX_RECIPIENTS 10
  gpgme_key_t recipients[MAX_RECIPIENTS + 1];
  int recipients_nr;

  gpg_error_t (*write_status) (void *hook, const char *status, const char *msg);
  void *write_status_hook;
  gpg_error_t (*write_data) (void *hook, const void *buf, size_t len);
  void *write_data_hook;
};
typedef struct gpgme_tool *gpgme_tool_t;


/* Forward declaration.  */
void gt_write_status (gpgme_tool_t gt, 
                      status_t status, ...) GT_GCC_A_SENTINEL(0);

void
_gt_progress_cb (void *opaque, const char *what,
		 int type, int current, int total)
{
  gpgme_tool_t gt = opaque;
  char buf[100];

  snprintf (buf, sizeof (buf), "0x%02x %i %i", type, current, total);
  gt_write_status (gt, STATUS_PROGRESS, what, buf, NULL);
}


gpg_error_t
_gt_gpgme_new (gpgme_tool_t gt, gpgme_ctx_t *ctx)
{
  gpg_error_t err;

  err = gpgme_new (ctx);
  if (err)
    return err;
  gpgme_set_progress_cb (*ctx, _gt_progress_cb, gt);
  return 0;
}


void
gt_init (gpgme_tool_t gt)
{
  memset (gt, '\0', sizeof (*gt));
  gpg_error_t err;

  err = _gt_gpgme_new (gt, &gt->ctx);
  if (err)
    log_error (1, err, "can't create gpgme context");
}


gpg_error_t
gt_signers_add (gpgme_tool_t gt, const char *fpr)
{
  gpg_error_t err;
  gpgme_key_t key;

  err = gpgme_get_key (gt->ctx, fpr, &key, 0);
  if (err)
    return err;

  return gpgme_signers_add (gt->ctx, key);
}


gpg_error_t
gt_signers_clear (gpgme_tool_t gt)
{
  gpgme_signers_clear (gt->ctx);
  return 0;
}


gpg_error_t
gt_get_key (gpgme_tool_t gt, const char *pattern, gpgme_key_t *r_key)
{
  gpgme_ctx_t ctx;
  gpgme_ctx_t listctx;
  gpgme_error_t err;
  gpgme_key_t key;

  if (!gt || !r_key || !pattern)
    return gpg_error (GPG_ERR_INV_VALUE);
  
  ctx = gt->ctx;

  err = gpgme_new (&listctx);
  if (err)
    return err;

  {
    gpgme_protocol_t proto;
    gpgme_engine_info_t info;

    /* Clone the relevant state.  */
    proto = gpgme_get_protocol (ctx);
    /* The g13 protocol does not allow keylisting, we need to choose
       something else.  */
    if (proto == GPGME_PROTOCOL_G13)
      proto = GPGME_PROTOCOL_OpenPGP;

    gpgme_set_protocol (listctx, proto);
    gpgme_set_keylist_mode (listctx, gpgme_get_keylist_mode (ctx));
    info = gpgme_ctx_get_engine_info (ctx);
    while (info && info->protocol != proto)
      info = info->next;
    if (info)
      gpgme_ctx_set_engine_info (listctx, proto,
				 info->file_name, info->home_dir);
  }

  err = gpgme_op_keylist_start (listctx, pattern, 0);
  if (!err)
    err = gpgme_op_keylist_next (listctx, r_key);
  if (!err)
    {
    try_next_key:
      err = gpgme_op_keylist_next (listctx, &key);
      if (gpgme_err_code (err) == GPG_ERR_EOF)
	err = 0;
      else
	{
          if (!err
              && *r_key && (*r_key)->subkeys && (*r_key)->subkeys->fpr
              && key && key->subkeys && key->subkeys->fpr
              && !strcmp ((*r_key)->subkeys->fpr, key->subkeys->fpr))
            {
              /* The fingerprint is identical.  We assume that this is
                 the same key and don't mark it as an ambiguous.  This
                 problem may occur with corrupted keyrings and has
                 been noticed often with gpgsm.  In fact gpgsm uses a
                 similar hack to sort out such duplicates but it can't
                 do that while listing keys.  */
              gpgme_key_unref (key);
              goto try_next_key;
            }
	  if (!err)
	    {
	      gpgme_key_unref (key);
	      err = gpg_error (GPG_ERR_AMBIGUOUS_NAME);
	    }
	  gpgme_key_unref (*r_key);
	}
    }
  gpgme_release (listctx);
  
  if (! err)
    gt_write_status (gt, STATUS_RECIPIENT, 
		     ((*r_key)->subkeys && (*r_key)->subkeys->fpr) ? 
		     (*r_key)->subkeys->fpr : "invalid", NULL);
  return err;
}


gpg_error_t
gt_recipients_add (gpgme_tool_t gt, const char *pattern)
{
  gpg_error_t err;
  gpgme_key_t key;

  if (gt->recipients_nr >= MAX_RECIPIENTS)
    return gpg_error_from_errno (ENOMEM);

  if (gpgme_get_protocol (gt->ctx) == GPGME_PROTOCOL_UISERVER)
    err = gpgme_key_from_uid (&key, pattern);
  else
    err = gt_get_key (gt, pattern, &key);
  if (err)
    return err;

  gt->recipients[gt->recipients_nr++] = key;
  return 0;
}


void
gt_recipients_clear (gpgme_tool_t gt)
{
  int idx;

  for (idx = 0; idx < gt->recipients_nr; idx++)
    gpgme_key_unref (gt->recipients[idx]);
  memset (gt->recipients, '\0', gt->recipients_nr * sizeof (gpgme_key_t));
  gt->recipients_nr = 0;
}


gpg_error_t
gt_reset (gpgme_tool_t gt)
{
  gpg_error_t err;
  gpgme_ctx_t ctx;
  
  err = _gt_gpgme_new (gt, &ctx);
  if (err)
    return err;

  gpgme_release (gt->ctx);
  gt->ctx = ctx;
  gt_recipients_clear (gt);
  return 0;
}


void
gt_write_status (gpgme_tool_t gt, status_t status, ...)
{
  va_list ap;
  const char *text;
  char buf[950];
  char *p;
  size_t n;
  gpg_error_t err;

  va_start (ap, status);
  p = buf;
  n = 0;
  while ((text = va_arg (ap, const char *)))
    {
      if (n)
	{
	  *p++ = ' ';
	  n++;
	}
      while (*text && n < sizeof (buf) - 2)
	{
	  *p++ = *text++;
	  n++;
	}
    }
  *p = 0;
  va_end (ap);

  err = gt->write_status (gt->write_status_hook, status_string[status], buf);
  if (err)
    log_error (1, err, "can't write status line");
}


gpg_error_t
gt_write_data (gpgme_tool_t gt, const void *buf, size_t len)
{
  return gt->write_data (gt->write_data_hook, buf, len);
}


gpg_error_t
gt_get_engine_info (gpgme_tool_t gt, gpgme_protocol_t proto)
{
  gpgme_engine_info_t info;
  info = gpgme_ctx_get_engine_info (gt->ctx);
  while (info)
    {
      if (proto == GPGME_PROTOCOL_UNKNOWN || proto == info->protocol)
	gt_write_status (gt, STATUS_ENGINE,
			 gpgme_get_protocol_name (info->protocol),
			 info->file_name, info->version,
			 info->req_version, info->home_dir, NULL);
      info = info->next;
    }
  return 0;
}


gpgme_protocol_t
gt_protocol_from_name (const char *name)
{
  if (! strcasecmp (name, gpgme_get_protocol_name (GPGME_PROTOCOL_OpenPGP)))
    return GPGME_PROTOCOL_OpenPGP;
  if (! strcasecmp (name, gpgme_get_protocol_name (GPGME_PROTOCOL_CMS)))
    return GPGME_PROTOCOL_CMS;
  if (! strcasecmp (name,gpgme_get_protocol_name (GPGME_PROTOCOL_GPGCONF)))
    return GPGME_PROTOCOL_GPGCONF;
  if (! strcasecmp (name, gpgme_get_protocol_name (GPGME_PROTOCOL_ASSUAN)))
    return GPGME_PROTOCOL_ASSUAN;
  if (! strcasecmp (name, gpgme_get_protocol_name (GPGME_PROTOCOL_G13)))
    return GPGME_PROTOCOL_G13;
  if (! strcasecmp (name, gpgme_get_protocol_name (GPGME_PROTOCOL_UISERVER)))
    return GPGME_PROTOCOL_UISERVER;
  if (! strcasecmp (name, gpgme_get_protocol_name (GPGME_PROTOCOL_DEFAULT)))
    return GPGME_PROTOCOL_DEFAULT;
  return GPGME_PROTOCOL_UNKNOWN;
}

  
gpg_error_t
gt_set_protocol (gpgme_tool_t gt, gpgme_protocol_t proto)
{
  return gpgme_set_protocol (gt->ctx, proto);
}


gpg_error_t
gt_get_protocol (gpgme_tool_t gt)
{
  gpgme_protocol_t proto = gpgme_get_protocol (gt->ctx);

  gt_write_status (gt, STATUS_PROTOCOL, gpgme_get_protocol_name (proto),
		   NULL);

  return 0;
}


gpg_error_t
gt_set_sub_protocol (gpgme_tool_t gt, gpgme_protocol_t proto)
{
  return gpgme_set_sub_protocol (gt->ctx, proto);
}


gpg_error_t
gt_get_sub_protocol (gpgme_tool_t gt)
{
  gpgme_protocol_t proto = gpgme_get_sub_protocol (gt->ctx);

  gt_write_status (gt, STATUS_PROTOCOL, gpgme_get_protocol_name (proto),
		   NULL);

  return 0;
}


gpg_error_t
gt_set_armor (gpgme_tool_t gt, int armor)
{
  gpgme_set_armor (gt->ctx, armor);
  return 0;
}


gpg_error_t
gt_get_armor (gpgme_tool_t gt)
{
  gt_write_status (gt, STATUS_ARMOR,
		   gpgme_get_armor (gt->ctx) ? "true" : "false", NULL);

  return 0;
}


gpg_error_t
gt_set_textmode (gpgme_tool_t gt, int textmode)
{
  gpgme_set_textmode (gt->ctx, textmode);
  return 0;
}


gpg_error_t
gt_get_textmode (gpgme_tool_t gt)
{
  gt_write_status (gt, STATUS_TEXTMODE,
		   gpgme_get_textmode (gt->ctx) ? "true" : "false", NULL);

  return 0;
}


gpg_error_t
gt_set_keylist_mode (gpgme_tool_t gt, gpgme_keylist_mode_t keylist_mode)
{
  gpgme_set_keylist_mode (gt->ctx, keylist_mode);
  return 0;
}


gpg_error_t
gt_get_keylist_mode (gpgme_tool_t gt)
{
#define NR_KEYLIST_MODES 6
  const char *modes[NR_KEYLIST_MODES + 1];
  int idx = 0;
  gpgme_keylist_mode_t mode = gpgme_get_keylist_mode (gt->ctx);
  
  if (mode & GPGME_KEYLIST_MODE_LOCAL)
    modes[idx++] = "local";
  if (mode & GPGME_KEYLIST_MODE_EXTERN)
    modes[idx++] = "extern";
  if (mode & GPGME_KEYLIST_MODE_SIGS)
    modes[idx++] = "sigs";
  if (mode & GPGME_KEYLIST_MODE_SIG_NOTATIONS)
    modes[idx++] = "sig_notations";
  if (mode & GPGME_KEYLIST_MODE_EPHEMERAL)
    modes[idx++] = "ephemeral";
  if (mode & GPGME_KEYLIST_MODE_VALIDATE)
    modes[idx++] = "validate";
  modes[idx++] = NULL;

  gt_write_status (gt, STATUS_KEYLIST_MODE, modes[0], modes[1], modes[2],
		   modes[3], modes[4], modes[5], modes[6], NULL);

  return 0;
}


gpg_error_t
gt_set_include_certs (gpgme_tool_t gt, int include_certs)
{
  gpgme_set_include_certs (gt->ctx, include_certs);
  return 0;
}


gpg_error_t
gt_get_include_certs (gpgme_tool_t gt)
{
  int include_certs = gpgme_get_include_certs (gt->ctx);
  char buf[100];

  if (include_certs == GPGME_INCLUDE_CERTS_DEFAULT)
    strcpy (buf, "default");
  else
    snprintf (buf, sizeof (buf), "%i", include_certs);

  gt_write_status (gt, STATUS_INCLUDE_CERTS, buf, NULL);

  return 0;
}


gpg_error_t
gt_decrypt_verify (gpgme_tool_t gt, gpgme_data_t cipher, gpgme_data_t plain,
		   int verify)
{
  if (verify)
    return gpgme_op_decrypt_verify (gt->ctx, cipher, plain);
  else
    return gpgme_op_decrypt (gt->ctx, cipher, plain);
}


gpg_error_t
gt_sign_encrypt (gpgme_tool_t gt, gpgme_encrypt_flags_t flags,
		 gpgme_data_t plain, gpgme_data_t cipher, int sign)
{
  gpg_error_t err;

  if (sign)
    err = gpgme_op_encrypt_sign (gt->ctx, gt->recipients, flags, plain, cipher);
  else
    err = gpgme_op_encrypt (gt->ctx, gt->recipients, flags, plain, cipher);

  gt_recipients_clear (gt);

  return err;
}


gpg_error_t
gt_sign (gpgme_tool_t gt, gpgme_data_t plain, gpgme_data_t sig,
	 gpgme_sig_mode_t mode)
{
  return gpgme_op_sign (gt->ctx, plain, sig, mode);
}


gpg_error_t
gt_verify (gpgme_tool_t gt, gpgme_data_t sig, gpgme_data_t sig_text,
	   gpgme_data_t plain)
{
  return gpgme_op_verify (gt->ctx, sig, sig_text, plain);
}


gpg_error_t
gt_import (gpgme_tool_t gt, gpgme_data_t data)
{
  return gpgme_op_import (gt->ctx, data);
}


gpg_error_t
gt_export (gpgme_tool_t gt, const char *pattern[], gpgme_export_mode_t mode,
	   gpgme_data_t data)
{
  return gpgme_op_export_ext (gt->ctx, pattern, mode, data);
}


gpg_error_t
gt_genkey (gpgme_tool_t gt, const char *parms, gpgme_data_t public,
	   gpgme_data_t secret)
{
  return gpgme_op_genkey (gt->ctx, parms, public, secret);
}


gpg_error_t
gt_import_keys (gpgme_tool_t gt, char *fpr[])
{
  gpg_error_t err = 0;
  int cnt;
  int idx;
  gpgme_key_t *keys;
  
  cnt = 0;
  while (fpr[cnt])
    cnt++;
  
  if (! cnt)
    return gpg_error (GPG_ERR_INV_VALUE);

  keys = malloc ((cnt + 1) * sizeof (gpgme_key_t));
  if (! keys)
    return gpg_error_from_syserror ();
  
  for (idx = 0; idx < cnt; idx++)
    {
      err = gpgme_get_key (gt->ctx, fpr[idx], &keys[idx], 0);
      if (err)
	break;
    }
  if (! err)
    {
      keys[cnt] = NULL;
      err = gpgme_op_import_keys (gt->ctx, keys);
    }
  
  /* Rollback.  */
  while (--idx >= 0)
    gpgme_key_unref (keys[idx]);
  free (keys);

  return err;
}


gpg_error_t
gt_delete (gpgme_tool_t gt, char *fpr, int allow_secret)
{
  gpg_error_t err;
  gpgme_key_t key;

  err = gpgme_get_key (gt->ctx, fpr, &key, 0);
  if (err)
    return err;

  err = gpgme_op_delete (gt->ctx, key, allow_secret);
  gpgme_key_unref (key);
  return err;
}


gpg_error_t
gt_keylist_start (gpgme_tool_t gt, const char *pattern[], int secret_only)
{
  return gpgme_op_keylist_ext_start (gt->ctx, pattern, secret_only, 0);
}


gpg_error_t
gt_keylist_next (gpgme_tool_t gt, gpgme_key_t *key)
{
  return gpgme_op_keylist_next (gt->ctx, key);
}


gpg_error_t
gt_getauditlog (gpgme_tool_t gt, gpgme_data_t output, unsigned int flags)
{
  return gpgme_op_getauditlog (gt->ctx, output, flags);
}


gpg_error_t
gt_vfs_mount (gpgme_tool_t gt, const char *container_file,
	      const char *mount_dir, int flags)
{
  gpg_error_t err;
  gpg_error_t op_err;
  err = gpgme_op_vfs_mount (gt->ctx, container_file, mount_dir, flags, &op_err);
  return err ? err : op_err;
}


gpg_error_t
gt_vfs_create (gpgme_tool_t gt, const char *container_file, int flags)
{
  gpg_error_t err;
  gpg_error_t op_err;
  err = gpgme_op_vfs_create (gt->ctx, gt->recipients, container_file,
			     flags, &op_err);
  gt_recipients_clear (gt);
  return err ? err : op_err;
}


static const char hlp_passwd[] = 
  "PASSWD <user-id>\n"
  "\n"
  "Ask the backend to change the passphrase for the key\n"
  "specified by USER-ID.";
gpg_error_t
gt_passwd (gpgme_tool_t gt, char *fpr)
{
  gpg_error_t err;
  gpgme_key_t key;

  err = gpgme_get_key (gt->ctx, fpr, &key, 0);
  if (err)
    return gpg_err_code (err) == GPG_ERR_EOF? gpg_error (GPG_ERR_NO_PUBKEY):err;

  err = gpgme_op_passwd (gt->ctx, key, 0);
  gpgme_key_unref (key);
  return err;
}


#define GT_RESULT_ENCRYPT 0x1
#define GT_RESULT_DECRYPT 0x2
#define GT_RESULT_SIGN 0x4
#define GT_RESULT_VERIFY 0x8
#define GT_RESULT_IMPORT 0x10
#define GT_RESULT_GENKEY 0x20
#define GT_RESULT_KEYLIST 0x40
#define GT_RESULT_VFS_MOUNT 0x80
#define GT_RESULT_ALL (~0U)

gpg_error_t
gt_result (gpgme_tool_t gt, unsigned int flags)
{
  static const char xml_preamble1[] = "<?xml version=\"1.0\" "
    "encoding=\"UTF-8\" standalone=\"yes\"?>\n";
  static const char xml_preamble2[] = "<gpgme>\n";
  static const char xml_end[] = "</gpgme>\n";
  int indent = 2;

  gt_write_data (gt, xml_preamble1, sizeof (xml_preamble1));
  gt_write_data (gt, NULL, 0);
  gt_write_data (gt, xml_preamble2, sizeof (xml_preamble2));
  gt_write_data (gt, NULL, 0);
  if (flags & GT_RESULT_ENCRYPT)
    result_encrypt_to_xml (gt->ctx, indent,
			   (result_xml_write_cb_t) gt_write_data, gt);
  if (flags & GT_RESULT_DECRYPT)
    result_decrypt_to_xml (gt->ctx, indent,
			   (result_xml_write_cb_t) gt_write_data, gt);
  if (flags & GT_RESULT_SIGN)
    result_sign_to_xml (gt->ctx, indent,
			(result_xml_write_cb_t) gt_write_data, gt);
  if (flags & GT_RESULT_VERIFY)
    result_verify_to_xml (gt->ctx, indent,
			  (result_xml_write_cb_t) gt_write_data, gt);
  if (flags & GT_RESULT_IMPORT)
    result_import_to_xml (gt->ctx, indent,
			  (result_xml_write_cb_t) gt_write_data, gt);
  if (flags & GT_RESULT_GENKEY)
    result_genkey_to_xml (gt->ctx, indent,
			  (result_xml_write_cb_t) gt_write_data, gt);
  if (flags & GT_RESULT_KEYLIST)
    result_keylist_to_xml (gt->ctx, indent,
			   (result_xml_write_cb_t) gt_write_data, gt);
  if (flags & GT_RESULT_VFS_MOUNT)
    result_vfs_mount_to_xml (gt->ctx, indent,
			     (result_xml_write_cb_t) gt_write_data, gt);
  gt_write_data (gt, xml_end, sizeof (xml_end));

  return 0;
}


/* GPGME SERVER.  */

#include <assuan.h>

struct server
{
  gpgme_tool_t gt;
  assuan_context_t assuan_ctx;

  gpgme_data_encoding_t input_enc;
  gpgme_data_encoding_t output_enc;
  assuan_fd_t input_fd;
  char *input_filename;
  FILE *input_stream;
  assuan_fd_t output_fd;
  char *output_filename;
  FILE *output_stream;
  assuan_fd_t message_fd;
  char *message_filename;
  FILE *message_stream;
  gpgme_data_encoding_t message_enc;
};


gpg_error_t
server_write_status (void *hook, const char *status, const char *msg)
{
  struct server *server = hook;
  return assuan_write_status (server->assuan_ctx, status, msg);
}


gpg_error_t
server_write_data (void *hook, const void *buf, size_t len)
{
  struct server *server = hook;
  return assuan_send_data (server->assuan_ctx, buf, len);
}



static gpg_error_t
server_parse_fd (assuan_context_t ctx, char *line, assuan_fd_t *rfd,
		 char **filename)
{
  *rfd = ASSUAN_INVALID_FD;
  *filename = NULL;

  if (! strncasecmp (line, "file=", 5))
    {
      char *term;
      *filename = strdup (line + 5);
      if (!*filename)
	return gpg_error_from_syserror();
      term = strchr (*filename, ' ');
      if (term)
	*term = '\0';
      return 0;
    }
  else
    return assuan_command_parse_fd (ctx, line, rfd);
}
    

static gpgme_data_encoding_t
server_data_encoding (const char *line)
{
  if (strstr (line, "--binary"))
    return GPGME_DATA_ENCODING_BINARY;
  if (strstr (line, "--base64"))
    return GPGME_DATA_ENCODING_BASE64;
  if (strstr (line, "--armor"))
    return GPGME_DATA_ENCODING_ARMOR;
  if (strstr (line, "--url"))
    return GPGME_DATA_ENCODING_URL;
  if (strstr (line, "--urlesc"))
    return GPGME_DATA_ENCODING_URLESC;
  if (strstr (line, "--url0"))
    return GPGME_DATA_ENCODING_URL0;
  return GPGME_DATA_ENCODING_NONE;
}


static gpgme_error_t
server_data_obj (assuan_fd_t fd, char *fn, int out,
		 gpgme_data_encoding_t encoding,
		 gpgme_data_t *data, FILE **fs)
{
  gpgme_error_t err;

  *fs = NULL;
  if (fn)
    {
      *fs = fopen (fn, out ? "wb" : "rb");
      if (!*fs)
	return gpg_error_from_syserror ();

      err = gpgme_data_new_from_stream (data, *fs);
    }
  else
    err = gpgme_data_new_from_fd (data, (int) fd);

  if (err)
    return err;
  return gpgme_data_set_encoding (*data, encoding);
}


void
server_reset_fds (struct server *server)
{
  /* assuan closes the input and output FDs for us when doing a RESET,
     but we use this same function after commands, so repeat it
     here.  */
  assuan_close_input_fd (server->assuan_ctx);
  assuan_close_output_fd (server->assuan_ctx);
  if (server->message_fd != ASSUAN_INVALID_FD)
    {
      /* FIXME: Assuan should provide a close function.  */
#if HAVE_W32_SYSTEM
      CloseHandle (server->message_fd);
#else
      close (server->message_fd);
#endif
      server->message_fd = ASSUAN_INVALID_FD;
    }
  if (server->input_filename)
    {
      free (server->input_filename);
      server->input_filename = NULL;
    }
  if (server->output_filename)
    {
      free (server->output_filename);
      server->output_filename = NULL;
    }
  if (server->message_filename)
    {
      free (server->message_filename);
      server->message_filename = NULL;
    }
  if (server->input_stream)
    {
      fclose (server->input_stream);
      server->input_stream = NULL;
    }
  if (server->output_stream)
    {
      fclose (server->output_stream);
      server->output_stream = NULL;
    }
  if (server->message_stream)
    {
      fclose (server->message_stream);
      server->message_stream = NULL;
    }

  server->input_enc = GPGME_DATA_ENCODING_NONE;
  server->output_enc = GPGME_DATA_ENCODING_NONE;
  server->message_enc = GPGME_DATA_ENCODING_NONE;
}


static gpg_error_t
reset_notify (assuan_context_t ctx, char *line)
{
  struct server *server = assuan_get_pointer (ctx);
  server_reset_fds (server);
  gt_reset (server->gt);
  return 0;
}


static const char hlp_version[] = 
  "VERSION [<string>]\n"
  "\n"
  "Call the function gpgme_check_version.";
static gpg_error_t
cmd_version (assuan_context_t ctx, char *line)
{
  if (line && *line)
    {
      const char *version = gpgme_check_version (line);
      return version ? 0 : gpg_error (GPG_ERR_SELFTEST_FAILED);
    }
  else
    {
      const char *version = gpgme_check_version (NULL);
      return assuan_send_data (ctx, version, strlen (version));
    }
}


static const char hlp_engine[] =
  "ENGINE [<string>]\n"
  "\n"
  "Get information about a GPGME engine (a.k.a. protocol).";
static gpg_error_t
cmd_engine (assuan_context_t ctx, char *line)
{
  struct server *server = assuan_get_pointer (ctx);
  return gt_get_engine_info (server->gt, gt_protocol_from_name (line));
}


static const char hlp_protocol[] = 
  "PROTOCOL [<name>]\n"
  "\n"
  "With NAME, set the protocol.  Without, return the current\n"
  "protocol.";
static gpg_error_t
cmd_protocol (assuan_context_t ctx, char *line)
{
  struct server *server = assuan_get_pointer (ctx);
  if (line && *line)
    return gt_set_protocol (server->gt, gt_protocol_from_name (line));
  else
    return gt_get_protocol (server->gt);
}


static const char hlp_sub_protocol[] =
  "SUB_PROTOCOL [<name>]\n"
  "\n"
  "With NAME, set the sub-protocol.  Without, return the\n"
  "current sub-protocol.";
static gpg_error_t
cmd_sub_protocol (assuan_context_t ctx, char *line)
{
  struct server *server = assuan_get_pointer (ctx);
  if (line && *line)
    return gt_set_sub_protocol (server->gt, gt_protocol_from_name (line));
  else
    return gt_get_sub_protocol (server->gt);
}


static const char hlp_armor[] =
  "ARMOR [true|false]\n"
  "\n"
  "With 'true' or 'false', turn output ASCII armoring on or\n"
  "off.  Without, return the current armoring status.";
static gpg_error_t
cmd_armor (assuan_context_t ctx, char *line)
{
  struct server *server = assuan_get_pointer (ctx);
  if (line && *line)
    {
      int flag = 0;
      
      if (! strcasecmp (line, "true") || ! strcasecmp (line, "yes")
	  || line[0] == '1')
	flag = 1;
      
      return gt_set_armor (server->gt, flag);
    }
  else
    return gt_get_armor (server->gt);
}


static const char hlp_textmode[] =
  "TEXTMODE [true|false]\n"
  "\n"
  "With 'true' or 'false', turn text mode on or off.\n"
  "Without, return the current text mode status.";
static gpg_error_t
cmd_textmode (assuan_context_t ctx, char *line)
{
  struct server *server = assuan_get_pointer (ctx);
  if (line && *line)
    {
      int flag = 0;

      if (! strcasecmp (line, "true") || ! strcasecmp (line, "yes")
	  || line[0] == '1')
	flag = 1;
      
      return gt_set_textmode (server->gt, flag);
    }
  else
    return gt_get_textmode (server->gt);
}


static const char hlp_include_certs[] =
  "INCLUDE_CERTS [default|<n>]\n"
  "\n"
  "With DEFAULT or N, set how many certificates should be\n"
  "included in the next S/MIME signed message.  See the\n"
  "GPGME documentation for details on the meaning of"
  "various N.  Without either, return the current setting.";
static gpg_error_t
cmd_include_certs (assuan_context_t ctx, char *line)
{
  struct server *server = assuan_get_pointer (ctx);

  if (line && *line)
    {
      int include_certs = 0;
      
      if (! strcasecmp (line, "default"))
	include_certs = GPGME_INCLUDE_CERTS_DEFAULT;
      else
	include_certs = atoi (line);
      
      return gt_set_include_certs (server->gt, include_certs);
    }
  else
    return gt_get_include_certs (server->gt);
}


static const char hlp_keylist_mode[] =
  "KEYLIST_MODE [local] [extern] [sigs] [sig_notations]\n"
  "  [ephemeral] [validate]\n"
  "\n"
  "Set the mode for the next KEYLIST command.";
static gpg_error_t
cmd_keylist_mode (assuan_context_t ctx, char *line)
{
  struct server *server = assuan_get_pointer (ctx);

  if (line && *line)
    {
      gpgme_keylist_mode_t mode = 0;
      
      if (strstr (line, "local"))
	mode |= GPGME_KEYLIST_MODE_LOCAL;
      if (strstr (line, "extern"))
	mode |= GPGME_KEYLIST_MODE_EXTERN;
      if (strstr (line, "sigs"))
	mode |= GPGME_KEYLIST_MODE_SIGS;
      if (strstr (line, "sig_notations"))
	mode |= GPGME_KEYLIST_MODE_SIG_NOTATIONS;
      if (strstr (line, "ephemeral"))
	mode |= GPGME_KEYLIST_MODE_EPHEMERAL;
      if (strstr (line, "validate"))
	mode |= GPGME_KEYLIST_MODE_VALIDATE;
      
      return gt_set_keylist_mode (server->gt, mode);
    }
  else
    return gt_get_keylist_mode (server->gt);
}


static const char hlp_input[] =
  "INPUT [<fd>|FILE=<path>]\n"
  "\n"
  "Set the input for the next command.  Use either the\n"
  "Assuan file descriptor FD or a filesystem PATH.";
static gpg_error_t
cmd_input (assuan_context_t ctx, char *line)
{
  struct server *server = assuan_get_pointer (ctx);
  gpg_error_t err;
  assuan_fd_t sysfd;
  char *filename;

  err = server_parse_fd (ctx, line, &sysfd, &filename);
  if (err)
    return err;
  server->input_fd = sysfd;
  server->input_filename = filename;
  server->input_enc = server_data_encoding (line);
  return 0;
}


static const char hlp_output[] =
  "OUTPUT [<fd>|FILE=<path>]\n"
  "\n"
  "Set the output for the next command.  Use either the\n"
  "Assuan file descriptor FD or a filesystem PATH.";
static gpg_error_t
cmd_output (assuan_context_t ctx, char *line)
{
  struct server *server = assuan_get_pointer (ctx);
  gpg_error_t err;
  assuan_fd_t sysfd;
  char *filename;

  err = server_parse_fd (ctx, line, &sysfd, &filename);
  if (err)
    return err;
  server->output_fd = sysfd;
  server->output_filename = filename;
  server->output_enc = server_data_encoding (line);
  return 0;
}


static const char hlp_message[] =
  "MESSAGE [<fd>|FILE=<path>]\n"
  "\n"
  "Set the plaintext message for the next VERIFY command\n"
  "with a detached signature.  Use either the Assuan file\n"
  "descriptor FD or a filesystem PATH.";
static gpg_error_t
cmd_message (assuan_context_t ctx, char *line)
{
  struct server *server = assuan_get_pointer (ctx);
  gpg_error_t err;
  assuan_fd_t sysfd;
  char *filename;

  err = server_parse_fd (ctx, line, &sysfd, &filename);
  if (err)
    return err;
  server->message_fd = sysfd;
  server->message_filename = filename;
  server->message_enc = server_data_encoding (line);
  return 0;
}


static const char hlp_recipient[] =
  "RECIPIENT <pattern>\n"
  "\n"
  "Add the key matching PATTERN to the list of recipients\n"
  "for the next encryption command.";
static gpg_error_t
cmd_recipient (assuan_context_t ctx, char *line)
{
  struct server *server = assuan_get_pointer (ctx);

  return gt_recipients_add (server->gt, line);
}


static const char hlp_signer[] =
  "SIGNER <fingerprint>\n"
  "\n"
  "Add the key with FINGERPRINT to the list of signers to\n"
  "be used for the next signing command.";
static gpg_error_t
cmd_signer (assuan_context_t ctx, char *line)
{
  struct server *server = assuan_get_pointer (ctx);

  return gt_signers_add (server->gt, line);
}


static const char hlp_signers_clear[] =
  "SIGNERS_CLEAR\n"
  "\n"
  "Clear the list of signers specified by previous SIGNER\n"
  "commands.";
static gpg_error_t
cmd_signers_clear (assuan_context_t ctx, char *line)
{
  struct server *server = assuan_get_pointer (ctx);

  return gt_signers_clear (server->gt);
}


static gpg_error_t
_cmd_decrypt_verify (assuan_context_t ctx, char *line, int verify)
{
  struct server *server = assuan_get_pointer (ctx);
  gpg_error_t err;
  assuan_fd_t inp_fd;
  char *inp_fn;
  assuan_fd_t out_fd;
  char *out_fn;
  gpgme_data_t inp_data;
  gpgme_data_t out_data;

  inp_fd = assuan_get_input_fd (ctx);
  inp_fn = server->input_filename;
  if (inp_fd == ASSUAN_INVALID_FD && !inp_fn)
    return GPG_ERR_ASS_NO_INPUT;
  out_fd = assuan_get_output_fd (ctx);
  out_fn = server->output_filename;
  if (out_fd == ASSUAN_INVALID_FD && !out_fn)
    return GPG_ERR_ASS_NO_OUTPUT;
  
  err = server_data_obj (inp_fd, inp_fn, 0, server->input_enc, &inp_data,
			 &server->input_stream);
  if (err)
    return err;
  err = server_data_obj (out_fd, out_fn, 1, server->output_enc, &out_data,
			 &server->output_stream);
  if (err)
    {
      gpgme_data_release (inp_data);
      return err;
    }

  err = gt_decrypt_verify (server->gt, inp_data, out_data, verify); 

  gpgme_data_release (inp_data);
  gpgme_data_release (out_data);

  server_reset_fds (server);

  return err;
}


static const char hlp_decrypt[] =
  "DECRYPT\n"
  "\n"
  "Decrypt the object set by the last INPUT command and\n"
  "write the decrypted message to the object set by the\n"
  "last OUTPUT command.";
static gpg_error_t
cmd_decrypt (assuan_context_t ctx, char *line)
{
  return _cmd_decrypt_verify (ctx, line, 0);
}


static const char hlp_decrypt_verify[] =
  "DECRYPT_VERIFY\n"
  "\n"
  "Decrypt the object set by the last INPUT command and\n"
  "verify any embedded signatures.  Write the decrypted\n"
  "message to the object set by the last OUTPUT command.";
static gpg_error_t
cmd_decrypt_verify (assuan_context_t ctx, char *line)
{
  return _cmd_decrypt_verify (ctx, line, 1);
}


static gpg_error_t
_cmd_sign_encrypt (assuan_context_t ctx, char *line, int sign)
{
  struct server *server = assuan_get_pointer (ctx);
  gpg_error_t err;
  assuan_fd_t inp_fd;
  char *inp_fn;
  assuan_fd_t out_fd;
  char *out_fn;
  gpgme_data_t inp_data = NULL;
  gpgme_data_t out_data = NULL;
  gpgme_encrypt_flags_t flags = 0;

  if (strstr (line, "--always-trust"))
    flags |= GPGME_ENCRYPT_ALWAYS_TRUST;
  if (strstr (line, "--no-encrypt-to"))
    flags |= GPGME_ENCRYPT_NO_ENCRYPT_TO;
  if (strstr (line, "--prepare"))
    flags |= GPGME_ENCRYPT_PREPARE;
  if (strstr (line, "--expect-sign"))
    flags |= GPGME_ENCRYPT_EXPECT_SIGN;
  
  inp_fd = assuan_get_input_fd (ctx);
  inp_fn = server->input_filename;
  out_fd = assuan_get_output_fd (ctx);
  out_fn = server->output_filename;
  if (inp_fd != ASSUAN_INVALID_FD || inp_fn)
    {
      err = server_data_obj (inp_fd, inp_fn, 0, server->input_enc, &inp_data,
			     &server->input_stream);
      if (err)
	return err;
    }
  if (out_fd != ASSUAN_INVALID_FD || out_fn)
    {
      err = server_data_obj (out_fd, out_fn, 1, server->output_enc, &out_data,
			     &server->output_stream);
      if (err)
	{
	  gpgme_data_release (inp_data);
	  return err;
	}
    }

  err = gt_sign_encrypt (server->gt, flags, inp_data, out_data, sign); 

  gpgme_data_release (inp_data);
  gpgme_data_release (out_data);

  server_reset_fds (server);

  return err;
}


static const char hlp_encrypt[] =
  "ENCRYPT [--always-trust] [--no-encrypt-to]\n"
  "  [--prepare] [--expect-sign]\n"
  "\n"
  "Encrypt the object set by the last INPUT command to\n"
  "the keys specified by previous RECIPIENT commands.  \n"
  "Write the signed and encrypted message to the object\n"
  "set by the last OUTPUT command.";
static gpg_error_t
cmd_encrypt (assuan_context_t ctx, char *line)
{
  return _cmd_sign_encrypt (ctx, line, 0);
}


static const char hlp_sign_encrypt[] =
  "SIGN_ENCRYPT [--always-trust] [--no-encrypt-to]\n"
  "  [--prepare] [--expect-sign]\n"
  "\n"
  "Sign the object set by the last INPUT command with the\n"
  "keys specified by previous SIGNER commands and encrypt\n"
  "it to the keys specified by previous RECIPIENT\n"
  "commands.  Write the signed and encrypted message to\n"
  "the object set by the last OUTPUT command.";
static gpg_error_t
cmd_sign_encrypt (assuan_context_t ctx, char *line)
{
  return _cmd_sign_encrypt (ctx, line, 1);
}


static const char hlp_sign[] =
  "SIGN [--clear|--detach]\n"
  "\n"
  "Sign the object set by the last INPUT command with the\n"
  "keys specified by previous SIGNER commands.  Write the\n"
  "signed message to the object set by the last OUTPUT\n"
  "command.  With `--clear`, generate a clear text\n"
  "signature.  With `--detach`, generate a detached\n"
  "signature.";
static gpg_error_t
cmd_sign (assuan_context_t ctx, char *line)
{
  struct server *server = assuan_get_pointer (ctx);
  gpg_error_t err;
  assuan_fd_t inp_fd;
  char *inp_fn;
  assuan_fd_t out_fd;
  char *out_fn;
  gpgme_data_t inp_data;
  gpgme_data_t out_data;
  gpgme_sig_mode_t mode = GPGME_SIG_MODE_NORMAL;

  if (strstr (line, "--clear"))
    mode = GPGME_SIG_MODE_CLEAR;
  if (strstr (line, "--detach"))
    mode = GPGME_SIG_MODE_DETACH;

  inp_fd = assuan_get_input_fd (ctx);
  inp_fn = server->input_filename;
  if (inp_fd == ASSUAN_INVALID_FD && !inp_fn)
    return GPG_ERR_ASS_NO_INPUT;
  out_fd = assuan_get_output_fd (ctx);
  out_fn = server->output_filename;
  if (out_fd == ASSUAN_INVALID_FD && !out_fn)
    return GPG_ERR_ASS_NO_OUTPUT;
  
  err = server_data_obj (inp_fd, inp_fn, 0, server->input_enc, &inp_data,
			 &server->input_stream);
  if (err)
    return err;
  err = server_data_obj (out_fd, out_fn, 1, server->output_enc, &out_data,
			 &server->output_stream);
  if (err)
    {
      gpgme_data_release (inp_data);
      return err;
    }

  err = gt_sign (server->gt, inp_data, out_data, mode);

  gpgme_data_release (inp_data);
  gpgme_data_release (out_data);
  server_reset_fds (server);

  return err;
}


static const char hlp_verify[] =
  "VERIFY\n"
  "\n"
  "Verify signatures on the object set by the last INPUT\n"
  "and MESSAGE commands.  If the message was encrypted,\n"
  "write the plaintext to the object set by the last\n"
  "OUTPUT command.";
static gpg_error_t
cmd_verify (assuan_context_t ctx, char *line)
{
  struct server *server = assuan_get_pointer (ctx);
  gpg_error_t err;
  assuan_fd_t inp_fd;
  assuan_fd_t msg_fd;
  assuan_fd_t out_fd;
  char *inp_fn;
  char *msg_fn;
  char *out_fn;
  gpgme_data_t inp_data;
  gpgme_data_t msg_data = NULL;
  gpgme_data_t out_data = NULL;

  inp_fd = assuan_get_input_fd (ctx);
  inp_fn = server->input_filename;
  if (inp_fd == ASSUAN_INVALID_FD && !inp_fn)
    return GPG_ERR_ASS_NO_INPUT;
  msg_fd = server->message_fd;
  msg_fn = server->message_filename;
  out_fd = assuan_get_output_fd (ctx);
  out_fn = server->output_filename;

  err = server_data_obj (inp_fd, inp_fn, 0, server->input_enc, &inp_data,
			 &server->input_stream);
  if (err)
    return err;
  if (msg_fd != ASSUAN_INVALID_FD || msg_fn)
    {
      err = server_data_obj (msg_fd, msg_fn, 0, server->message_enc, &msg_data,
			     &server->message_stream);
      if (err)
	{
	  gpgme_data_release (inp_data);
	  return err;
	}
    }
  if (out_fd != ASSUAN_INVALID_FD || out_fn)
    {
      err = server_data_obj (out_fd, out_fn, 1, server->output_enc, &out_data,
			     &server->output_stream);
      if (err)
	{
	  gpgme_data_release (inp_data);
	  gpgme_data_release (msg_data);
	  return err;
	}
    }

  err = gt_verify (server->gt, inp_data, msg_data, out_data);

  gpgme_data_release (inp_data);
  if (msg_data)
    gpgme_data_release (msg_data);
  if (out_data)
    gpgme_data_release (out_data);

  server_reset_fds (server);

  return err;
}


static const char hlp_import[] =
  "IMPORT [<pattern>]\n"
  "\n"
  "With PATTERN, import the keys described by PATTERN.\n"
  "Without, read a key (or keys) from the object set by the\n"
  "last INPUT command.";
static gpg_error_t
cmd_import (assuan_context_t ctx, char *line)
{
  struct server *server = assuan_get_pointer (ctx);
  
  if (line && *line)
    {
      char *fprs[2] = { line, NULL };

      return gt_import_keys (server->gt, fprs);
    }
  else
    {
      gpg_error_t err;
      assuan_fd_t inp_fd;
      char *inp_fn;
      gpgme_data_t inp_data;
      
      inp_fd = assuan_get_input_fd (ctx);
      inp_fn = server->input_filename;
      if (inp_fd == ASSUAN_INVALID_FD && !inp_fn)
	return GPG_ERR_ASS_NO_INPUT;

      err = server_data_obj (inp_fd, inp_fn, 0, server->input_enc, &inp_data,
			     &server->input_stream);
      if (err)
	return err;
      
      err = gt_import (server->gt, inp_data); 
      
      gpgme_data_release (inp_data);
      server_reset_fds (server);

      return err;
    }
}


static const char hlp_export[] = 
  "EXPORT [--extern] [--minimal] [<pattern>]\n"
  "\n"
  "Export the keys described by PATTERN.  Write the\n"
  "the output to the object set by the last OUTPUT command.";
static gpg_error_t
cmd_export (assuan_context_t ctx, char *line)
{
  struct server *server = assuan_get_pointer (ctx);
  gpg_error_t err;
  assuan_fd_t out_fd;
  char *out_fn;
  gpgme_data_t out_data;
  gpgme_export_mode_t mode = 0;
  const char *pattern[2];

  out_fd = assuan_get_output_fd (ctx);
  out_fn = server->output_filename;
  if (out_fd == ASSUAN_INVALID_FD && !out_fn)
    return GPG_ERR_ASS_NO_OUTPUT;
  err = server_data_obj (out_fd, out_fn, 1, server->output_enc, &out_data,
			 &server->output_stream);
  if (err)
    return err;

  if (has_option (line, "--extern"))
    mode |= GPGME_EXPORT_MODE_EXTERN;
  if (has_option (line, "--minimal"))
    mode |= GPGME_EXPORT_MODE_MINIMAL;

  line = skip_options (line);

  pattern[0] = line;
  pattern[1] = NULL;

  err = gt_export (server->gt, pattern, mode, out_data);

  gpgme_data_release (out_data);
  server_reset_fds (server);

  return err;
}


static gpg_error_t
_cmd_genkey_write (gpgme_data_t data, const void *buf, size_t size)
{
  while (size > 0)
    {
      ssize_t writen = gpgme_data_write (data, buf, size);
      if (writen < 0 && errno != EAGAIN)
	return gpg_error_from_syserror ();
      else if (writen > 0)
	{
	  buf = (void *) (((char *) buf) + writen);
	  size -= writen;
	}
    }
  return 0;
}


static gpg_error_t
cmd_genkey (assuan_context_t ctx, char *line)
{
  struct server *server = assuan_get_pointer (ctx);
  gpg_error_t err;
  assuan_fd_t inp_fd;
  char *inp_fn;
  assuan_fd_t out_fd;
  char *out_fn;
  gpgme_data_t inp_data;
  gpgme_data_t out_data = NULL;
  gpgme_data_t parms_data = NULL;
  const char *parms;

  inp_fd = assuan_get_input_fd (ctx);
  inp_fn = server->input_filename;
  if (inp_fd == ASSUAN_INVALID_FD && !inp_fn)
    return GPG_ERR_ASS_NO_INPUT;
  out_fd = assuan_get_output_fd (ctx);
  out_fn = server->output_filename;
  
  err = server_data_obj (inp_fd, inp_fn, 0, server->input_enc, &inp_data,
			 &server->input_stream);
  if (err)
    return err;
  if (out_fd != ASSUAN_INVALID_FD || out_fn)
    {
      err = server_data_obj (out_fd, out_fn, 1, server->output_enc, &out_data,
			     &server->output_stream);
      if (err)
	{
	  gpgme_data_release (inp_data);
	  return err;
	}
    }

  /* Convert input data.  */
  err = gpgme_data_new (&parms_data);
  if (err)
    goto out;
  do
    {
      char buf[512];
      ssize_t readn = gpgme_data_read (inp_data, buf, sizeof (buf));
      if (readn < 0)
	{
	  err = gpg_error_from_syserror ();
	  goto out;
	}
      else if (readn == 0)
	break;

      err = _cmd_genkey_write (parms_data, buf, readn);
      if (err)
	goto out;
    }
  while (1);
  err = _cmd_genkey_write (parms_data, "", 1);
  if (err)
    goto out;
  parms = gpgme_data_release_and_get_mem (parms_data, NULL);
  parms_data = NULL;
  if (! parms)
    {
      err = gpg_error (GPG_ERR_GENERAL);
      goto out;
    }

  err = gt_genkey (server->gt, parms, out_data, NULL);

  server_reset_fds (server);

 out:
  gpgme_data_release (inp_data);
  if (out_data)
    gpgme_data_release (out_data);
  if (parms_data)
    gpgme_data_release (parms_data);

  return err; 
}


static gpg_error_t
cmd_delete (assuan_context_t ctx, char *line)
{
  struct server *server = assuan_get_pointer (ctx);
  int allow_secret = 0;
  const char optstr[] = "--allow-secret";

  if (!strncasecmp (line, optstr, strlen (optstr)))
    {
      allow_secret = 1;
      line += strlen (optstr);
      while (*line && !spacep (line))
	line++;
    }
  return gt_delete (server->gt, line, allow_secret);
}


static const char hlp_keylist[] = 
  "KEYLIST [--secret-only] [<patterns>]\n"
  "\n"
  "List all certificates or only those specified by PATTERNS.  Each\n"
  "pattern shall be a percent-plus escaped certificate specification.";
static gpg_error_t
cmd_keylist (assuan_context_t ctx, char *line)
{
#define MAX_CMD_KEYLIST_PATTERN 20
  struct server *server = assuan_get_pointer (ctx);
  gpg_error_t err;
  int secret_only = 0;
  int idx;
  const char *pattern[MAX_CMD_KEYLIST_PATTERN+1];
  const char optstr[] = "--secret-only";
  char *p;

  if (!strncasecmp (line, optstr, strlen (optstr)))
    {
      secret_only = 1;
      line += strlen (optstr);
      while (*line && !spacep (line))
	line++;
    }

  idx = 0;
  for (p=line; *p; line = p)
    {
      while (*p && *p != ' ')
        p++;
      if (*p)
        *p++ = 0;
      if (*line)
        {
          if (idx+1 == DIM (pattern))
            return gpg_error (GPG_ERR_TOO_MANY);
          strcpy_escaped_plus (line, line);
          pattern[idx++] = line;
        }
    }
  pattern[idx] = NULL;

  err = gt_keylist_start (server->gt, pattern, secret_only);
  while (! err)
    {
      gpgme_key_t key;

      err = gt_keylist_next (server->gt, &key);
      if (gpg_err_code (err) == GPG_ERR_EOF)
	{
	  err = 0;
	  break;
	}
      else if (! err)
	{
	  char buf[100];
	  /* FIXME: More data.  */
	  snprintf (buf, sizeof (buf), "key:%s\n", key->subkeys->fpr);
          /* Write data and flush so that we see one D line for each
             key.  This does not change the semantics but is easier to
             read by organic eyes.  */
	  if (!assuan_send_data (ctx, buf, strlen (buf)))
            assuan_send_data (ctx, NULL, 0);
	  gpgme_key_unref (key);
	}
    }
  
  server_reset_fds (server);

  return err;
}


static const char hlp_getauditlog[] = 
  "GETAUDITLOG [--html] [--with-help]\n"
  "\n"
  "Call the function gpgme_op_getauditlog with the given flags.  Write\n"
  "the output to the object set by the last OUTPUT command.";
static gpg_error_t
cmd_getauditlog (assuan_context_t ctx, char *line)
{
  struct server *server = assuan_get_pointer (ctx);
  gpg_error_t err;
  assuan_fd_t out_fd;
  char *out_fn;
  gpgme_data_t out_data;
  unsigned int flags = 0;

  out_fd = assuan_get_output_fd (ctx);
  out_fn = server->output_filename;
  if (out_fd == ASSUAN_INVALID_FD && !out_fn)
    return GPG_ERR_ASS_NO_OUTPUT;
  err = server_data_obj (out_fd, out_fn, 1, server->output_enc, &out_data,
			 &server->output_stream);
  if (err)
    return err;

  if (strstr (line, "--html"))
    flags |= GPGME_AUDITLOG_HTML;
  if (strstr (line, "--with-help"))
    flags |= GPGME_AUDITLOG_WITH_HELP;

  err = gt_getauditlog (server->gt, out_data, flags);

  gpgme_data_release (out_data);
  server_reset_fds (server);

  return err;
}


static gpg_error_t
cmd_vfs_mount (assuan_context_t ctx, char *line)
{
  struct server *server = assuan_get_pointer (ctx);
  char *mount_dir;
  gpg_error_t err;

  mount_dir = strchr (line, ' ');
  if (mount_dir)
    {
      *(mount_dir++) = '\0';
      while (*mount_dir == ' ')
	mount_dir++;
    }

  err = gt_vfs_mount (server->gt, line, mount_dir, 0);

  return err;
}


static gpg_error_t
cmd_vfs_create (assuan_context_t ctx, char *line)
{
  struct server *server = assuan_get_pointer (ctx);
  gpg_error_t err;
  char *end;

  end = strchr (line, ' ');
  if (end)
    {
      *(end++) = '\0';
      while (*end == ' ')
	end++;
    }

  err = gt_vfs_create (server->gt, line, 0);

  return err;
}


static gpg_error_t
cmd_passwd (assuan_context_t ctx, char *line)
{
  struct server *server = assuan_get_pointer (ctx);

  return gt_passwd (server->gt, line);
}



static gpg_error_t
cmd_result (assuan_context_t ctx, char *line)
{
  struct server *server = assuan_get_pointer (ctx);
  return gt_result (server->gt, GT_RESULT_ALL);
}


/* STRERROR <err>  */
static gpg_error_t
cmd_strerror (assuan_context_t ctx, char *line)
{
  gpg_error_t err;
  char buf[100];

  err = atoi (line);
  snprintf (buf, sizeof (buf), "%s <%s>", gpgme_strerror (err),
	    gpgme_strsource (err));
  return assuan_send_data (ctx, buf, strlen (buf));
}


static gpg_error_t
cmd_pubkey_algo_name (assuan_context_t ctx, char *line)
{
  gpgme_pubkey_algo_t algo;
  char buf[100];

  algo = atoi (line);
  snprintf (buf, sizeof (buf), "%s", gpgme_pubkey_algo_name (algo));
  return assuan_send_data (ctx, buf, strlen (buf));
}


static gpg_error_t
cmd_hash_algo_name (assuan_context_t ctx, char *line)
{
  gpgme_hash_algo_t algo;
  char buf[100];

  algo = atoi (line);
  snprintf (buf, sizeof (buf), "%s", gpgme_hash_algo_name (algo));
  return assuan_send_data (ctx, buf, strlen (buf));
}


/* Tell the assuan library about our commands.  */
static gpg_error_t
register_commands (assuan_context_t ctx)
{
  gpg_error_t err;
  static struct {
    const char *name;
    assuan_handler_t handler;
    const char * const help;
  } table[] = {
    /* RESET, BYE are implicit.  */
    { "VERSION", cmd_version, hlp_version },
    /* TODO: Set engine info.  */
    { "ENGINE", cmd_engine, hlp_engine },
    { "PROTOCOL", cmd_protocol, hlp_protocol },
    { "SUB_PROTOCOL", cmd_sub_protocol, hlp_sub_protocol },
    { "ARMOR", cmd_armor, hlp_armor },
    { "TEXTMODE", cmd_textmode, hlp_textmode },
    { "INCLUDE_CERTS", cmd_include_certs, hlp_include_certs },
    { "KEYLIST_MODE", cmd_keylist_mode, hlp_keylist_mode },
    { "INPUT", cmd_input, hlp_input },
    { "OUTPUT", cmd_output, hlp_output },
    { "MESSAGE", cmd_message, hlp_message },
    { "RECIPIENT", cmd_recipient, hlp_recipient },
    { "SIGNER", cmd_signer, hlp_signer },
    { "SIGNERS_CLEAR", cmd_signers_clear, hlp_signers_clear },
     /* TODO: SIGNOTATION missing. */
     /* TODO: Could add wait interface if we allow more than one context */
     /* and add _START variants. */
     /* TODO: Could add data interfaces if we allow multiple data objects. */
    { "DECRYPT", cmd_decrypt, hlp_decrypt },
    { "DECRYPT_VERIFY", cmd_decrypt_verify, hlp_decrypt_verify },
    { "ENCRYPT", cmd_encrypt, hlp_encrypt },
    { "ENCRYPT_SIGN", cmd_sign_encrypt, hlp_sign_encrypt },
    { "SIGN_ENCRYPT", cmd_sign_encrypt, hlp_sign_encrypt },
    { "SIGN", cmd_sign, hlp_sign },
    { "VERIFY", cmd_verify, hlp_verify },
    { "IMPORT", cmd_import, hlp_import },
    { "EXPORT", cmd_export, hlp_export },
    { "GENKEY", cmd_genkey },
    { "DELETE", cmd_delete },
    /* TODO: EDIT, CARD_EDIT (with INQUIRE) */
    { "KEYLIST", cmd_keylist, hlp_keylist },
    { "LISTKEYS", cmd_keylist, hlp_keylist },
    /* TODO: TRUSTLIST, TRUSTLIST_EXT */
    { "GETAUDITLOG", cmd_getauditlog, hlp_getauditlog },
    /* TODO: ASSUAN */
    { "VFS_MOUNT", cmd_vfs_mount },
    { "MOUNT", cmd_vfs_mount },
    { "VFS_CREATE", cmd_vfs_create },
    { "CREATE", cmd_vfs_create },
    /* TODO: GPGCONF  */
    { "RESULT", cmd_result },
    { "STRERROR", cmd_strerror },
    { "PUBKEY_ALGO_NAME", cmd_pubkey_algo_name },
    { "HASH_ALGO_NAME", cmd_hash_algo_name },
    { "PASSWD", cmd_passwd, hlp_passwd },
    { NULL }
  };
  int idx;

  for (idx = 0; table[idx].name; idx++)
    {
      err = assuan_register_command (ctx, table[idx].name, table[idx].handler,
                                     table[idx].help);
      if (err)
        return err;
    } 
  return 0;
}


/* TODO: password callback can do INQUIRE.  */
void
gpgme_server (gpgme_tool_t gt)
{
  gpg_error_t err;
  assuan_fd_t filedes[2];
  struct server server;
  static const char hello[] = ("GPGME-Tool " VERSION " ready");

  memset (&server, 0, sizeof (server));
  server.message_fd = ASSUAN_INVALID_FD;
  server.input_enc = GPGME_DATA_ENCODING_NONE;
  server.output_enc = GPGME_DATA_ENCODING_NONE;
  server.message_enc = GPGME_DATA_ENCODING_NONE;

  server.gt = gt;
  gt->write_status = server_write_status;
  gt->write_status_hook = &server;
  gt->write_data = server_write_data;
  gt->write_data_hook = &server;

  /* We use a pipe based server so that we can work from scripts.
     assuan_init_pipe_server will automagically detect when we are
     called with a socketpair and ignore FIELDES in this case. */
#ifdef HAVE_W32CE_SYSTEM
  filedes[0] = ASSUAN_STDIN;
  filedes[1] = ASSUAN_STDOUT;
#else
  filedes[0] = assuan_fdopen (0);
  filedes[1] = assuan_fdopen (1);
#endif
  err = assuan_new (&server.assuan_ctx);
  if (err)
    log_error (1, err, "can't create assuan context");

  assuan_set_pointer (server.assuan_ctx, &server);

  err = assuan_init_pipe_server (server.assuan_ctx, filedes);
  if (err)
    log_error (1, err, "can't initialize assuan server");
  err = register_commands (server.assuan_ctx);
  if (err)
    log_error (1, err, "can't register assuan commands");
  assuan_set_hello_line (server.assuan_ctx, hello);

  assuan_register_reset_notify (server.assuan_ctx, reset_notify);

#define DBG_ASSUAN 0
  if (DBG_ASSUAN)
    assuan_set_log_stream (server.assuan_ctx, log_stream);

  for (;;)
    {
      err = assuan_accept (server.assuan_ctx);
      if (err == -1)
	break;
      else if (err)
	{
	  log_error (0, err, "assuan accept problem");
	  break;
        }
      
      err = assuan_process (server.assuan_ctx);
      if (err)
	log_error (0, err, "assuan processing failed");
    }

  assuan_release (server.assuan_ctx);
}



/* MAIN PROGRAM STARTS HERE.  */

const char *argp_program_version = VERSION;
const char *argp_program_bug_address = "bug-gpgme@gnupg.org";
error_t argp_err_exit_status = 1;

static char doc[] = "GPGME Tool -- Assuan server exposing GPGME operations";
static char args_doc[] = "COMMAND [OPTIONS...]";

static struct argp_option options[] = {
  { "server", 's', 0, 0, "Server mode" },
  { 0 }
};

static error_t parse_options (int key, char *arg, struct argp_state *state);
static struct argp argp = { options, parse_options, args_doc, doc };

struct args
{
  enum { CMD_DEFAULT, CMD_SERVER } cmd;
};

void
args_init (struct args *args)
{
  memset (args, '\0', sizeof (*args));
  args->cmd = CMD_DEFAULT;
}


static error_t
parse_options (int key, char *arg, struct argp_state *state)
{
  struct args *args = state->input;

  switch (key)
    {
    case 's':
      args->cmd = CMD_SERVER;
      break;
#if 0
    case ARGP_KEY_ARG:
      if (state->arg_num >= 2)
	argp_usage (state);
      printf ("Arg[%i] = %s\n", state->arg_num, arg);
      break;
    case ARGP_KEY_END:
      if (state->arg_num < 2)
	argp_usage (state);
      break;
#endif

    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}


int
main (int argc, char *argv[])
{
  struct args args;
  struct gpgme_tool gt;

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

  args_init (&args);

  argp_parse (&argp, argc, argv, 0, 0, &args);
  log_init ();

  gt_init (&gt);

  switch (args.cmd)
    {
    case CMD_DEFAULT:
    case CMD_SERVER:
      gpgme_server (&gt);
      break;
    }

  gpgme_release (gt.ctx);

#ifdef HAVE_W32CE_SYSTEM
  /* Give the buggy ssh server time to flush the output buffers.  */
  Sleep (300);
#endif

  return 0;
}

