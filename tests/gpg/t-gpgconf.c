/* t-gpgconf.c - Regression test.
 * Copyright (C) 2001, 2004, 2007 g10 Code GmbH
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <locale.h>
#include <string.h>

#ifdef HAVE_W32_SYSTEM
#include <windows.h>
#endif

#include <gpgme.h>

#include "t-support.h"

static char *
spaces (char *str, int extra)
{
  static char buf[80];
  int len = str ? strlen (str) : 0;
  int n;

#define TABSTOP 30
  n = TABSTOP - len - extra;

  memset (buf, ' ', sizeof (buf));
  if (n < 1 || n > (sizeof (buf) - 1))
    {
      buf[0] = '\n';
      n = TABSTOP + 1;
    }

  buf[n] = '\0';
  return buf;
}


void
dump_arg (int type, gpgme_conf_arg_t arg)
{
  if (!arg)
    {
      printf ("(none)");
      return;
    }

  while (arg)
    {
      switch (type)
	{
	case GPGME_CONF_STRING:
	case GPGME_CONF_PATHNAME:
	case GPGME_CONF_LDAP_SERVER:
        case GPGME_CONF_KEY_FPR:
        case GPGME_CONF_PUB_KEY:
        case GPGME_CONF_SEC_KEY:
        case GPGME_CONF_ALIAS_LIST:
	  printf ("`%s'", arg->value.string);
	  break;

	case GPGME_CONF_UINT32:
	  printf ("%u", arg->value.uint32);
	  break;

	case GPGME_CONF_INT32:
	  printf ("%i", arg->value.int32);
	  break;

	case GPGME_CONF_NONE:
	  printf ("%i (times)", arg->value.count);
	  break;

	default:
	  printf ("(unknown type)");
	}

      arg = arg->next;
      if (arg)
	printf (" ");
    }
}


void
dump_opt (gpgme_conf_opt_t opt)
{
  char level;
  char runtime = (opt->flags & GPGME_CONF_RUNTIME) ? 'r' : ' ';

  switch (opt->level)
    {
    case GPGME_CONF_BASIC:
      level = 'b';
      break;
    case GPGME_CONF_ADVANCED:
      level = 'a';
      break;
    case GPGME_CONF_EXPERT:
      level = 'e';
      break;
    case GPGME_CONF_INVISIBLE:
      level = 'i';
      break;
    case GPGME_CONF_INTERNAL:
      level = '#';
      break;
    default:
      level = '?';
    }

  if (opt->flags & GPGME_CONF_GROUP)
    {
      printf ("\n");
      printf ("%c%c [%s]%s%s\n", level, runtime, opt->name, spaces (opt->name, 5),
	      opt->description
	      ? opt->description : "");
    }
  else
    {
      if (opt->argname)
	{
	  const char *more = (opt->flags & GPGME_CONF_LIST) ? "..." : "";

	  if (opt->flags & GPGME_CONF_OPTIONAL)
	    {
	      printf ("%c%c --%s [%s%s] %s", level, runtime, opt->name, opt->argname, more,
		      spaces (opt->name, 9 + strlen (opt->argname) + strlen (more)));
	    }
	  else
	    {
	      printf ("%c%c --%s %s%s %s", level, runtime, opt->name, opt->argname, more,
		      spaces (opt->name, 7 + strlen (opt->argname) + strlen (more)));
	    }
	}
      else
	printf ("%c%c --%s%s", level, runtime, opt->name, spaces (opt->name, 5));

      if (opt->description)
	printf ("%s", opt->description);
      printf ("\n");

      if (opt->flags & GPGME_CONF_DEFAULT)
	{
	  printf ("%s%s = ", spaces (NULL, 0), opt->argname ? opt->argname : "(default)");
	  dump_arg (opt->type, opt->default_value);
	  printf ("\n");
	}
      else if (opt->flags & GPGME_CONF_DEFAULT_DESC)
	printf ("%s%s = %s\n", spaces (NULL, 0), opt->argname ? opt->argname : "(default)",
		opt->default_description);

      if (opt->no_arg_value)
	{
	  printf ("%sNo Arg Def = ", spaces (NULL, 0));
	  dump_arg (opt->type, opt->no_arg_value);
	  printf ("\n");
	}
      if (opt->value)
	{
	  printf ("%sCurrent = ", spaces (NULL, 0));
	  dump_arg (opt->type, opt->value);
	  printf ("\n");
	}
    }

#if 0
  arg = comp->options;
  while (opt)
    {
      dump_opt (opt);
      opt = opt->next;
    }
#endif
}


void
dump_comp (gpgme_conf_comp_t comp)
{
  gpgme_conf_opt_t opt;

  printf ("COMPONENT\n");
  printf ("=========\n");
  printf ("  Name: %s\n", comp->name);
  if (comp->description)
    printf ("  Desc: %s\n", comp->description);
  if (comp->program_name)
    printf ("  Path: %s\n", comp->program_name);
  printf ("\n");

  opt = comp->options;
  while (opt)
    {
      dump_opt (opt);
      opt = opt->next;
    }
}


int
lookup (gpgme_conf_comp_t conf,
	const char *component,
	const char *option,
	gpgme_conf_comp_t *comp,
	gpgme_conf_opt_t *opt)
{
  *comp = conf;
  while (*comp && strcmp ((*comp)->name, component))
    *comp = (*comp)->next;

  if (*comp)
    {
      *opt = (*comp)->options;
      while (*opt && strcmp ((*opt)->name, option))
	*opt = (*opt)->next;

      /* Allow for the option not to be there.  */
      if (*opt)
	return 1;	/* Found.  */
    }

  return 0;		/* Not found.  */
}

#include <assert.h>


int
main (void)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_conf_comp_t conf;
  gpgme_conf_comp_t comp;
  int first;
  int i, N = 10;

  init_gpgme (GPGME_PROTOCOL_GPGCONF);

  err = gpgme_new (&ctx);
  fail_if_err (err);

  {
    /* Let's check getting the agent-socket directory for different homedirs.  */
    char *result1 = NULL;
    char *result2 = NULL;
    err = gpgme_ctx_set_engine_info (ctx, GPGME_PROTOCOL_GPGCONF, NULL, "/tmp/foo");
    fail_if_err (err);
    err = gpgme_op_conf_dir (ctx, "agent-socket", &result1);
    fail_if_err (err);

    err = gpgme_ctx_set_engine_info (ctx, GPGME_PROTOCOL_GPGCONF, NULL, NULL);
    fail_if_err (err);
    err = gpgme_op_conf_dir (ctx, "agent-socket", &result2);
    fail_if_err (err);

    /* They have to be different.  */
    test (strcmp(result1, result2));
    gpgme_free (result1);
    gpgme_free (result2);
  }

  err = gpgme_op_conf_load (ctx, &conf);
  fail_if_err (err);

  comp = conf;
  first = 1;
  while (comp)
    {
      if (!first)
	printf ("\n");
      else
	first = 0;
      dump_comp (comp);
      comp = comp->next;
    }

  /* Now change something.  */
  fprintf (stderr, " dirmngr.verbose ");
  for (i = 0; i < N; i++) {
    unsigned int count = i % 4 + 1; /* counts must not be zero */
    gpgme_conf_arg_t arg;
    gpgme_conf_opt_t opt;

    err = gpgme_conf_arg_new (&arg, GPGME_CONF_NONE, &count);
    fail_if_err (err);

    if (lookup (conf, "dirmngr", "verbose", &comp, &opt))
      {
	/* Found.  */
	err = gpgme_conf_opt_change (opt, 0, arg);
	fail_if_err (err);

	err = gpgme_op_conf_save (ctx, comp);
	fail_if_err (err);
      }
    else
      {
	fprintf (stderr, "Skipping test, option dirmngr.verbose not found.\n");
	break;
      }

    /* Reload config and verify that the value was updated.  */
    gpgme_conf_release (conf);
    err = gpgme_op_conf_load (ctx, &conf);
    fail_if_err (err);
    if (lookup (conf, "dirmngr", "verbose", &comp, &opt))
      {
        /* Found.  */
        test (opt->alt_type == GPGME_CONF_NONE);
        test (opt->value);
        test ((unsigned long) opt->value->value.count == count);
      }

    fprintf (stderr, ".");
    fflush (stderr);
  }

  /* Now change something else.  */
  fprintf (stderr, " dirmngr.keyserver ");
  for (i = 0; i < N; i++) {
    const char *values[2] = { "hkp://foo.bar", "hkps://bar.foo" };
    gpgme_conf_arg_t arg;
    gpgme_conf_opt_t opt;

    err = gpgme_conf_arg_new (&arg, GPGME_CONF_STRING, values[i%2]);
    fail_if_err (err);

    if (lookup (conf, "dirmngr", "keyserver", &comp, &opt))
      {
	/* Found.  */
	test (opt->alt_type == GPGME_CONF_STRING);
	err = gpgme_conf_opt_change (opt, 0, arg);
	fail_if_err (err);

	err = gpgme_op_conf_save (ctx, comp);
	fail_if_err (err);
      }
    else
      {
	fprintf (stderr, "Skipping test, option dirmngr.keyserver not found.\n");
	break;
      }

    /* Reload config and verify that the value was updated.  */
    gpgme_conf_release (conf);
    err = gpgme_op_conf_load (ctx, &conf);
    fail_if_err (err);
    if (lookup (conf, "dirmngr", "keyserver", &comp, &opt))
      {
        /* Found.  */
        test (opt->alt_type == GPGME_CONF_STRING);
        test (opt->value);
        test (opt->value->value.string);
        test (strcmp (opt->value->value.string, values[i%2]) == 0);
      }

    fprintf (stderr, ".");
    fflush (stderr);
  }
  fprintf (stderr, "\n");

  gpgme_conf_release (conf);
  gpgme_release (ctx);
  return 0;
}
