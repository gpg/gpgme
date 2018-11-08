/* show-group-options.c - Example code to retrieve the group option.
   Copyright (C) 2008 g10 Code GmbH

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
   License along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <locale.h>

#include <gpgme.h>


#define fail_if_err(err)					\
  do								\
    {								\
      if (err)							\
        {							\
          fprintf (stderr, "%s:%d: gpgme_error_t %s\n",		\
                   __FILE__, __LINE__, gpgme_strerror (err));   \
          exit (1);						\
        }							\
    }								\
  while (0)




static void
print_one_alias (const char *string)
{
  const char *value, *s;
  size_t namelen;
  int first = 1;
  int any = 0;

  while (isascii (*string) && isspace (*string))
    string++;

  value = strchr (string, '=');
  if (value)
    {
      for (s=value-1; s > string ; s--)
        if (!isascii (*s) || !isspace (*s))
          break;
    }
  if (!value || s == value )
    {
      printf ("# error: invalid group definition!\n");
      return;
    }
  value++;
  namelen = (s + 1 - string);
  printf ("%.*s: ", (int)namelen, string);

  for (;;)
    {
      while (isascii (*value) && isspace (*value))
        value++;
      if (!*value)
        break;
      for (s = value; *s && !(isascii (*s) && isspace (*s)); s++)
        ;
      printf ("%s%*s%.*s",
              first? "":",\n",
              any? (int)namelen+2:0, "",
              (int)(s-value), value);
      first = 0;
      any = 1;
      value = s;
    }
  putchar ('\n');
}




static void
print_gpgconf_string (const char *cname, const char *name)
{
  gpg_error_t err;
  gpgme_ctx_t ctx;
  gpgme_conf_comp_t conf_list, conf;
  gpgme_conf_opt_t opt;
  gpgme_conf_arg_t value;

  err = gpgme_new (&ctx);
  fail_if_err (err);

  err = gpgme_op_conf_load (ctx, &conf_list);
  fail_if_err (err);
      
  for (conf = conf_list; conf; conf = conf->next)
    {
      if ( !strcmp (conf->name, cname) )
        {
          for (opt = conf->options; opt; opt = opt->next)
            if ( !(opt->flags & GPGME_CONF_GROUP)
                 && !strcmp (opt->name, name))
              {
                for (value = opt->value; value; value = value->next)
                  {
                    if (opt->type == GPGME_CONF_ALIAS_LIST)
                      print_one_alias (value->value.string);
                  }
                break;
              }
          break;
        } 
    }
  
  gpgme_conf_release (conf_list);
  gpgme_release (ctx);
}



int 
main (int argc, char **argv )
{
  gpgme_check_version (NULL);
  setlocale (LC_ALL, "");
  gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
#ifndef HAVE_W32_SYSTEM
  gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
#endif

  print_gpgconf_string ("gpg", "group");

  return 0;
}


/*
Local Variables:
compile-command: "cc -o show-group-options show-group-options.c -lgpgme"
End:
*/
