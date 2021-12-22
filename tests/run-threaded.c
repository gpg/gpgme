/* run-threaded.c  - Helper to put GPGME under multithread load.
 * Copyright (C) 2018 by Bundesamt für Sicherheit in der Informationstechnik
 *               Software engineering by Intevation GmbH
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

/* The idea of this test is not to be run as unit test but as part
 * of development to find threading issues and resource leaks. */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <gpgme.h>
#include <gpg-error.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <unistd.h>

#define PGM "run-threaded"

#include "run-support.h"

static volatile int stop;
static volatile int thread_cnt;
static volatile int running_threads;
static int verbose;
static int data_type;
static int mem_only;

#ifdef HAVE_W32_SYSTEM
# include <windows.h>
# define THREAD_RET DWORD CALLBACK

static void
create_thread (THREAD_RET (*func) (void *), void *arg)
{
  HANDLE hd = CreateThread (NULL, 0, func, arg, 0, NULL);
  if (hd == INVALID_HANDLE_VALUE)
    {
      fprintf (stderr, "Failed to create thread!\n");
      exit (1);
    }
  running_threads++;
  CloseHandle (hd);
}

#else
# include <pthread.h>
# define THREAD_RET void *

static void
create_thread (THREAD_RET (func) (void *), void *arg)
{
  pthread_t handle;
  running_threads++;
  if (pthread_create (&handle, NULL, func, arg))
    {
      fprintf (stderr, "Failed to create thread!\n");
      exit (1);
    }
}
#endif

#include <gpg-error.h>

GPGRT_LOCK_DEFINE (out_lock);

#define out(format, ...) \
  { \
    gpgrt_lock_lock (&out_lock); \
    printf (format "\n", ##__VA_ARGS__); \
    gpgrt_lock_unlock (&out_lock); \
  }

#define errpoint \
{ \
  out ("Error on %i", __LINE__); \
  exit (1); \
}

#define log(format, ...) \
if (verbose) \
  { \
    gpgrt_lock_lock (&out_lock); \
    printf (format "\n", ##__VA_ARGS__); \
    gpgrt_lock_unlock (&out_lock); \
  }

/* Lazy mans signal */
GPGRT_LOCK_DEFINE (threads_lock);

void del_thread (void)
{
  if (--running_threads == 0)
    {
      gpgrt_lock_unlock (&threads_lock);
    }
}

static int
show_usage (int ex)
{
  fputs ("usage: " PGM " [options] [messages]\n\n"
         "Options:\n"
         "  --verbose     run in verbose mode\n"
         "  --no-list     do not do keylistings\n"
         "  --allow-del   allow to delete keys after import\n"
         "  --data-type   mem function to use one of:\n"
         "                    1: fstream\n"
         "                    2: posix fd\n"
         "                    3: memory\n"
         "                    4: gpgrt_stream\n"
         "                    default: random\n"
/*         "  --mem-cache   read data only once and then work on memory\n"
           "                exlusive with data-type option\n" */
         "  --threads N   use 4+N threads (4 are used for keylisting"
" default 1)\n"
         "  --repeat  N   do N repeats on the messages (default 1)\n\n"
         "Note: The test does keylistings of both S/MIME and OpenPGP\n"
         "      in the background while running operations on the\n"
         "      messages, depending on their type.\n"
         "      (Currently decrypt / verify).\n\n"
         "      Without messages only keylistings will be done.\n"
         , stderr);
  exit (ex);
}


struct msg_list_s
{
  const char *file_name;
  struct msg_list_s *next;
};
typedef struct msg_list_s *msg_list_t;

struct data_s
{
  int fd;
  FILE *file;
  gpgrt_stream_t stream;
  unsigned char *mem;
  gpgme_data_t dh;
};
typedef struct data_s *data_t;

struct keylist_args_s
{
  gpgme_protocol_t proto;
  int secret;
};
typedef struct keylist_args_s *keylist_args_t;

static volatile int keylists;

static int allow_del;

static THREAD_RET
do_keylist (void *keylist_args)
{
  gpgme_error_t err;
  gpgme_ctx_t ctx;
  gpgme_key_t key;

  keylist_args_t args = (keylist_args_t) keylist_args;

  log ("Keylist %i, Protocol: %s, Secret %i",
       keylists++,
       args->proto == GPGME_PROTOCOL_CMS ? "CMS" : "OpenPGP",
       args->secret);

  err = gpgme_new (&ctx);
  fail_if_err (err);

  err = gpgme_set_protocol (ctx, args->proto);
  fail_if_err (err);

  err = gpgme_op_keylist_start (ctx, NULL, args->secret);
  fail_if_err (err);

  while (!(err = gpgme_op_keylist_next (ctx, &key)))
    {
      gpgme_key_unref (key);
    }

  if (gpgme_err_code (err) != GPG_ERR_EOF)
    {
      fail_if_err (err);
    }

  gpgme_release (ctx);

  if (!stop)
    {
      create_thread (do_keylist, keylist_args);
    }
  del_thread ();
  return 0;
}


static unsigned char *
get_file (const char *fname, size_t *r_size)
{
  gpg_error_t err;
  gpgrt_stream_t fp;
  struct stat st;
  unsigned char *buf;
  size_t buflen;

  fp = gpgrt_fopen (fname, "r");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      fprintf (stderr, "Error: can't open '%s': %s\n", fname,
               gpg_strerror (err));
      return NULL;
    }

  if (fstat (gpgrt_fileno(fp), &st))
    {
      err = gpg_error_from_syserror ();
      fprintf (stderr, "Error: can't stat '%s': %s\n", fname,
               gpg_strerror (err));
      gpgrt_fclose (fp);
      return NULL;
    }

  buflen = st.st_size;
  buf = malloc (buflen+1);
  if (!buf)
    {
      fprintf (stderr, "Error: no mem\n");
      gpgrt_fclose (fp);
      return NULL;
    }

  if (gpgrt_fread (buf, buflen, 1, fp) != 1)
    {
      err = gpg_error_from_syserror ();
      fprintf (stderr, "error reading '%s': %s\n", fname,
               gpg_strerror (err));
      gpgrt_fclose (fp);
      free (buf);
      return NULL;
    }
  buf[buflen] = 0;
  gpgrt_fclose (fp);

  if (r_size)
    {
      *r_size = buflen;
    }

  return buf;
}

/** Lets use random data. This should also introduce a bit
    of randomness into the system by changing the runtimes
    of various data functions. Esp. Mem against the file ops. */
data_t
random_data_new (const char *fname)
{
  data_t ret = calloc (1, sizeof (struct data_s));
  int data_rand;

  ret->fd = -1;

  if (data_type)
    {
      data_rand = data_type;
    }
  else
    {
      data_rand = rand () % 3;
    }

  if (data_rand == 0) /* stream */
    {
      FILE *f_stream = fopen (fname, "rb");
      if (!f_stream)
        {
          errpoint;
        }
      fail_if_err (gpgme_data_new_from_stream (&(ret->dh), f_stream));
      ret->file = f_stream;
      return ret;
    }
  if (data_rand == 1) /* fd */
    {
      int fd = open (fname, O_RDONLY);
      gpgme_data_t dh;
      if (fd == -1)
        {
          errpoint;
        }
      fail_if_err (gpgme_data_new_from_fd (&dh, fd));
      ret->fd = fd;
      ret->dh = dh;
      return ret;
    }
  if (data_rand == 2) /* mem */
    {
      unsigned char *mem;
      size_t size;

      mem = get_file (fname, &size);
      if (!mem)
        {
          errpoint;
        }
      fail_if_err (gpgme_data_new_from_mem (&(ret->dh),
                                            (const char *)mem,
                                            size, 0));
      ret->mem = mem;
      return ret;
    }
  if (data_rand == 3) /* estream */
    {
      gpgrt_stream_t stream = gpgrt_fopen (fname, "rb");

      if (!stream)
        {
          errpoint;
        }

      fail_if_err (gpgme_data_new_from_estream (&(ret->dh), stream));
      ret->stream = stream;
      return ret;
    }
  /* notreached */
  return ret;
}

void
random_data_close (data_t data)
{
  if (data->dh)
    {
      gpgme_data_release (data->dh);
    }

  if (data->fd != -1)
    {
      close (data->fd);
    }
  else if (data->file)
    {
      fclose (data->file);
    }
  else if (data->stream)
    {
      gpgrt_fclose (data->stream);
    }
  else if (data->mem)
    {
      free (data->mem);
    }
  free (data);
}

void
verify (const char *fname, gpgme_protocol_t proto)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_data_t output;
  char *msg;
  size_t msg_len;
  data_t data = random_data_new (fname);

  log ("Starting verify on: %s with protocol %s", fname,
       proto == GPGME_PROTOCOL_CMS ? "CMS" : "OpenPGP");

  gpgme_data_new (&output);

  err = gpgme_new (&ctx);
  fail_if_err (err);

  err = gpgme_set_protocol (ctx, proto);
  fail_if_err (err);

  err = gpgme_op_verify (ctx, data->dh, NULL, output);
  out ("Data: %p, %i %p %p %p", data->dh,
       data->fd, data->file, data->stream,
       data->mem);
  fail_if_err (err);

  msg = gpgme_data_release_and_get_mem (output, &msg_len);

  if (msg_len)
    {
      log ("Verify result \n'%.*s'", (int)msg_len, msg);
    }

  gpgme_release (ctx);

  random_data_close (data);
  free (msg);
}


/* We randomize data access to put in a bit additional
   entropy in this test and also to check if maybe
   some data functions might not be properly thread
   safe. */
void
decrypt (const char *fname, gpgme_protocol_t proto)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_data_t output;
  char *msg;
  size_t msg_len;
  data_t data = random_data_new (fname);

  log ("Starting decrypt on: %s", fname);

  gpgme_data_new (&output);

  err = gpgme_new (&ctx);
  fail_if_err (err);

  err = gpgme_set_protocol (ctx, proto);
  fail_if_err (err);

  err = gpgme_op_decrypt (ctx, data->dh, output);
  fail_if_err (err);

  gpgme_release (ctx);

  msg = gpgme_data_release_and_get_mem (output, &msg_len);

  if (msg_len)
    {
      log ("Decrypt result \n'%.*s'", (int)msg_len, msg);
    }

  random_data_close (data);
}

void
delete_key (gpgme_key_t key)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;

  err = gpgme_new (&ctx);
  fail_if_err (err);

  gpgme_set_protocol (ctx, key->protocol);

  err = gpgme_op_delete (ctx, key, 0);
  fail_if_err (err);

  gpgme_release (ctx);
}

/* Get the key for the fpr in protocol and call delete_key
   on it. */
void
delete_fpr (const char *fpr, gpgme_protocol_t proto)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_key_t key = NULL;

  err = gpgme_new (&ctx);
  fail_if_err (err);

  gpgme_set_protocol (ctx, proto);

  err = gpgme_get_key (ctx, fpr, &key, 0);
  fail_if_err (err);

  if (!key)
    {
      errpoint;
    }
  delete_key (key);

  log ("deleted key %s", fpr);
  gpgme_key_unref (key);
  gpgme_release (ctx);
}

void
delete_impres (gpgme_import_result_t r, gpgme_protocol_t proto)
{
  gpgme_import_status_t st;

  if (!r)
    {
      errpoint;
    }

  for (st=r->imports; st; st = st->next)
    {
      if (st->fpr)
        delete_fpr (st->fpr, proto);
    }
}

void
import (const char *fname, gpgme_protocol_t proto)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  data_t data = random_data_new (fname);

  log ("Starting import on: %s", fname);

  err = gpgme_new (&ctx);
  fail_if_err (err);

  err = gpgme_set_protocol (ctx, proto);
  fail_if_err (err);

  gpgme_set_offline (ctx, 1);

  err = gpgme_op_import (ctx, data->dh);
  fail_if_err (err);

  if (allow_del)
    {
      delete_impres (gpgme_op_import_result (ctx), proto);
    }

  gpgme_release (ctx);

  log ("Import completed.");

  random_data_close (data);
}

static THREAD_RET
do_data_op (void *file_name)
{
  gpgme_data_t data;
  const char *fname = (const char *) file_name;
  FILE *f = fopen (fname, "rb");
  gpgme_data_type_t type;

  if (!f)
    {
      fprintf (stderr, "Failed to open '%s'\n", fname);
      exit (1);
    }

  fail_if_err (gpgme_data_new_from_stream (&data, f));

  type = gpgme_data_identify (data, 0);
  gpgme_data_release (data);
  fclose (f);

  switch (type)
    {
      case GPGME_DATA_TYPE_INVALID:
      case GPGME_DATA_TYPE_UNKNOWN:
        {
          fprintf (stderr, "Failed to identify '%s'", fname);
          exit(1);
        }
      case GPGME_DATA_TYPE_PGP_SIGNED:
        {
          verify (fname, GPGME_PROTOCOL_OpenPGP);
          break;
        }
      case GPGME_DATA_TYPE_CMS_SIGNED:
        {
          verify (fname, GPGME_PROTOCOL_CMS);
          break;
        }
      case GPGME_DATA_TYPE_PGP_ENCRYPTED:
        {
          decrypt (fname, GPGME_PROTOCOL_OpenPGP);
          break;
        }
      case GPGME_DATA_TYPE_CMS_ENCRYPTED:
        {
          decrypt (fname, GPGME_PROTOCOL_CMS);
          break;
        }
      case GPGME_DATA_TYPE_PGP_KEY:
        {
          import (fname, GPGME_PROTOCOL_OpenPGP);
          break;
        }
      case GPGME_DATA_TYPE_X509_CERT:
        {
          import (fname, GPGME_PROTOCOL_CMS);
          break;
        }
      default:
        {
          out ("Unhandled data type 0x%x for '%s'\n", type, fname);
          errpoint;
        }
    }

  del_thread ();
  return 0;
}


void
start_keylistings (void)
{
  static struct keylist_args_s args[4];
  int i;

  args[0].proto = GPGME_PROTOCOL_OpenPGP;
  args[0].secret = 0;

  args[1].proto = GPGME_PROTOCOL_OpenPGP;
  args[1].secret = 1;

  args[2].proto = GPGME_PROTOCOL_CMS;
  args[2].secret = 0;

  args[3].proto = GPGME_PROTOCOL_CMS;
  args[3].secret = 1;

  for (i = 0; i < 4; i++)
    {
      thread_cnt--;
      create_thread (do_keylist, &args[i]);
    }
}

int
main (int argc, char **argv)
{
  int last_argc = -1;
  int repeats = 1;
  int threads = 0;
  int no_list = 0;
  msg_list_t msgs = NULL;
  msg_list_t msg_it = NULL;
  stop = 0;

  srand (1 /* Somewhat deterministic results */);

  if (argc)
    { argc--; argv++; }

  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--help"))
        {
          show_usage (0);
        }
      else if (!strcmp (*argv, "--verbose"))
        {
          verbose = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--no-list"))
        {
          no_list = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--allow-del"))
        {
          allow_del = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--mem-only"))
        {
          if (data_type)
            {
              show_usage (1);
            }
          mem_only = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--threads"))
        {
          argc--; argv++;
          if (!argc)
            {
              show_usage (1);
            }
          threads = atoi (*argv);
          if (!threads)
            {
              show_usage (1);
            }
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--data-type"))
        {
          argc--; argv++;
          if (!argc || mem_only)
            {
              show_usage (1);
            }
          data_type = atoi (*argv);
          if (data_type > 4)
            {
              show_usage (1);
            }
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--repeat"))
        {
          argc--; argv++;
          if (!argc)
            {
              show_usage (1);
            }
          repeats = atoi (*argv);
          if (!repeats)
            {
              show_usage (1);
            }
          argc--; argv++;
        }
    }

  init_gpgme_basic ();

  if (threads < argc)
    {
      /* Make sure we run once on each arg */
      threads += argc;
    }
  while (argc)
    {
      if (!msgs)
        {
          msgs = calloc (1, sizeof *msgs);
          msg_it = msgs;
        }
      else
        {
          msg_it->next = calloc (1, sizeof *msgs);
          msg_it = msg_it->next;
        }
      msg_it->file_name = *argv;
      argc--; argv++;
    }

  gpgrt_lock_lock (&threads_lock);
  do
    {
      stop = 0;
      thread_cnt = threads + 4;
      out ("Repeats left: %i", repeats);

      if (!no_list)
        {
          start_keylistings ();
        }
      else
        {
          thread_cnt -= 4;
        }

      while (thread_cnt)
        {
          log ("Thread %i", thread_cnt);
          for (msg_it = msgs; msg_it && thread_cnt; msg_it = msg_it->next)
            {
              thread_cnt--;
              create_thread (do_data_op, (void *)msg_it->file_name);
            }
        }

      stop = 1;
      gpgrt_lock_lock (&threads_lock);
    }
  while (--repeats != 0);

  return 0;
}
