/* context.h - Definitions for a GPGME context.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003 g10 Code GmbH

   This file is part of GPGME.
 
   GPGME is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
 
   GPGME is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with GPGME; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#ifndef CONTEXT_H
#define CONTEXT_H

#include "gpgme.h"
#include "engine.h"
#include "wait.h"


/* Operations might require to remember arbitrary information and data
   objects during invocations of the status handler.  The
   ctx_op_data structure provides a generic framework to hook in
   such additional data.  */
typedef enum
  {
    OPDATA_DECRYPT, OPDATA_SIGN, OPDATA_ENCRYPT, OPDATA_PASSPHRASE,
    OPDATA_IMPORT, OPDATA_GENKEY, OPDATA_KEYLIST, OPDATA_EDIT,
    OPDATA_VERIFY, OPDATA_TRUSTLIST
  } ctx_op_data_id_t;


struct ctx_op_data
{
  /* The next element in the linked list, or NULL if this is the last
     element.  */
  struct ctx_op_data *next;

  /* The type of the hook data, which can be used by a routine to
     lookup the hook data.  */
  ctx_op_data_id_t type;

  /* The function to release HOOK and all its associated resources.
     Can be NULL if no special dealllocation routine is necessary.  */
  void (*cleanup) (void *hook);

  /* The hook that points to the operation data.  */
  void *hook;
};
typedef struct ctx_op_data *ctx_op_data_t;


/* The context defines an environment in which crypto operations can
   be performed (sequentially).  */
struct gpgme_context
{
  /* The protocol used by this context.  */
  gpgme_protocol_t protocol;

  /* The running engine process.  */
  engine_t engine;

  /* True if armor mode should be used.  */
  unsigned int use_armor : 1;

  /* True if text mode should be used.  */
  unsigned int use_textmode : 1;

  /* Flags for keylist mode.  */
  gpgme_keylist_mode_t keylist_mode;

  /* Number of certs to be included.  */
  unsigned int include_certs;

  /* The number of keys in signers.  */
  unsigned int signers_len;

  /* Size of the following array.  */
  unsigned int signers_size;
  gpgme_key_t *signers;

  /* The locale for the pinentry.  */
  char *lc_ctype;
  char *lc_messages;

  /* The operation data hooked into the context.  */
  ctx_op_data_t op_data;

  /* The user provided passphrase callback and its hook value.  */
  gpgme_passphrase_cb_t passphrase_cb;
  void *passphrase_cb_value;

  /* The user provided progress callback and its hook value.  */
  gpgme_progress_cb_t progress_cb;
  void *progress_cb_value;

  /* A list of file descriptors in active use by the current
     operation.  */
  struct fd_table fdt;
  struct gpgme_io_cbs io_cbs;
};

#endif	/* CONTEXT_H */
