/* context.h - Definitions for a GPGME context.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003, 2004, 2005, 2010 g10 Code GmbH

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

#ifndef CONTEXT_H
#define CONTEXT_H

#include "gpgme.h"
#include "engine.h"
#include "wait.h"
#include "sema.h"


extern gpgme_error_t _gpgme_selftest;

/* Operations might require to remember arbitrary information and data
   objects during invocations of the status handler.  The
   ctx_op_data structure provides a generic framework to hook in
   such additional data.  */
typedef enum
  {
    OPDATA_DECRYPT, OPDATA_SIGN, OPDATA_ENCRYPT, OPDATA_PASSPHRASE,
    OPDATA_IMPORT, OPDATA_GENKEY, OPDATA_KEYLIST, OPDATA_EDIT,
    OPDATA_VERIFY, OPDATA_TRUSTLIST, OPDATA_ASSUAN, OPDATA_VFS_MOUNT,
    OPDATA_PASSWD, OPDATA_EXPORT, OPDATA_KEYSIGN, OPDATA_TOFU_POLICY
  } ctx_op_data_id_t;


/* "gpgmeres" in ASCII.  */
#define CTX_OP_DATA_MAGIC 0x736572656d677067ULL
struct ctx_op_data
{
  /* A magic word just to make sure people don't deallocate something
     that ain't a result structure.  */
  unsigned long long magic;

  /* The next element in the linked list, or NULL if this is the last
     element.  Used by op data structures linked into a context.  */
  struct ctx_op_data *next;

  /* The type of the hook data, which can be used by a routine to
     lookup the hook data.  */
  ctx_op_data_id_t type;

  /* The function to release HOOK and all its associated resources.
     Can be NULL if no special deallocation routine is necessary.  */
  void (*cleanup) (void *hook);

  /* The hook that points to the operation data.  */
  void *hook;

  /* The number of outstanding references.  */
  int references;
};
typedef struct ctx_op_data *ctx_op_data_t;


/* The context defines an environment in which crypto operations can
   be performed (sequentially).  */
struct gpgme_context
{
  DECLARE_LOCK (lock);

  /* True if the context was canceled asynchronously.  */
  int canceled;

  /* The engine info for this context.  */
  gpgme_engine_info_t engine_info;

  /* The protocol used by this context.  */
  gpgme_protocol_t protocol;

  /* The running engine process.  */
  engine_t engine;

  /* Engine's sub protocol.  */
  gpgme_protocol_t sub_protocol;

  /* True if armor mode should be used.  */
  unsigned int use_armor : 1;

  /* True if text mode should be used.  */
  unsigned int use_textmode : 1;

  /* True if offline mode should be used.  */
  unsigned int offline : 1;

  /* True if a status callback shall be called for nearly all status
   * lines.  */
  unsigned int full_status : 1;

  /* The Tofu info has a human readable string which is presented to
   * the user in a directly usable format.  By enabling this flag the
   * unmodified string, as received form gpg, will be returned.  */
  unsigned int raw_description : 1;

  /* Flags for keylist mode.  */
  gpgme_keylist_mode_t keylist_mode;

  /* The current pinnetry mode.  */
  gpgme_pinentry_mode_t pinentry_mode;

  /* Number of certs to be included.  */
  unsigned int include_certs;

  /* The number of keys in signers.  */
  unsigned int signers_len;

  /* Size of the following array.  */
  unsigned int signers_size;
  gpgme_key_t *signers;

  /* The signature notations for this context.  */
  gpgme_sig_notation_t sig_notations;

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

  /* The user provided status callback and its hook value.  */
  gpgme_status_cb_t status_cb;
  void *status_cb_value;

  /* A list of file descriptors in active use by the current
     operation.  */
  struct fd_table fdt;
  struct gpgme_io_cbs io_cbs;
};

#endif	/* CONTEXT_H */
