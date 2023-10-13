/* trustlist.c - Trust item listing.
 * Copyright (C) 2000 Werner Koch (dd9jn)
 * Copyright (C) 2001, 2002, 2003, 2004 g10 Code GmbH
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

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "gpgme.h"
#include "debug.h"
#include "util.h"
#include "context.h"
#include "ops.h"


struct trust_queue_item_s
{
  struct trust_queue_item_s *next;
  gpgme_trust_item_t item;
};

typedef struct
{
  /* Something new is available.  */
  int trust_cond;
  struct trust_queue_item_s *trust_queue;
} *op_data_t;



static gpgme_error_t
trustlist_status_handler (void *priv, gpgme_status_code_t code, char *args)
{
  (void)priv;
  (void)code;
  (void)args;
  return 0;
}


/* This handler is used to parse the output of --list-trust-path:
   Format:
   level:keyid:type:recno:ot:val:mc:cc:name:
   With TYPE = U for a user ID
               K for a key
   The RECNO is either the one of the dir record or the one of the uid
   record.  OT is the usual trust letter and only available on K
   lines.  VAL is the calculated validity MC is the marginal trust
   counter and only available on U lines CC is the same for the
   complete count NAME ist the username and only printed on U
   lines.  */
static gpgme_error_t
trustlist_colon_handler (void *priv, char *line)
{
  gpgme_ctx_t ctx = (gpgme_ctx_t) priv;
  gpgme_error_t err;
  char *p, *pend;
  int field = 0;
  gpgme_trust_item_t item = NULL;

  if (!line)
    return 0; /* EOF */

  for (p = line; p; p = pend)
    {
      field++;
      pend = strchr (p, ':');
      if (pend)
	*pend++ = 0;

      switch (field)
	{
	case 1: /* level */
	  err = _gpgme_trust_item_new (&item);
	  if (err)
	    return err;
	  item->level = atoi (p);
	  break;
	case 2: /* long keyid */
	  if (strlen (p) == DIM(item->keyid) - 1)
	    strcpy (item->keyid, p);
	  break;
	case 3: /* type */
	  item->type = *p == 'K'? 1 : *p == 'U'? 2 : 0;
	  break;
	case 5: /* owner trust */
	  item->_owner_trust[0] = *p;
	  break;
	case 6: /* validity */
	  item->_validity[0] = *p;
	  break;
	case 9: /* user ID */
	  item->name = strdup (p);
	  if (!item->name)
	    {
              int saved_err = gpg_error_from_syserror ();
	      gpgme_trust_item_unref (item);
	      return saved_err;
	    }
	  break;
        }
    }

  if (item)
    _gpgme_engine_io_event (ctx->engine, GPGME_EVENT_NEXT_TRUSTITEM, item);
  return 0;
}


void
_gpgme_op_trustlist_event_cb (void *data, gpgme_event_io_t type,
			      void *type_data)
{
  gpgme_ctx_t ctx = (gpgme_ctx_t) data;
  gpgme_error_t err;
  void *hook;
  op_data_t opd;
  gpgme_trust_item_t item = (gpgme_trust_item_t) type_data;
  struct trust_queue_item_s *q, *q2;

  assert (type == GPGME_EVENT_NEXT_TRUSTITEM);

  err = _gpgme_op_data_lookup (ctx, OPDATA_TRUSTLIST, &hook, -1, NULL);
  opd = hook;
  if (err)
    return;

  q = malloc (sizeof *q);
  if (!q)
    {
      gpgme_trust_item_unref (item);
      /* FIXME: GPGME_Out_Of_Core; */
      return;
    }
  q->item = item;
  q->next = NULL;
  /* FIXME: Use a tail pointer */
  q2 = opd->trust_queue;
  if (!q2)
    opd->trust_queue = q;
  else
    {
      while (q2->next)
	q2 = q2->next;
      q2->next = q;
    }
  /* FIXME: unlock queue */
  opd->trust_cond = 1;
}


gpgme_error_t
gpgme_op_trustlist_start (gpgme_ctx_t ctx, const char *pattern, int max_level)
{
  gpgme_error_t err = 0;
  void *hook;
  op_data_t opd;

  TRACE_BEG  (DEBUG_CTX, "gpgme_op_trustlist_start", ctx,
	      "pattern=%s, max_level=%i", pattern, max_level);

  if (!ctx || !pattern || !*pattern)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = _gpgme_op_reset (ctx, 2);
  if (err)
    return TRACE_ERR (err);

  err = _gpgme_op_data_lookup (ctx, OPDATA_TRUSTLIST, &hook,
			       sizeof (*opd), NULL);
  opd = hook;
  if (err)
    return TRACE_ERR (err);

  _gpgme_engine_set_status_handler (ctx->engine,
				    trustlist_status_handler, ctx);
  err = _gpgme_engine_set_colon_line_handler (ctx->engine,
					      trustlist_colon_handler, ctx);
  if (err)
    return TRACE_ERR (err);

  err = _gpgme_engine_op_trustlist (ctx->engine, pattern);
  return TRACE_ERR (err);
}


gpgme_error_t
gpgme_op_trustlist_next (gpgme_ctx_t ctx, gpgme_trust_item_t *r_item)
{
  gpgme_error_t err;
  void *hook;
  op_data_t opd;
  struct trust_queue_item_s *q;

  TRACE_BEG (DEBUG_CTX, "gpgme_op_trustlist_next", ctx, "");

  if (!ctx || !r_item)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));
  *r_item = NULL;
  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = _gpgme_op_data_lookup (ctx, OPDATA_TRUSTLIST, &hook, -1, NULL);
  opd = hook;
  if (err)
    return TRACE_ERR (err);
  if (opd == NULL)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  if (!opd->trust_queue)
    {
      err = _gpgme_wait_on_condition (ctx, &opd->trust_cond, NULL);
      if (err)
	return TRACE_ERR (err);
      if (!opd->trust_cond)
	return TRACE_ERR (gpg_error (GPG_ERR_EOF));
      opd->trust_cond = 0;
      assert (opd->trust_queue);
    }
  q = opd->trust_queue;
  opd->trust_queue = q->next;

  *r_item = q->item;
  free (q);
  if ((*r_item)->type == 1)
    {
      TRACE_SUC ("trust_item=%p: %s: owner trust %s with level %i "
		  "and validity %s", *r_item, (*r_item)->keyid,
		  (*r_item)->owner_trust, (*r_item)->level,
		  (*r_item)->validity);
    }
  else if ((*r_item)->type == 2)
    {
      TRACE_SUC ("trust_item=%p: %s: UID %s with level %i "
		  "and validity %s", *r_item, (*r_item)->keyid,
		  (*r_item)->name, (*r_item)->level, (*r_item)->validity);
    }
  else
    {
      TRACE_SUC ("trust_item=%p: %s: unknown type %i with level %i "
		  "and validity %s", *r_item, (*r_item)->keyid,
		  (*r_item)->type, (*r_item)->level, (*r_item)->validity);
    }
  return 0;
}


/* Terminate a pending trustlist operation within CTX.  */
gpgme_error_t
gpgme_op_trustlist_end (gpgme_ctx_t ctx)
{
  TRACE (DEBUG_CTX, "gpgme_op_trustlist_end", ctx, "");

  if (!ctx)
    return gpg_error (GPG_ERR_INV_VALUE);

  return 0;
}
