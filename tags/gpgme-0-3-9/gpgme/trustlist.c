/* trustlist.c -  key listing
 *	Copyright (C) 2000 Werner Koch (dd9jn)
 *      Copyright (C) 2001, 2002 g10 Code GmbH
 *
 * This file is part of GPGME.
 *
 * GPGME is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GPGME is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include "util.h"
#include "context.h"
#include "ops.h"

struct gpgme_trust_item_s
{
  int level;
  char keyid[16+1];
  int type;   
  char ot[2];
  char val[2];
  char *name;
};


static GpgmeTrustItem
trust_item_new (void)
{
  GpgmeTrustItem item;

  item = xtrycalloc (1, sizeof *item);
  return item;
}


static void
trustlist_status_handler (GpgmeCtx ctx, GpgmeStatusCode code, char *args)
{
  if (ctx->error)
    return;

  switch (code)
    {
    case GPGME_STATUS_EOF:
      break;

    default:
      break;
    }
}


/* 
 * This handler is used to parse the output of --list-trust-path:
 * Format:
 *   level:keyid:type:recno:ot:val:mc:cc:name:
 * With TYPE = U for a user ID
 *	       K for a key
 * The RECNO is either the one of the dir record or the one of the uid record.
 * OT is the the usual trust letter and only availabel on K lines.
 * VAL is the calcualted validity
 * MC is the marginal trust counter and only available on U lines
 * CC is the same for the complete count
 * NAME ist the username and only printed on U lines
 */
static void
trustlist_colon_handler (GpgmeCtx ctx, char *line)
{
  char *p, *pend;
  int field = 0;
  GpgmeTrustItem item = NULL;

  if (ctx->error)
    return;
  if (!line)
    return; /* EOF */

  for (p = line; p; p = pend)
    {
      field++;
      pend = strchr (p, ':');
      if (pend) 
	*pend++ = 0;

      switch (field)
	{
	case 1: /* level */
	  item = trust_item_new ();
	  if (!item)
	    {
	      ctx->error = mk_error (Out_Of_Core);
	      return;
            }
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
	  item->ot[0] = *p;
	  item->ot[1] = 0;
	  break;
	case 6: /* validity */
	  item->val[0] = *p;
	  item->val[1] = 0;
	  break;
	case 9: /* user ID */
	  item->name = xtrystrdup (p);
	  if (!item->name)
	    ctx->error = mk_error (Out_Of_Core);
	  break;
        }
    }

  if (item)
    _gpgme_engine_io_event (ctx->engine, GPGME_EVENT_NEXT_TRUSTITEM, item);
}


void
_gpgme_op_trustlist_event_cb (void *data, GpgmeEventIO type, void *type_data)
{
  GpgmeCtx ctx = (GpgmeCtx) data;
  GpgmeTrustItem item = (GpgmeTrustItem) type_data;
  struct trust_queue_item_s *q, *q2;

  assert (type == GPGME_EVENT_NEXT_KEY);

  q = xtrymalloc (sizeof *q);
  if (!q)
    {
      gpgme_trust_item_release (item);
      ctx->error = mk_error (Out_Of_Core);
      return;
    }
  q->item = item;
  q->next = NULL;
  /* FIXME: lock queue, keep a tail pointer */
  q2 = ctx->trust_queue;
  if (!q2)
    ctx->trust_queue = q;
  else
    {
      while (q2->next)
	q2 = q2->next;
      q2->next = q;
    }
  /* FIXME: unlock queue */
  ctx->key_cond = 1;
}


GpgmeError
gpgme_op_trustlist_start (GpgmeCtx ctx, const char *pattern, int max_level)
{
  GpgmeError err = 0;

  if (!pattern || !*pattern)
    return mk_error (Invalid_Value);

  err = _gpgme_op_reset (ctx, 2);
  if (err)
    goto leave;

  err = _gpgme_engine_set_colon_line_handler (ctx->engine,
					      trustlist_colon_handler, ctx);
  if (err)
    goto leave;

  err =_gpgme_engine_op_trustlist (ctx->engine, pattern);

  if (!err)	/* And kick off the process.  */
    err = _gpgme_engine_start (ctx->engine, ctx);

 leave:
  if (err)
    {
      ctx->pending = 0; 
      _gpgme_engine_release (ctx->engine);
      ctx->engine = NULL;
    }
  return err;
}


GpgmeError
gpgme_op_trustlist_next (GpgmeCtx ctx, GpgmeTrustItem *r_item)
{
  struct trust_queue_item_s *q;

  if (!r_item)
    return mk_error (Invalid_Value);
  *r_item = NULL;
  if (!ctx)
    return mk_error (Invalid_Value);
  if (!ctx->pending)
    return mk_error (No_Request);
  if (ctx->error)
    return ctx->error;

  if (!ctx->trust_queue)
    {
      GpgmeError err = _gpgme_wait_on_condition (ctx, &ctx->key_cond);
      if (err)
	{
	  ctx->pending = 0;
	  return err;
	}
      if (!ctx->pending)
	{
	  /* The operation finished.  Because not all keys might have
	     been returned to the caller yet, we just reset the
	     pending flag to 1.  This will cause us to call
	     _gpgme_wait_on_condition without any active file
	     descriptors, but that is a no-op, so it is safe.  */
	  ctx->pending = 1;
	}
      if (!ctx->key_cond)
	{
	  ctx->pending = 0;
	  return mk_error (EOF);
	}
      ctx->key_cond = 0; 
      assert (ctx->trust_queue);
    }
  q = ctx->trust_queue;
  ctx->trust_queue = q->next;

  *r_item = q->item;
  xfree (q);
  return 0;
}


/**
 * gpgme_op_trustlist_end:
 * @c: Context
 *
 * Ends the trustlist operation and allows to use the context for some
 * other operation next.
 **/
GpgmeError
gpgme_op_trustlist_end (GpgmeCtx ctx)
{
  if (!ctx)
    return mk_error (Invalid_Value);
  if (!ctx->pending)
    return mk_error (No_Request);
  if (ctx->error)
    return ctx->error;

  ctx->pending = 0;
  return 0;
}


void
gpgme_trust_item_release (GpgmeTrustItem item)
{
  if (!item)
    return;
  xfree (item->name);
  xfree (item);
}


const char *
gpgme_trust_item_get_string_attr (GpgmeTrustItem item, GpgmeAttr what,
				  const void *reserved, int idx)
{
  const char *val = NULL;

  if (!item)
    return NULL;
  if (reserved)
    return NULL;
  if (idx)
    return NULL;

  switch (what)
    {
    case GPGME_ATTR_KEYID:
      val = item->keyid;
      break;
    case GPGME_ATTR_OTRUST:  
      val = item->ot;
      break;
    case GPGME_ATTR_VALIDITY:
      val = item->val;
      break;
    case GPGME_ATTR_USERID:  
      val = item->name;
      break;
    default:
      break;
    }
  return val;
}


int
gpgme_trust_item_get_int_attr (GpgmeTrustItem item, GpgmeAttr what,
			       const void *reserved, int idx)
{
  int val = 0;
  
  if (!item)
    return 0;
  if (reserved)
    return 0;
  if (idx)
    return 0;

  switch (what)
    {
    case GPGME_ATTR_LEVEL:    
      val = item->level;
      break;
    case GPGME_ATTR_TYPE:    
      val = item->type;
      break;
    default:
      break;
    }
  return val;
}
