/* context.h 
 *	Copyright (C) 2000 Werner Koch (dd9jn)
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

#ifndef CONTEXT_H
#define CONTEXT_H

#include "gpgme.h"
#include "types.h"
#include "rungpg.h"  /* for GpgObject */

/* Currently we need it at several places, so we put the definition 
 * into this header file */
struct gpgme_context_s {
    int initialized;
    int pending;   /* a gpg request is still pending */
    
    GpgObject gpg; /* the running gpg process */

    int verbosity;  /* level of verbosity to use */
    int use_armor;  /* use armoring */
};


struct gpgme_data_s {
    size_t len;
    const char *data;
    GpgmeDataType type;
    GpgmeDataMode mode;
    size_t readpos;
    char *private_buffer;
};

struct recipient_s {
    struct recipient_s *next;
    char name[1];
};

struct gpgme_recipient_set_s {
    struct recipient_s *list;
    int checked;   /* wether the recipients are all valid */
};


#define fail_on_pending_request(c)                            \
          do {                                                \
                if (!(c))         return GPGME_Invalid_Value; \
                if ((c)->pending) return GPGME_Busy;          \
             } while (0)

#define wait_on_request_or_fail(c)                            \
          do {                                                \
                if (!(c))          return GPGME_Invalid_Value;\
                if (!(c)->pending) return GPGME_No_Request;   \
                gpgme_wait ((c), 1);                          \
             } while (0)



#endif /* CONTEXT_H */



