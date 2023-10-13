/* util.h
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003, 2004, 2005 g10 Code GmbH

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
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#ifndef UTIL_H
#define UTIL_H

#ifdef HAVE_W32_SYSTEM
# include "winsock2.h"
# include "windows.h"
#endif

/* For pid_t.  */
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
/* We must see the symbol ttyname_r before a redefinition. */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <stdint.h>


#include "gpgme.h"


#define DIM(v) (sizeof(v)/sizeof((v)[0]))



/*-- {posix,w32}-util.c --*/
int _gpgme_get_conf_int (const char *key, int *value);
void _gpgme_allow_set_foreground_window (pid_t pid);

/*-- dirinfo.c --*/
void _gpgme_dirinfo_disable_gpgconf (void);

const char *_gpgme_get_default_homedir (void);
const char *_gpgme_get_default_agent_socket (void);
const char *_gpgme_get_default_gpg_name (void);
const char *_gpgme_get_default_gpgsm_name (void);
const char *_gpgme_get_default_g13_name (void);
const char *_gpgme_get_default_gpgconf_name (void);
const char *_gpgme_get_default_gpgtar_name (void);
const char *_gpgme_get_default_uisrv_socket (void);
int _gpgme_in_gpg_one_mode (void);

const char *_gpgme_get_basename (const char *name);



/*-- replacement functions in <funcname>.c --*/
#ifdef HAVE_CONFIG_H

#ifndef HAVE_STPCPY
static _GPGME_INLINE char *
_gpgme_stpcpy (char *a, const char *b)
{
  while (*b)
    *a++ = *b++;
  *a = 0;
  return a;
}
#define stpcpy(a,b) _gpgme_stpcpy ((a), (b))
#endif /*!HAVE_STPCPY*/


/* Due to a bug in mingw32's snprintf related to the 'l' modifier and
   for increased portability we use our snprintf on all systems. */
#undef snprintf
#define snprintf gpgrt_snprintf


#if REPLACE_TTYNAME_R
int _gpgme_ttyname_r (int fd, char *buf, size_t buflen);
#undef  ttyname_r
#define ttyname_r(a,b,c) _gpgme_ttyname_r ((a), (b), (c))
#endif

#endif /*HAVE_CONFIG_H*/


/*-- conversion.c --*/

/* Make sure to erase the memory (PTR,LEN).  */
void _gpgme_wipememory (void *ptr, size_t len);

/* Concatenate the string S1 with all the following strings up to a
   NULL.  Returns a malloced buffer with the new string or NULL on a
   malloc error or if too many arguments are given.  */
char *_gpgme_strconcat (const char *s1, ...) GPGRT_ATTR_SENTINEL(0);

/* Convert two hexadecimal digits from STR to the value they
   represent.  Returns -1 if one of the characters is not a
   hexadecimal digit.  */
int _gpgme_hextobyte (const char *str);

/* Decode the C formatted string SRC and store the result in the
   buffer *DESTP which is LEN bytes long.  If LEN is zero, then a
   large enough buffer is allocated with malloc and *DESTP is set to
   the result.  Currently, LEN is only used to specify if allocation
   is desired or not, the caller is expected to make sure that *DESTP
   is large enough if LEN is not zero.  */
gpgme_error_t _gpgme_decode_c_string (const char *src, char **destp,
				      size_t len);

/* Decode the percent escaped string SRC and store the result in the
   buffer *DESTP which is LEN bytes long.  If LEN is zero, then a
   large enough buffer is allocated with malloc and *DESTP is set to
   the result.  Currently, LEN is only used to specify if allocation
   is desired or not, the caller is expected to make sure that *DESTP
   is large enough if LEN is not zero.  If BINARY is 1, then '\0'
   characters are allowed in the output.  */
gpgme_error_t _gpgme_decode_percent_string (const char *src, char **destp,
					    size_t len, int binary);

gpgme_error_t _gpgme_encode_percent_string (const char *src, char **destp,
					    size_t len);

/* Split a string into space delimited fields and remove leading and
 * trailing spaces from each field.  A pointer to each field is
 * stored in ARRAY.  Stop splitting at ARRAYSIZE fields.  The function
 * modifies STRING.  The number of parsed fields is returned.  */
int _gpgme_split_fields (char *string, char **array, int arraysize);

/* Convert the field STRING into an unsigned long value.  Check for
 * trailing garbage.  */
gpgme_error_t _gpgme_strtoul_field (const char *string, unsigned long *result);

/* Convert STRING into an offset value similar to atoi().  */
uint64_t _gpgme_string_to_off (const char *string);

/* Parse the string TIMESTAMP into a time_t.  The string may either be
   seconds since Epoch or in the ISO 8601 format like
   "20390815T143012".  Returns 0 for an empty string or seconds since
   Epoch. Leading spaces are skipped. If ENDP is not NULL, it will
   point to the next non-parsed character in TIMESTRING. */
time_t _gpgme_parse_timestamp (const char *timestamp, char **endp);

/* Variant of _gpgme_parse_timestamp to return an unsigned long or 0
 * on error or missing timestamp.  */
unsigned long _gpgme_parse_timestamp_ul (const char *timestamp);

int _gpgme_map_pk_algo (int algo, gpgme_protocol_t protocol);

const char *_gpgme_cipher_algo_name (int algo, gpgme_protocol_t protocol);
const char *_gpgme_cipher_mode_name (int algo, gpgme_protocol_t protocol);


/*-- b64dec.c --*/

struct b64state
{
  int idx;
  int quad_count;
  char *title;
  unsigned char radbuf[4];
  int stop_seen:1;
  int invalid_encoding:1;
  gpg_error_t lasterr;
};

gpg_error_t _gpgme_b64dec_start (struct b64state *state, const char *title);
gpg_error_t _gpgme_b64dec_proc (struct b64state *state,
                                void *buffer, size_t length, size_t *r_nbytes);
gpg_error_t _gpgme_b64dec_finish (struct b64state *state);



/* Retrieve the environment variable NAME and return a copy of it in a
   malloc()'ed buffer in *VALUE.  If the environment variable is not
   set, return NULL in *VALUE.  */
gpgme_error_t _gpgme_getenv (const char *name, char **value);


/*-- status-table.c --*/
/* Convert a status string to a status code.  */
void _gpgme_status_init (void);
gpgme_status_code_t _gpgme_parse_status (const char *name);
const char *_gpgme_status_to_string (gpgme_status_code_t code);


#ifdef HAVE_W32_SYSTEM
int _gpgme_mkstemp (int *fd, char **name);
const char *_gpgme_get_w32spawn_path (void);
#endif /*HAVE_W32_SYSTEM*/



#include <assuan.h>
/* System hooks for assuan integration.  */
extern struct assuan_system_hooks _gpgme_assuan_system_hooks;
extern struct assuan_malloc_hooks _gpgme_assuan_malloc_hooks;
int _gpgme_assuan_log_cb (assuan_context_t ctx, void *hook,
			  unsigned int cat, const char *msg);



/* Parse the compliance field.  */
#define PARSE_COMPLIANCE_FLAGS(flags, result)				\
  do {									\
    char *comp_p, *comp_endp;						\
    unsigned long comp_ul;						\
									\
    for (comp_p = (flags);						\
	 comp_p								\
	   && (comp_ul = strtoul (comp_p, &comp_endp, 10))		\
	   && comp_p != comp_endp;					\
	 comp_p = comp_endp)						\
      {									\
	switch (comp_ul)						\
	  {								\
	  case 23: (result)->is_de_vs = 1; break;			\
	  }								\
      }									\
  } while (0)


#endif /* UTIL_H */
