/* sema.h - Definitions for semaphores.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2003 g10 Code GmbH

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

#ifndef SEMA_H
#define SEMA_H

struct critsect_s
{
  const char *name;
  void *private;
};

#define DEFINE_GLOBAL_LOCK(name) \
  struct critsect_s name = { #name, NULL }
#define DEFINE_STATIC_LOCK(name) \
  static struct critsect_s name  = { #name, NULL }

#define DECLARE_LOCK(name) \
  struct critsect_s name
#define INIT_LOCK(a)			\
  do					\
    {					\
      (a).name = #a;			\
      (a).private = NULL;		\
    }					\
  while (0)
#define DESTROY_LOCK(name) _gpgme_sema_cs_destroy (&(name))
                       

#define LOCK(name)			\
  do					\
    {					\
      _gpgme_sema_cs_enter (&(name));	\
    }					\
  while (0)

#define UNLOCK(name)			\
  do					\
    {					\
      _gpgme_sema_cs_leave (&(name));	\
    }					\
  while (0)

void _gpgme_sema_subsystem_init (void);
void _gpgme_sema_cs_enter (struct critsect_s *s);
void _gpgme_sema_cs_leave (struct critsect_s *s);
void _gpgme_sema_cs_destroy (struct critsect_s *s);

#endif /* SEMA_H */
