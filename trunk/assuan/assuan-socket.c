/* assuan-socket.c
 * Copyright (C) 2004, 2005 Free Software Foundation, Inc.
 *
 * This file is part of Assuan.
 *
 * Assuan is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Assuan is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_W32_SYSTEM
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <io.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#endif
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>

#include "assuan-defs.h"

/* Hacks for Slowaris.  */
#ifndef PF_LOCAL
# ifdef PF_UNIX
#  define PF_LOCAL PF_UNIX
# else
#  define PF_LOCAL AF_UNIX
# endif
#endif
#ifndef AF_LOCAL
# define AF_LOCAL AF_UNIX
#endif

#ifdef HAVE_W32_SYSTEM
#ifndef S_IRGRP
# define S_IRGRP 0
# define S_IWGRP 0
#endif
#endif


#ifdef HAVE_W32_SYSTEM
int
_assuan_sock_wsa2errno (int err)
{
  switch (err)
    {
    case WSAENOTSOCK:
      return EINVAL;
    case WSAEWOULDBLOCK:
      return EAGAIN;
    case ERROR_BROKEN_PIPE:
      return EPIPE;
    case WSANOTINITIALISED:
      return ENOSYS;
    default:
      return EIO;
    }
}


/* W32: Fill BUFFER with LENGTH bytes of random.  Returns -1 on
   failure, 0 on success.  Sets errno on failure.  */
static int
get_nonce (char *buffer, size_t nbytes) 
{
  HCRYPTPROV prov;
  int ret = -1;

  if (!CryptAcquireContext (&prov, NULL, NULL, PROV_RSA_FULL, 
                            (CRYPT_VERIFYCONTEXT|CRYPT_SILENT)) )
    errno = ENODEV;
  else 
    {
      if (!CryptGenRandom (prov, nbytes, buffer))
        errno = ENODEV;
      else
        ret = 0;
      CryptReleaseContext (prov, 0);
    }
  return ret;
}


/* W32: The buffer for NONCE needs to be at least 16 bytes.  Returns 0 on
   success and sets errno on failure. */
static int
read_port_and_nonce (const char *fname, unsigned short *port, char *nonce)
{
  FILE *fp;
  char buffer[50], *p;
  size_t nread;
  int aval;

  fp = fopen (fname, "rb");
  if (!fp)
    return -1;
  nread = fread (buffer, 1, sizeof buffer - 1, fp);
  fclose (fp);
  if (!nread)
    {
      errno = ENOFILE;
      return -1;
    }
  buffer[nread] = 0;
  aval = atoi (buffer);
  if (aval < 1 || aval > 65535)
    {
      errno = EINVAL;
      return -1;
    }
  *port = (unsigned int)aval;
  for (p=buffer; nread && *p != '\n'; p++, nread--)
    ;
  if (*p != '\n' || nread != 17)
    {
      errno = EINVAL;
      return -1;
    }
  p++; nread--;
  memcpy (nonce, p, 16);
  return 0;
}
#endif /*HAVE_W32_SYSTEM*/



int
_assuan_close (assuan_fd_t fd)
{
#ifdef _ASSUAN_CUSTOM_IO
  return _assuan_custom_close (fd);
#else
#ifdef (HAVE_W32_SYSTEM)
  int rc = closesocket (HANDLE2SOCKET(fd));
  if (rc)
    errno = _assuan_sock_wsa2errno (WSAGetLastError ());
  if (rc && WSAGetLastError () == WSAENOTSOCK)
    {
      rc = CloseHandle (fd);
      if (rc)
	/* FIXME. */
	errno = EIO;
    }
  return rc;
#else
  return close (fd);
#endif
#endif
}


/* Return a new socket.  Note that under W32 we consider a socket the
   same as an System Handle; all functions using such a handle know
   about this dual use and act accordingly. */ 
assuan_fd_t
_assuan_sock_new (int domain, int type, int proto)
{
#ifdef HAVE_W32_SYSTEM
  assuan_fd_t res;
  if (domain == AF_UNIX || domain == AF_LOCAL)
    domain = AF_INET;

#ifdef _ASSUAN_CUSTOM_IO
  return _assuan_custom_socket (domain, type, proto);
#else
  res = SOCKET2HANDLE(socket (domain, type, proto));
  if (res == ASSUAN_INVALID_FD)
    errno = _assuan_sock_wsa2errno (WSAGetLastError ());
  return res;
#endif

#else

#ifdef _ASSUAN_CUSTOM_IO
  return _gpgme_io_socket (domain, type, proto);
#else
  return socket (domain, type, proto);
#endif

#endif
}


int
_assuan_sock_connect (assuan_fd_t sockfd, struct sockaddr *addr, int addrlen)
{
#ifdef HAVE_W32_SYSTEM
  if (addr->sa_family == AF_LOCAL || addr->sa_family == AF_UNIX)
    {
      struct sockaddr_in myaddr;
      struct sockaddr_un *unaddr;
      unsigned short port;
      char nonce[16];
      int ret;
      
      unaddr = (struct sockaddr_un *)addr;
      if (read_port_and_nonce (unaddr->sun_path, &port, nonce))
        return -1;
      
      myaddr.sin_family = AF_INET;
      myaddr.sin_port = htons (port); 
      myaddr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  
      /* Set return values.  */
      unaddr->sun_family = myaddr.sin_family;
      unaddr->sun_port = myaddr.sin_port;
      unaddr->sun_addr.s_addr = myaddr.sin_addr.s_addr;
  
#ifdef _ASSUAN_CUSTOM_IO
      ret = _assuan_custom_connect (sockfd,
				    (struct sockaddr *)&myaddr, sizeof myaddr);
#else
      ret = connect (HANDLE2SOCKET(sockfd), 
                     (struct sockaddr *)&myaddr, sizeof myaddr);
#endif

      if (!ret)
        {
          /* Send the nonce. */

          ret = _assuan_io_write (sockfd, nonce, 16);
          if (ret >= 0 && ret != 16)
            {
              errno = EIO;
              ret = -1;
            }
        }
      else
        errno = _assuan_sock_wsa2errno (WSAGetLastError ());
      return ret;
    }
  else
    {
      int res;
      res = connect (HANDLE2SOCKET (sockfd), addr, addrlen);
      if (res < 0)
	errno = _assuan_sock_wsa2errno (WSAGetLastError ());
      return res;
    }      
#else

#ifdef _ASSUAN_CUSTOM_IO
  return _assuan_custom_connect (sockfd, addr, addrlen);
#else
  return connect (sockfd, addr, addrlen);
#endif

#endif
}


int
_assuan_sock_bind (assuan_fd_t sockfd, struct sockaddr *addr, int addrlen)
{
#ifdef HAVE_W32_SYSTEM
  if (addr->sa_family == AF_LOCAL || addr->sa_family == AF_UNIX)
    {
      struct sockaddr_in myaddr;
      struct sockaddr_un *unaddr;
      int filefd;
      FILE *fp;
      int len = sizeof myaddr;
      int rc;
      char nonce[16];

      if (get_nonce (nonce, 16))
        return -1;

      unaddr = (struct sockaddr_un *)addr;

      myaddr.sin_port = 0;
      myaddr.sin_family = AF_INET;
      myaddr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

      filefd = open (unaddr->sun_path, 
                     (O_WRONLY|O_CREAT|O_EXCL|O_BINARY), 
                     (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP));
      if (filefd == -1)
        {
          if (errno == EEXIST)
            errno = WSAEADDRINUSE;
          return -1;
        }
      fp = fdopen (filefd, "wb");
      if (!fp)
        { 
          int save_e = errno;
          close (filefd);
          errno = save_e;
          return -1;
        }

      rc = bind (HANDLE2SOCKET (sockfd), (struct sockaddr *)&myaddr, len);
      if (!rc)
        rc = getsockname (HANDLE2SOCKET (sockfd), 
                          (struct sockaddr *)&myaddr, &len);
      if (rc)
        {
          int save_e = errno;
          fclose (fp);
          remove (unaddr->sun_path);
          errno = save_e;
          return rc;
        }
      fprintf (fp, "%d\n", ntohs (myaddr.sin_port));
      fwrite (nonce, 16, 1, fp);
      fclose (fp);

      return 0;
    }
  else
    {
      int res = bind (HANDLE2SOCKET(sockfd), addr, addrlen);
      if (res < 0)
	errno = _assuan_sock_wsa2errno (WSAGetLastError ());
      return res;
    }
#else
  return bind (sockfd, addr, addrlen);
#endif
}


int
_assuan_sock_get_nonce (struct sockaddr *addr, int addrlen, 
                        assuan_sock_nonce_t *nonce)
{
#ifdef HAVE_W32_SYSTEM
  if (addr->sa_family == AF_LOCAL || addr->sa_family == AF_UNIX)
    {
      struct sockaddr_un *unaddr;
      unsigned short port;

      if (sizeof nonce->nonce != 16)
        {
          errno = EINVAL;
          return -1;
        }
      nonce->length = 16;
      unaddr = (struct sockaddr_un *)addr;
      if (read_port_and_nonce (unaddr->sun_path, &port, nonce->nonce))
        return -1;
    }
  else
    {
      nonce->length = 42; /* Arbitrary valuie to detect unitialized nonce. */
      nonce->nonce[0] = 42;
    }
#else
  (void)addr;
  (void)addrlen;
  nonce->length = 0;
#endif
  return 0;
}
 
 
int
_assuan_sock_check_nonce (assuan_fd_t fd, assuan_sock_nonce_t *nonce)
{
#ifdef HAVE_W32_SYSTEM
  char buffer[16], *p;
  size_t nleft;
  int n;

  if (sizeof nonce->nonce != 16)
    {
      errno = EINVAL;
      return -1;
    }

  if (nonce->length == 42 && nonce->nonce[0] == 42)
    return 0; /* Not a Unix domain socket.  */

  if (nonce->length != 16)
    {
      errno = EINVAL;
      return -1;
    }
      
  p = buffer;
  nleft = 16;
  while (nleft)
    {
      n = _assuan_io_read (SOCKET2HANDLE(fd), p, nleft);
      if (n < 0 && errno == EINTR)
        ;
      else if (n < 0 && errno == EAGAIN)
        Sleep (100);
      else if (n < 0)
        return -1;
      else if (!n)
        {
          errno = EIO;
          return -1;
        }
      else
        {
          p += n;
          nleft -= n;
        }
    }
  if (memcmp (buffer, nonce->nonce, 16))
    {
      errno = EACCES;
      return -1;
    }
#else
  (void)fd;
  (void)nonce;
#endif
  return 0;
}


/* Public API.  */
int
assuan_sock_close (assuan_fd_t fd)
{
  return _assuan_close (fd);
}

assuan_fd_t 
assuan_sock_new (int domain, int type, int proto)
{
  return _assuan_sock_new (domain, type, proto);
}

int
assuan_sock_connect (assuan_fd_t sockfd, struct sockaddr *addr, int addrlen)
{
  return _assuan_sock_connect (sockfd, addr, addrlen);
}

int
assuan_sock_bind (assuan_fd_t sockfd, struct sockaddr *addr, int addrlen)
{
  return _assuan_sock_bind (sockfd, addr, addrlen);
}

int
assuan_sock_get_nonce (struct sockaddr *addr, int addrlen, 
                       assuan_sock_nonce_t *nonce)
{     
  return _assuan_sock_get_nonce (addr, addrlen, nonce);
}

int
assuan_sock_check_nonce (assuan_fd_t fd, assuan_sock_nonce_t *nonce)
{
  return _assuan_sock_check_nonce (fd, nonce);
}
