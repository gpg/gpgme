/* t-encrypt.c  - regression test
 *	Copyright (C) 2000 Werner Koch (dd9jn)
 *      Copyright (C) 2001 g10 Code GmbH
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <gpgme.h>

static const char test_text1[] = "Hallo Leute!\n";
static const char test_cip1[] =
"-----BEGIN CMS OBJECT-----\n"
"MIAGCSqGSIb3DQEHA6CAMIACAQAxggEJMIIBBQIBADBwMGsxCzAJBgNVBAYTAkRF\n"
"MRMwEQYDVQQHFApE/HNzZWxkb3JmMRYwFAYDVQQKEw1nMTAgQ29kZSBHbWJIMRkw\n"
"FwYDVQQLExBBZWd5cHRlbiBQcm9qZWN0MRQwEgYDVQQDEwt0ZXN0IGNlcnQgMQIB\n"
"ADALBgkqhkiG9w0BAQEEgYBOFcOfUtAav+XjKGM1RJtF+8JLkbnu46S3T3709Iok\n"
"u+Z9dwpOyfHwxXOmjzkSKQSBBxxi6ar+sKjU/KfPIvaMpARwT+NfIVSCZRWIJ27z\n"
"wbSrav/kcRRDDA0wXV7dHVmSLPUJNCpiFMNZbkYtI+ai15g0PVeDw+szYd9zdsjJ\n"
"2zCABgkqhkiG9w0BBwEwFAYIKoZIhvcNAwcECA8gPQY2NtJToIAECAeoY3MIcz9h\n"
"BAiiytWtOSmqnwAA\n"
"-----END CMS OBJECT-----\n";

#define fail_if_err(a) do { if(a) { int my_errno = errno; \
            fprintf (stderr, "%s:%d: GpgmeError %s\n", \
                 __FILE__, __LINE__, gpgme_strerror(a));   \
            if ((a) == GPGME_File_Error)                       \
                   fprintf (stderr, "\terrno=`%s'\n", strerror (my_errno)); \
                   exit (1); }                               \
                             } while(0)

static void
print_data (GpgmeData dh)
{
  char buf[100];
  int ret;
  
  ret = gpgme_data_seek (dh, 0, SEEK_SET);
  if (ret)
    fail_if_err (GPGME_File_Error);
  while ((ret = gpgme_data_read (dh, buf, 100)) > 0)
    fwrite (buf, ret, 1, stdout);
  if (ret < 0)
    fail_if_err (GPGME_File_Error);
}


int 
main (int argc, char **argv )
{
    GpgmeCtx ctx;
    GpgmeError err;
    GpgmeData in, out, pwdata = NULL;

  do {
    err = gpgme_new (&ctx);
    fail_if_err (err);
    gpgme_set_protocol (ctx, GPGME_PROTOCOL_CMS);

    err = gpgme_data_new_from_mem ( &in,
                                    test_cip1, strlen (test_cip1), 0 );
    fail_if_err (err);

    err = gpgme_data_new ( &out );
    fail_if_err (err);

    err = gpgme_op_decrypt (ctx, in, out );
    fail_if_err (err);

    fflush (NULL);
    fputs ("Begin Result:\n", stdout );
    print_data (out);
    fputs ("End Result.\n", stdout );
   
    gpgme_data_release (in);
    gpgme_data_release (out);
    gpgme_data_release (pwdata);
    gpgme_release (ctx);
  } while ( argc > 1 && !strcmp( argv[1], "--loop" ) );
   
    return 0;
}


