/* assuan.c - Definitions for the Assuan protocol
 *	Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.
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
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA 
 */

#ifndef ASSUAN_H
#define ASSUAN_H

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>

#define _ASSUAN_IN_GPGME
#ifdef _ASSUAN_IN_GPGME
#define _ASSUAN_EXT_SYM_PREFIX _gpgme_

#ifdef _ASSUAN_IN_GPGME_BUILD_ASSUAN
int _gpgme_io_read (int fd, void *buffer, size_t count);
int _gpgme_io_write (int fd, const void *buffer, size_t count);
ssize_t _gpgme_ath_select (int nfd, fd_set *rset, fd_set *wset, fd_set *eset,
			   struct timeval *timeout);
ssize_t _gpgme_ath_waitpid (pid_t pid, int *status, int options);
int _gpgme_ath_accept (int s, struct sockaddr *addr, socklen_t *length_ptr);
int _gpgme_ath_connect (int s, struct sockaddr *addr, socklen_t length);
int _gpgme_ath_sendmsg (int s, const struct msghdr *msg, int flags);
int _gpgme_ath_recvmsg (int s, struct msghdr *msg, int flags);

#define read          _gpgme_io_read
#define write         _gpgme_io_write
#define waitpid	      _gpgme_ath_waitpid
#define select	      _gpgme_ath_select
#define accept        _gpgme_ath_accept
#define connect       _gpgme_ath_connect
#define sendmsg	      _gpgme_ath_sendmsg
#define recvmsg       _gpgme_ath_recvmsg
#endif
#endif

#ifdef _ASSUAN_EXT_SYM_PREFIX
#define _ASSUAN_PREFIX1(x,y) x ## y
#define _ASSUAN_PREFIX2(x,y) _ASSUAN_PREFIX1(x,y)
#define _ASSUAN_PREFIX(x) _ASSUAN_PREFIX2(_ASSUAN_EXT_SYM_PREFIX,x)
#define assuan_ _ASSUAN_PREFIX(assuan_)
#define assuan_register_command _ASSUAN_PREFIX(assuan_register_command)
#define assuan_register_bye_notify _ASSUAN_PREFIX(assuan_register_bye_notify)
#define assuan_register_reset_notify \
  _ASSUAN_PREFIX(assuan_register_reset_notify)
#define assuan_register_cancel_notify \
  _ASSUAN_PREFIX(assuan_register_cancel_notify)
#define assuan_register_input_notify \
  _ASSUAN_PREFIX(assuan_register_input_notify)
#define assuan_register_output_notify \
  _ASSUAN_PREFIX(assuan_register_output_notify)
#define assuan_register_option_handler \
  _ASSUAN_PREFIX(assuan_register_option_handler)
#define assuan_process _ASSUAN_PREFIX(assuan_process)
#define assuan_process_next _ASSUAN_PREFIX(assuan_process_next)
#define assuan_get_active_fds _ASSUAN_PREFIX(assuan_get_active_fds)
#define assuan_get_data_fp _ASSUAN_PREFIX(assuan_get_data_fp)
#define assuan_set_okay_line _ASSUAN_PREFIX(assuan_set_okay_line)
#define assuan_write_status _ASSUAN_PREFIX(assuan_write_status)
#define assuan_command_parse_fd _ASSUAN_PREFIX(assuan_command_parse_fd)
#define assuan_set_hello_line _ASSUAN_PREFIX(assuan_set_hello_line)
#define assuan_accept _ASSUAN_PREFIX(assuan_accept)
#define assuan_get_input_fd _ASSUAN_PREFIX(assuan_get_input_fd)
#define assuan_get_output_fd _ASSUAN_PREFIX(assuan_get_output_fd)
#define assuan_close_input_fd _ASSUAN_PREFIX(assuan_close_input_fd)
#define assuan_close_output_fd _ASSUAN_PREFIX(assuan_close_output_fd)
#define assuan_init_pipe_server _ASSUAN_PREFIX(assuan_init_pipe_server)
#define assuan_deinit_server _ASSUAN_PREFIX(assuan_deinit_server)
#define assuan_init_socket_server _ASSUAN_PREFIX(assuan_init_socket_server)
#define assuan_init_connected_socket_server \
  _ASSUAN_PREFIX(assuan_init_connected_socket_server)
#define assuan_pipe_connect _ASSUAN_PREFIX(assuan_pipe_connect)
#define assuan_socket_connect _ASSUAN_PREFIX(assuan_socket_connect)
#define assuan_domain_connect _ASSUAN_PREFIX(assuan_domain_connect)
#define assuan_init_domain_server _ASSUAN_PREFIX(assuan_init_domain_server)
#define assuan_disconnect _ASSUAN_PREFIX(assuan_disconnect)
#define assuan_get_pid _ASSUAN_PREFIX(assuan_get_pid)
#define assuan_transact _ASSUAN_PREFIX(assuan_transact)
#define assuan_inquire _ASSUAN_PREFIX(assuan_inquire)
#define assuan_read_line _ASSUAN_PREFIX(assuan_read_line)
#define assuan_pending_line _ASSUAN_PREFIX(assuan_pending_line)
#define assuan_write_line _ASSUAN_PREFIX(assuan_write_line)
#define assuan_send_data _ASSUAN_PREFIX(assuan_send_data)
#define assuan_sendfd _ASSUAN_PREFIX(assuan_sendfd)
#define assuan_receivefd _ASSUAN_PREFIX(assuan_receivefd)
#define assuan_set_malloc_hooks _ASSUAN_PREFIX(assuan_set_malloc_hooks)
#define assuan_set_log_stream _ASSUAN_PREFIX(assuan_set_log_stream)
#define assuan_set_error _ASSUAN_PREFIX(assuan_set_error)
#define assuan_set_pointer _ASSUAN_PREFIX(assuan_set_pointer)
#define assuan_get_pointer _ASSUAN_PREFIX(assuan_get_pointer)
#define assuan_begin_confidential _ASSUAN_PREFIX(assuan_begin_confidential)
#define assuan_end_confidential _ASSUAN_PREFIX(assuan_end_confidential)
#define assuan_strerror _ASSUAN_PREFIX(assuan_strerror)
#define assuan_set_assuan_log_stream \
  _ASSUAN_PREFIX(assuan_set_assuan_log_stream)
#define assuan_get_assuan_log_stream \
  _ASSUAN_PREFIX(assuan_get_assuan_log_stream)
#define assuan_get_assuan_log_prefix \
  _ASSUAN_PREFIX(assuan_get_assuan_log_prefix)

/* And now the internal functions, argh...  */
#define _assuan_read_line _ASSUAN_PREFIX(_assuan_read_line)
#define _assuan_cookie_write_data _ASSUAN_PREFIX(_assuan_cookie_write_data)
#define _assuan_cookie_write_flush _ASSUAN_PREFIX(_assuan_cookie_write_flush)
#define _assuan_read_from_server _ASSUAN_PREFIX(_assuan_read_from_server)
#define _assuan_domain_init _ASSUAN_PREFIX(_assuan_domain_init)
#define _assuan_register_std_commands \
  _ASSUAN_PREFIX(_assuan_register_std_commands)
#define _assuan_simple_read _ASSUAN_PREFIX(_assuan_simple_read)
#define _assuan_simple_write _ASSUAN_PREFIX(_assuan_simple_write)
#define _assuan_simple_read _ASSUAN_PREFIX(_assuan_simple_read)
#define _assuan_simple_write _ASSUAN_PREFIX(_assuan_simple_write)
#define _assuan_new_context _ASSUAN_PREFIX(_assuan_new_context)
#define _assuan_release_context _ASSUAN_PREFIX(_assuan_release_context)
#define _assuan_malloc _ASSUAN_PREFIX(_assuan_malloc)
#define _assuan_realloc _ASSUAN_PREFIX(_assuan_realloc)
#define _assuan_calloc _ASSUAN_PREFIX(_assuan_calloc)
#define _assuan_free _ASSUAN_PREFIX(_assuan_free)
#define _assuan_log_print_buffer _ASSUAN_PREFIX(_assuan_log_print_buffer)
#define _assuan_log_sanitized_string \
  _ASSUAN_PREFIX(_assuan_log_sanitized_string)

#endif

#ifdef __cplusplus
extern "C"
{
#endif
  

typedef enum
{
  ASSUAN_No_Error = 0,
  ASSUAN_General_Error = 1,
  ASSUAN_Out_Of_Core = 2,
  ASSUAN_Invalid_Value = 3,
  ASSUAN_Timeout = 4,
  ASSUAN_Read_Error = 5,
  ASSUAN_Write_Error = 6,
  ASSUAN_Problem_Starting_Server = 7,
  ASSUAN_Not_A_Server = 8,
  ASSUAN_Not_A_Client = 9,
  ASSUAN_Nested_Commands = 10,
  ASSUAN_Invalid_Response = 11,
  ASSUAN_No_Data_Callback = 12,
  ASSUAN_No_Inquire_Callback = 13,
  ASSUAN_Connect_Failed = 14,
  ASSUAN_Accept_Failed = 15,

  /* error codes above 99 are meant as status codes */
  ASSUAN_Not_Implemented = 100,
  ASSUAN_Server_Fault    = 101,
  ASSUAN_Invalid_Command = 102,
  ASSUAN_Unknown_Command = 103,
  ASSUAN_Syntax_Error    = 104,
  ASSUAN_Parameter_Error = 105,
  ASSUAN_Parameter_Conflict = 106,
  ASSUAN_Line_Too_Long = 107,
  ASSUAN_Line_Not_Terminated = 108,
  ASSUAN_No_Input = 109,
  ASSUAN_No_Output = 110,
  ASSUAN_Canceled = 111,
  ASSUAN_Unsupported_Algorithm = 112,
  ASSUAN_Server_Resource_Problem = 113,
  ASSUAN_Server_IO_Error = 114,
  ASSUAN_Server_Bug = 115,
  ASSUAN_No_Data_Available = 116,
  ASSUAN_Invalid_Data = 117,
  ASSUAN_Unexpected_Command = 118,
  ASSUAN_Too_Much_Data = 119,
  ASSUAN_Inquire_Unknown = 120,
  ASSUAN_Inquire_Error = 121,
  ASSUAN_Invalid_Option = 122,
  ASSUAN_Invalid_Index = 123,
  ASSUAN_Unexpected_Status = 124,
  ASSUAN_Unexpected_Data = 125,
  ASSUAN_Invalid_Status = 126,

  ASSUAN_Not_Confirmed = 128,

  ASSUAN_Bad_Certificate = 201,
  ASSUAN_Bad_Certificate_Chain = 202,
  ASSUAN_Missing_Certificate = 203,
  ASSUAN_Bad_Signature = 204,
  ASSUAN_No_Agent = 205,
  ASSUAN_Agent_Error = 206,
  ASSUAN_No_Public_Key = 207,
  ASSUAN_No_Secret_Key = 208,
  ASSUAN_Invalid_Name = 209,

  ASSUAN_Cert_Revoked = 301,
  ASSUAN_No_CRL_For_Cert = 302,
  ASSUAN_CRL_Too_Old = 303,
  ASSUAN_Not_Trusted = 304,

  ASSUAN_Card_Error = 401,
  ASSUAN_Invalid_Card = 402,
  ASSUAN_No_PKCS15_App = 403,
  ASSUAN_Card_Not_Present = 404,
  ASSUAN_Invalid_Id = 405

} AssuanError;

/* This is a list of pre-registered ASSUAN commands */
typedef enum
{
  ASSUAN_CMD_NOP = 0,
  ASSUAN_CMD_CANCEL,    /* cancel the current request */
  ASSUAN_CMD_BYE,
  ASSUAN_CMD_AUTH,
  ASSUAN_CMD_RESET,
  ASSUAN_CMD_OPTION,
  ASSUAN_CMD_DATA,
  ASSUAN_CMD_END,
  ASSUAN_CMD_INPUT,
  ASSUAN_CMD_OUTPUT,

  ASSUAN_CMD_USER = 256  /* Other commands should be used with this offset*/
} AssuanCommand;

#define ASSUAN_LINELENGTH 1002 /* 1000 + [CR,]LF */

struct assuan_context_s;
typedef struct assuan_context_s *ASSUAN_CONTEXT;

/*-- assuan-handler.c --*/
int assuan_register_command (ASSUAN_CONTEXT ctx,
                             const char *cmd_string,
                             int (*handler)(ASSUAN_CONTEXT, char *));
int assuan_register_bye_notify (ASSUAN_CONTEXT ctx,
                                void (*fnc)(ASSUAN_CONTEXT));
int assuan_register_reset_notify (ASSUAN_CONTEXT ctx,
                                  void (*fnc)(ASSUAN_CONTEXT));
int assuan_register_cancel_notify (ASSUAN_CONTEXT ctx,
                                   void (*fnc)(ASSUAN_CONTEXT));
int assuan_register_input_notify (ASSUAN_CONTEXT ctx,
                                  void (*fnc)(ASSUAN_CONTEXT, const char *));
int assuan_register_output_notify (ASSUAN_CONTEXT ctx,
                                  void (*fnc)(ASSUAN_CONTEXT, const char *));

int assuan_register_option_handler (ASSUAN_CONTEXT ctx,
                                    int (*fnc)(ASSUAN_CONTEXT,
                                               const char*, const char*));

int assuan_process (ASSUAN_CONTEXT ctx);
int assuan_process_next (ASSUAN_CONTEXT ctx);
int assuan_get_active_fds (ASSUAN_CONTEXT ctx, int what,
                           int *fdarray, int fdarraysize);


FILE *assuan_get_data_fp (ASSUAN_CONTEXT ctx);
AssuanError assuan_set_okay_line (ASSUAN_CONTEXT ctx, const char *line);
void assuan_write_status (ASSUAN_CONTEXT ctx,
                          const char *keyword, const char *text);

/* Negotiate a file descriptor.  If LINE contains "FD=N", returns N
   assuming a local file descriptor.  If LINE contains "FD" reads a
   file descriptor via CTX and stores it in *RDF (the CTX must be
   capable of passing file descriptors).  */
AssuanError assuan_command_parse_fd (ASSUAN_CONTEXT ctx, char *line,
				     int *rfd);

/*-- assuan-listen.c --*/
AssuanError assuan_set_hello_line (ASSUAN_CONTEXT ctx, const char *line);
AssuanError assuan_accept (ASSUAN_CONTEXT ctx);
int assuan_get_input_fd (ASSUAN_CONTEXT ctx);
int assuan_get_output_fd (ASSUAN_CONTEXT ctx);
AssuanError assuan_close_input_fd (ASSUAN_CONTEXT ctx);
AssuanError assuan_close_output_fd (ASSUAN_CONTEXT ctx);


/*-- assuan-pipe-server.c --*/
int assuan_init_pipe_server (ASSUAN_CONTEXT *r_ctx, int filedes[2]);
void assuan_deinit_server (ASSUAN_CONTEXT ctx);

/*-- assuan-socket-server.c --*/
int assuan_init_socket_server (ASSUAN_CONTEXT *r_ctx, int listen_fd);
int assuan_init_connected_socket_server (ASSUAN_CONTEXT *r_ctx, int fd);


/*-- assuan-pipe-connect.c --*/
AssuanError assuan_pipe_connect (ASSUAN_CONTEXT *ctx, const char *name,
                                 char *const argv[], int *fd_child_list);
/*-- assuan-socket-connect.c --*/
AssuanError assuan_socket_connect (ASSUAN_CONTEXT *ctx, const char *name,
                                   pid_t server_pid);

/*-- assuan-domain-connect.c --*/

/* Connect to a Unix domain socket server.  RENDEZVOUSFD is
   bidirectional file descriptor (normally returned via socketpair)
   which the client can use to rendezvous with the server.  SERVER s
   the server's pid.  */
AssuanError assuan_domain_connect (ASSUAN_CONTEXT *r_ctx,
				   int rendezvousfd,
				   pid_t server);

/*-- assuan-domain-server.c --*/

/* RENDEZVOUSFD is a bidirectional file descriptor (normally returned
   via socketpair) that the domain server can use to rendezvous with
   the client.  CLIENT is the client's pid.  */
AssuanError assuan_init_domain_server (ASSUAN_CONTEXT *r_ctx,
				       int rendezvousfd,
				       pid_t client);


/*-- assuan-connect.c --*/
void assuan_disconnect (ASSUAN_CONTEXT ctx);
pid_t assuan_get_pid (ASSUAN_CONTEXT ctx);

/*-- assuan-client.c --*/
AssuanError 
assuan_transact (ASSUAN_CONTEXT ctx,
                 const char *command,
                 AssuanError (*data_cb)(void *, const void *, size_t),
                 void *data_cb_arg,
                 AssuanError (*inquire_cb)(void*, const char *),
                 void *inquire_cb_arg,
                 AssuanError (*status_cb)(void*, const char *),
                 void *status_cb_arg);


/*-- assuan-inquire.c --*/
AssuanError assuan_inquire (ASSUAN_CONTEXT ctx, const char *keyword,
                            char **r_buffer, size_t *r_length, size_t maxlen);

/*-- assuan-buffer.c --*/
AssuanError assuan_read_line (ASSUAN_CONTEXT ctx,
                              char **line, size_t *linelen);
int assuan_pending_line (ASSUAN_CONTEXT ctx);
AssuanError assuan_write_line (ASSUAN_CONTEXT ctx, const char *line );
AssuanError assuan_send_data (ASSUAN_CONTEXT ctx,
                              const void *buffer, size_t length);

/* The file descriptor must be pending before assuan_receivefd is
   call.  This means that assuan_sendfd should be called *before* the
   trigger is sent (normally via assuan_send_data ("I sent you a
   descriptor")).  */
AssuanError assuan_sendfd (ASSUAN_CONTEXT ctx, int fd);
AssuanError assuan_receivefd (ASSUAN_CONTEXT ctx, int *fd);

/*-- assuan-util.c --*/
void assuan_set_malloc_hooks ( void *(*new_alloc_func)(size_t n),
                               void *(*new_realloc_func)(void *p, size_t n),
                               void (*new_free_func)(void*) );
void assuan_set_log_stream (ASSUAN_CONTEXT ctx, FILE *fp);
int assuan_set_error (ASSUAN_CONTEXT ctx, int err, const char *text);
void assuan_set_pointer (ASSUAN_CONTEXT ctx, void *pointer);
void *assuan_get_pointer (ASSUAN_CONTEXT ctx);

void assuan_begin_confidential (ASSUAN_CONTEXT ctx);
void assuan_end_confidential (ASSUAN_CONTEXT ctx);

/*-- assuan-errors.c (built) --*/
const char *assuan_strerror (AssuanError err);

/*-- assuan-logging.c --*/

/* Set the stream to which assuan should log.  By default, this is
   stderr.  */
extern void assuan_set_assuan_log_stream (FILE *fp);

/* Return the stream which is currently being using for logging.  */
extern FILE *assuan_get_assuan_log_stream (void);

/* User defined call back.  Return a prefix to be used at the start of
   a line emitted by assuan on the log stream.  The default
   implementation returns the empty string, i.e. ""  */
extern const char *assuan_get_assuan_log_prefix (void);

#ifdef __cplusplus
}
#endif
#endif /* ASSUAN_H */
