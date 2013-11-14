/**
 * Copyright 2013 @cmpxchg8
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, 
 * MA  02111-1307 USA
 * 
 * http://www.gnu.org/licenses/gpl-2.0.txt
 * 
 */

#define APP_NAME     "ZoPHER"
#define APP_VERSION  "0.1b"
#define AUTHOR_EMAIL "@cmpxchg8"

#define HTTP_PORT       80
#define HTTPS_PORT     443
#define MAX_CONNECTION   2

#ifdef _WIN32
  #define WINDOWS
  #define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>

#include <errno.h>
#include <pthread.h>

// server stuff for Linux and Windows
#ifdef WINDOWS
 #include <ws2tcpip.h>
 #include <winsock2.h>
 #include <windows.h>

 #define snprintf _snprintf

#ifdef USE_SSL
 #pragma comment(lib, "..\\openssl\\lib\\ssleay32.lib")
 #pragma comment(lib, "..\\openssl\\lib\\libeay32.lib")
 #pragma comment(lib, "gdi32.lib")
 #pragma comment(lib, "advapi32.lib")
 #pragma comment(lib, "user32.lib")
#endif
 #pragma comment(lib, "ws2_32.lib")
 #pragma comment(lib, "wininet.lib")
 #pragma comment(lib, "..\\pthreads\\lib\\x86\\pthreadvc2.lib")
 
 #define in_addr_t unsigned long
 #define close closesocket
#else
 #include <unistd.h>
 #include <sys/socket.h>
 #include <sys/types.h>
 #include <arpa/inet.h>
 #include <netdb.h>
 #include <sys/ioctl.h>
 #include <net/if.h>
 #include <signal.h>
 #include <fcntl.h>
 #define SOCKET int
#endif

#ifdef USE_SSL
 #include "cert.h"
 #include "key.h"
 
 #include <openssl/ssl.h>
 #include <openssl/bio.h>
 #include <openssl/err.h>
 
 SSL_CTX *ctx;
#endif

#define GET_CTX  0
#define POST_CTX 1

typedef struct _THREAD_PARAMS_T {
  int ctx;
  pthread_t id;
  int sd;
#ifdef USE_SSL
  SSL *ssl;
#else
  int *ssl;
#endif
} thread_params_t;

thread_params_t tp[2];
int pfd[2];
int interrupted=0;

pthread_barrier_t b;
pthread_mutex_t m;
pthread_cond_t cv;
int connections=0, secure=0;
SOCKET sd;
int threads=0;

void xstrerror(const char fmt[], ...);

#define WDEBUG vout

int verbose=0;
/**********************************************************************
 * For debugging purposes
 **********************************************************************/
void vout (const char fmt[], ...) {
  va_list arglist;
  char    buffer[2048];
  
  if (verbose == 0) return;
  
  va_start (arglist, fmt);
  vsnprintf (buffer, sizeof(buffer) - 1, fmt, arglist);
  va_end (arglist);
  
  fprintf (stdout, "  %s\n", buffer);
  fflush (stdout);
}

/**********************************************************************
 * Display an error on both Linux / Windows
 **********************************************************************/
void xstrerror (const char fmt[], ...) {
  char    *error;
  va_list arglist;
  char    buffer[2048];
  
  va_start (arglist, fmt);
  vsnprintf (buffer, sizeof(buffer) - 1, fmt, arglist);
  va_end (arglist);
    
#ifdef WINDOWS
  FormatMessage (
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
      NULL, GetLastError (), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
      (LPSTR)&error, 0, NULL);
#else
  error = strerror (errno);
#endif
  fprintf (stdout, "  %s : %s\n", buffer, error);
#ifdef WINDOWS
  LocalFree (error);
#endif
}

/**********************************************************************
 *  Resolve ip or hostname
 **********************************************************************/
in_addr_t resolve (char host[]) {
  struct      hostent *hp;
  in_addr_t   host_ip = 0;

  host_ip = inet_addr (host);
  
  if (host_ip == INADDR_NONE) {
    hp = gethostbyname (host);
    if (hp != NULL) {
      host_ip = *(in_addr_t *)hp->h_addr;
    }
  }
  return host_ip;
}

/**********************************************************************
 * Responds to GET request by remote WinInet HTTP client.
 * Transfer-Encoding: Chunked attempts to keep connection open.
 * Reads commands from stdin and sends to remote client as 1 chunk
 **********************************************************************/
void get (void *arg) {
#ifdef WINDOWS
  WSANETWORKEVENTS ne;
  HANDLE           lh[2];
  u_long           off=0;
  DWORD            rn;
#endif
  fd_set           fds;
  int              idx, len, ret, quit=0;
  char             buf[BUFSIZ*2], cmd[BUFSIZ];
  
  const char chunk[]     = "%02x\r\n%s\r\n";
  const char response[]  = "HTTP/1.1 200 OK\r\n"
                           "Content-Type: text/html\r\n"
                           "Transfer-Encoding: Chunked\r\n"
                           "Server: "APP_NAME" v"APP_VERSION"\r\n"
                           "\r\n";
  
  idx = (tp[0].ctx == GET_CTX) ? 0 : 1;
  
  // send initial response
  if (tp[idx].ssl != NULL) 
  {
  #ifdef USE_SSL
    SSL_write (tp[idx].ssl, response, strlen(response));
  #endif
  } else {
    send (tp[idx].sd, response, strlen(response), 0);
  }
  
  WDEBUG ("GET: Thread Index : %i", idx);
  pthread_barrier_wait (&b);
  WDEBUG ("GET: Running");
  
  #ifdef WINDOWS
    lh[0] = (HANDLE)WSACreateEvent ();
    lh[1] = GetStdHandle (STD_INPUT_HANDLE);
  #endif
  
  while (!quit) 
  {
    WDEBUG ("GET: Waiting for events");
    
    #ifdef WINDOWS
      ret = WSAEventSelect (tp[idx].sd, lh[0], FD_CLOSE);
      if (ret == SOCKET_ERROR) {
        WDEBUG ("WSAEventSelect() error");
        break;
      }
      ret = WaitForMultipleObjects (2, lh, 
          FALSE, INFINITE) - WAIT_OBJECT_0;
      if (ret < 0) {
        WDEBUG ("WaitForSingleObject() error");
        break;
      }
      if (ret == 0) {
        FD_SET (tp[idx].sd, &fds);
        WSAEnumNetworkEvents (tp[idx].sd, lh[0], &ne);
      }
      
      WSAEventSelect (tp[idx].sd, lh[0], 0);
      ioctlsocket (tp[idx].sd, FIONBIO, &off);
    
      if (ne.lNetworkEvents & FD_CLOSE) {
        WDEBUG ("GET: socket closed");
        break;
      }
      
      if (ret == 1) {
        FD_SET (0, &fds);
      }
    #else
      FD_ZERO (&fds);
      FD_SET (tp[idx].sd, &fds);
      FD_SET (0, &fds);

      if (select (FD_SETSIZE, &fds, NULL, NULL, NULL) == -1) {
        WDEBUG ("GET: select() error");
        break;
      }
    #endif
    
    if (FD_ISSET(0, &fds))
    {
      WDEBUG ("GET: Reading from stdin.");
      memset (cmd, 0, BUFSIZ);
      #ifdef WINDOWS
        if (!ReadFile (lh[1], cmd, BUFSIZ, &rn, 0)) {
          WDEBUG ("ReadFile() failed.");
          break;
        }
        len = rn;
      #else
        len = read (0, cmd, BUFSIZ);
        cmd[len-1] = '\r';
        cmd[len++] = '\n';
      #endif
      if (strncmp (cmd, "exit", 4) == 0) {
        memset (cmd, 0, BUFSIZ);
        cmd[0] = '0'; // send EOF
        len    = 2;
        quit   = 1;
      }

      memset (buf, 0, BUFSIZ*2);
      snprintf (buf, BUFSIZ*2, chunk, len, cmd);
      
      WDEBUG ("GET: Sending command");
      
      if (tp[idx].ssl != 0) {
      #ifdef USE_SSL
        len = SSL_write (tp[idx].ssl, buf, strlen (buf));
      #endif
      } else {
        len = send (tp[idx].sd, buf, strlen (buf), 0);
      }
      if (len > 0) {
        WDEBUG ("GET: Command sent");
      } else if (len == 0) {
        WDEBUG ("GET: socket closed");
        break;
      } else if (len == -1) {
        WDEBUG ("GET: socket error");
        break;
      }
    }
  }
  WDEBUG ("GET: Ending thread.");
  pthread_mutex_lock (&m);
  threads--;
  pthread_cond_signal (&cv);
  pthread_mutex_unlock (&m);
  pthread_exit (NULL);
}

/**********************************************************************
 *  Accepts data in POST request by remote WinInet HTTP client
 *  Data received is written to stdout
 **********************************************************************/
void post (void *arg) {
#ifdef WINDOWS
  WSANETWORKEVENTS ne;
  HANDLE           e;
  u_long           off=0;
#endif
  fd_set           fds;
  int              idx, len, ret;
  char             buf[BUFSIZ];
  
  idx = (tp[0].ctx == GET_CTX) ? 1 : 0;
  
  WDEBUG ("POST: Thread Index : %i", idx);
  pthread_barrier_wait (&b);
  WDEBUG ("POST: Running");
  
  #ifdef WINDOWS
    e = (HANDLE)WSACreateEvent ();
  #endif
  
  while (1) 
  {
    WDEBUG ("POST: Waiting for events.");
    FD_ZERO (&fds);
    
    #ifdef WINDOWS  
      ret = WSAEventSelect (tp[idx].sd, e, FD_READ | FD_CLOSE);
      if (ret == SOCKET_ERROR) 
      {
        WDEBUG ("WSAEventSelect() error");
        break;
      }
      ret = WaitForSingleObject (e, INFINITE) - WAIT_OBJECT_0;
      
      if (ret != 0) 
      {
        WDEBUG ("WaitForSingleObject() error");
        break;
      }

      FD_SET (tp[idx].sd, &fds);
      WSAEnumNetworkEvents (tp[idx].sd, e, &ne);
     
      WSAEventSelect (tp[idx].sd, e, 0);
      ioctlsocket (tp[idx].sd, FIONBIO, &off);
      
      if (ne.lNetworkEvents & FD_CLOSE) 
      {
        WDEBUG ("POST: socket closed");
        break;
      }
    #else
      FD_SET (tp[idx].sd, &fds);
      
      if (select (FD_SETSIZE, &fds, NULL, NULL, NULL) == -1) 
      {
        WDEBUG ("POST: select() error");
        break;
      }
    #endif
    
    WDEBUG ("POST: Received event");
    
    // socket event?
    if (FD_ISSET(tp[idx].sd, &fds)) 
    {
      WDEBUG ("POST: socket event");      
      memset (buf, 0, BUFSIZ);
      
      if (tp[idx].ssl != NULL) 
      {
      #ifdef USE_SSL
        len = SSL_read (tp[idx].ssl, buf, BUFSIZ);
      #endif
      } else {
        len = recv (tp[idx].sd, buf, BUFSIZ, 0);
      }
      
      if (len > 0) 
      {
        WDEBUG ("POST: Writing data to stdout");
        write (fileno(stdout), buf, len);
      } else if (len == 0) {
        WDEBUG ("POST: socket closed");
        break;
      } else if (len == -1 ) {
        WDEBUG ("POST: socket error");
        break;
      }
    }
  }
  WDEBUG ("POST: Ending thread.");
  pthread_mutex_lock (&m);
  threads--;
  pthread_cond_signal (&cv);
  pthread_mutex_unlock (&m);
  pthread_exit (NULL);
}

/**********************************************************************
 *  Handle signals from operating system and user such as CTRL+C
 **********************************************************************/
int sig (int code) 
{
  #ifdef WINDOWS
    if (code != CTRL_C_EVENT) return 0;
    SetEvent ((HANDLE)pfd[0]);
  #else
    WDEBUG ("signal received %i", code);
    write (pfd[1], ".", 1);
  #endif
  pthread_mutex_lock (&m);
  interrupted = 1;
  pthread_cond_signal (&cv);
  pthread_mutex_unlock (&m);
  return 1;
}

#ifdef USE_SSL
int get_ssl_error (SSL *ssl, int ret)
{
  int code = SSL_get_error(ssl, ret);
  
  switch (code)
  {
    case SSL_ERROR_NONE :
      WDEBUG("SSL_ERROR_NONE");
      break;
    case SSL_ERROR_ZERO_RETURN :
      WDEBUG("SSL_ERROR_ZERO_RETURN");
      break;
    case SSL_ERROR_WANT_READ :
      WDEBUG("SSL_ERROR_WANT_READ");
      break;
    case SSL_ERROR_WANT_WRITE :
      WDEBUG("SSL_ERROR_WANT_WRITE");
      break;
    case SSL_ERROR_WANT_CONNECT :
      WDEBUG("SSL_ERROR_WANT_CONNECT");
      break;
    case SSL_ERROR_WANT_ACCEPT :
      WDEBUG("SSL_ERROR_WANT_ACCEPT");
      break;    
    case SSL_ERROR_WANT_X509_LOOKUP :
      WDEBUG("SSL_ERROR_WANT_X509_LOOKUP");
      break;    
    case SSL_ERROR_SYSCALL :
      WDEBUG("SSL_ERROR_SYSCALL");
      break;    
    case SSL_ERROR_SSL :
      WDEBUG("SSL_ERROR_SSL");
      break;
    default:
      WDEBUG("Unknown code : %08x", code);
      break;
  }
  return code;
}
#endif

/**
 *
 * intialize inbound connection
 *
 */
int init_request (int sd) {
  char      buf[BUFSIZ];
  int       ret = -1;
  socklen_t len = 0;
  int       idx = threads;
  fd_set    fds;
  int       i;
  int       status = 0;
  
  const char *methods[] = {"GET ", "POST"};
  
  memset (buf, 0, BUFSIZ);
  if (secure) 
  {
  #ifdef USE_SSL
    while (1) 
    {
      WDEBUG("Initializing SSL connection");
      if (tp[idx].ssl == NULL) 
      {
        tp[idx].ssl = SSL_new (ctx);
        if (tp[idx].ssl == NULL) {
          WDEBUG("SSL_new() failed");
          break;
        }
        if (!SSL_set_fd (tp[idx].ssl, sd)) {
          WDEBUG("SSL_set_fd() failed");
          break;
        }
        SSL_set_accept_state (tp[idx].ssl);
        SSL_accept (tp[idx].ssl);
      }
      len = SSL_read (tp[idx].ssl, buf, BUFSIZ);
      ret = get_ssl_error (tp[idx].ssl, len);
      
      if (ret != SSL_ERROR_WANT_READ) break;
      
      FD_ZERO(&fds);
      FD_SET(sd, &fds);  
      select (FD_SETSIZE, &fds, NULL, NULL, NULL); 
    }
  #endif
  } else {
    len = recv (sd, buf, BUFSIZ, 0);
  }
  
  if (len >= 4)
  {
    WDEBUG ("Read %u bytes", len);
    for (i = 0; i < MAX_CONNECTION; i++) {
      if (!strncmp (buf, methods[i], strlen (methods[i]))) {
        tp[idx].ctx = i;
        tp[idx].sd  = sd;
        WDEBUG ("Creating thread for %s", methods[i]);
        pthread_create (&tp[idx].id, 0, 
            (void*)(i == 0 ? get : post), (void*)NULL);
        status++;
      }
    }
  } else {
    WDEBUG ("Ignoring...");
    #ifdef USE_SSL
    if (tp[idx].ssl != NULL)
    {
      SSL_shutdown (tp[idx].ssl);
      SSL_free (tp[idx].ssl);
      tp[idx].ssl = NULL;
    }
    #endif
    WDEBUG ("Closing socket");
    close (sd);
  }
  return status;
}


void zopher_server (char address[], char cert[], char key[]) {
#ifdef WINDOWS
  WSADATA            wsa;
  DWORD              e;
  WSANETWORKEVENTS   ne;
  HANDLE             lh[2];
  u_long             off;
#else
  struct sigaction   handler;
#endif
  int                sd, ret, port, i;
  in_addr_t          ip;
  struct sockaddr_in l, p;
  fd_set             fds;
  socklen_t          plen;
  pthread_t          tid[MAX_CONNECTION];
  u_long             on;
#ifdef WINDOWS
  WSAStartup (MAKEWORD(2, 2), &wsa);
#endif

  if (secure) {
  #ifdef USE_SSL
    SSL_library_init();
    SSL_load_error_strings();
    
    ctx = SSL_CTX_new (SSLv23_server_method());

    if (cert != NULL) 
    {
      if (!SSL_CTX_use_certificate_file (ctx, 
           cert, SSL_FILETYPE_PEM)) 
      {  
        fprintf (stdout, "\n  Unable to load SSL cert : %s\n", cert);
        return;
      }
    } else {
      if (!SSL_CTX_use_certificate_ASN1(ctx, 
          SSL_CERT_DER_len, SSL_CERT_DER)) 
      {
        fprintf (stdout, "\n  Unable to set SSL cert\n");
        return;
      }
    }

    if (key != NULL) 
    {
      if (!SSL_CTX_use_PrivateKey_file (ctx, 
          key, SSL_FILETYPE_PEM)) 
      {  
        fprintf (stdout, "\n  Unable to load SSL private key : %s\n", key);
        return;
      }
    } else {
      if (!SSL_CTX_use_PrivateKey_ASN1(EVP_PKEY_RSA, ctx, 
          RSA_KEY_DER, RSA_KEY_DER_len)) 
      {
        fprintf(stdout, "\n  Unable to set SSL key\n");
        return;
      }
    }
    SSL_CTX_set_verify (ctx, SSL_VERIFY_NONE, NULL);
    port = HTTPS_PORT;
  #endif
  } else {
    port = HTTP_PORT;
  }
  
  sd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
  
  if (sd > 0)
  {
    on = 1;
    ret = setsockopt (sd, SOL_SOCKET, SO_REUSEADDR, (char*)&on, sizeof (on));
    
    ip = ((address == NULL) ? INADDR_ANY : resolve (address));
    
    memcpy (&l.sin_addr, &ip, sizeof (ip));
    l.sin_port   = htons (port);
    l.sin_family = AF_INET;
    
    if (!bind (sd, (struct sockaddr*)&l, sizeof (l)))
    {
      pthread_barrier_init (&b, NULL, MAX_CONNECTION);
      pthread_mutex_init (&m, NULL);
      pthread_cond_init (&cv, NULL);
    
      if (!listen (sd, MAX_CONNECTION))
      {
        fprintf (stdout, "\n  Listening on %s : %s (%i). . .\n", 
      (address == NULL) ? "any interface" : inet_ntoa (l.sin_addr), 
       port == HTTP_PORT ? "http" : "https", ntohs (l.sin_port));
      #ifdef WINDOWS
        pfd[0] = (int)CreateEvent (NULL, TRUE, FALSE, NULL);
        
        SetConsoleCtrlHandler ((PHANDLER_ROUTINE)sig, TRUE);
        
        lh[0] = (HANDLE)WSACreateEvent ();
        lh[1] = (HANDLE)pfd[0];
      #else
        pipe (pfd);              
        handler.sa_handler = (void (*)(int))sig;
        sigemptyset(&handler.sa_mask);
        handler.sa_flags = 0;
        sigaction (SIGINT, &handler, NULL); 
      #endif
      
        while (1)
        {
          WDEBUG ("MAIN: Waiting for events");

          FD_ZERO(&fds);
          
          #ifdef WINDOWS
            ret = WSAEventSelect (sd, lh[0], FD_ACCEPT);
            if (ret == SOCKET_ERROR) {
              WDEBUG ("MAIN: WSAEventSelect() error");
              break;
            }
            ret = WaitForMultipleObjects (2, lh, FALSE, INFINITE);
            if (ret == SOCKET_ERROR) {
              WDEBUG ("MAIN: WaitForMultipleObjects() error");
              break;
            }
            
            if (ret == 0) {
              WSAEnumNetworkEvents (sd, lh[0], &ne);
              FD_SET(sd, &fds);
            }
            
            if (ret == 1) {
              FD_SET(pfd[0], &fds);
            }
            
            WSAEventSelect (sd, lh[0], 0);
            off = 0;
            ioctlsocket (sd, FIONBIO, &off);
          #else
            FD_SET(sd, &fds);
            FD_SET(pfd[0], &fds);
            ret = select (FD_SETSIZE, &fds, NULL, NULL, NULL);
          #endif
          
          if (FD_ISSET(pfd[0], &fds)) {
            WDEBUG ("MAIN: Received interrupt");
            break;
          }
          
          if (FD_ISSET(sd, &fds)) 
          {
            WDEBUG ("Received socket event");
            plen = sizeof (p);
            ret = accept (sd, (struct sockaddr *)&p, &plen);
            if (ret < 0) continue;
            
            fprintf (stdout, "  Connection from %s:%i\n\n", 
              inet_ntoa (p.sin_addr), ntohs (p.sin_port));
              
            threads += init_request (ret);
          }
          
          WDEBUG ("MAIN: %i threads running.", threads);
          
          if (threads == MAX_CONNECTION) 
          {  
            // wait for a signal from interrupt or thread exiting
            pthread_mutex_lock (&m);
            pthread_cond_wait (&cv, &m);
            pthread_mutex_unlock (&m);
          
            #ifdef WINDOWS
              // Unblock any pending reads in GET thread.
              // Crude? Yes.. but easier than anything else
              // pre-Vista and we're only running once
              // so it doesn't matter much :)
              CloseHandle (GetStdHandle (STD_INPUT_HANDLE));
            #endif
            
            for (i = 0; i < MAX_CONNECTION; i++) 
            {
              if (tp[i].ssl != NULL)
              {
              #ifdef USE_SSL
                SSL_shutdown (tp[i].ssl);
                SSL_free (tp[i].ssl);
                tp[i].ssl = NULL;
              #endif
              }
              close (tp[i].sd);
            }
            for (i = 0; i < MAX_CONNECTION; i++) 
            {
              WDEBUG ("Waiting for thread ID %08X to end", tp[i].id);
              pthread_join (tp[i].id, (void*)NULL);
            }
            break;
          }
        }
        #ifdef WINDOWS
          CloseHandle (lh[0]);
          CloseHandle ((HANDLE)pfd[0]);
        #else
          close (pfd[0]);
          close (pfd[1]);
        #endif
      } else {
        xstrerror ("listen()");
      }
      
      pthread_mutex_destroy (&m);
      pthread_cond_destroy (&cv);
      pthread_barrier_destroy (&b);
    
    } else {
      xstrerror ("bind()");
    }
    close (sd);
  } else {
    xstrerror ("socket()");
  }
#ifdef WINDOWS
  WSACleanup ();
#endif
}

/**********************************************************************
 * Lists available interfaces to listen on. Linux / Windows only..
 **********************************************************************/
void list_interfaces(void) {
#ifdef WINDOWS
  #define ifr_addr iiAddress.AddressIn
#else
  struct ifconf ifc;
  #define INTERFACE_INFO struct ifreq
#endif
  struct sockaddr_in *sin;
  INTERFACE_INFO *ifr;
  int sd, i, num;
  size_t len;
  char buf[sizeof(INTERFACE_INFO) * 32];
#ifdef WINDOWS
  WSADATA wsa;
  WSAStartup (MAKEWORD(2, 0), &wsa);
#endif

  sd = socket(AF_INET, SOCK_STREAM, 0);
  if (sd < 0) {
    xstrerror ("socket()");
  } else {

  #ifdef WINDOWS
    if (WSAIoctl (sd, SIO_GET_INTERFACE_LIST, 0, 0, 
        buf, sizeof (buf), (void *)&num, 0, 0) < 0) {
      xstrerror ("WSAIoctl()");
    }
    ifr = (void *)buf;
  #else
    ifc.ifc_len = sizeof (buf);
    ifc.ifc_buf = buf;
    
    if (ioctl (sd, SIOCGIFCONF, (char *)&ifc) < 0) {
      xstrerror ("ioctl()");
    }
    num = ifc.ifc_len;
    ifr = ifc.ireq;
  #endif

    close (sd);
    
    fprintf (stdout, "\n  Listing available addresses\n\n");
    
    for (i = 0, len = 0; len < num; i++)
    {
      sin = (struct sockaddr_in *)&ifr->ifr_addr;

      if (sin->sin_family      != AF_INET)     continue;
      if (sin->sin_addr.s_addr == INADDR_NONE) continue;

      fprintf (stdout, "  [%i]: %s\n", i, inet_ntoa (sin->sin_addr));
      
      #ifdef WINDOWS
        len += sizeof (INTERFACE_INFO);
        ifr++;
      #else
        len += IFNAMSIZ + ifr->ifr_addr.sa_len;
        ifr += IFNAMSIZ + ifr->ifr_addr.sa_len;
      #endif
    }
  }
#ifdef WINDOWS
  WSACleanup();
#endif
}

/**********************************************************************
 *  Accepts data in POST request by remote WinInet HTTP client
 *  Data received is written to stdout
 **********************************************************************/
void usage(char argv[]) {
  
  fprintf (stdout, 
      "\n  Usage: %s <host> [options]\n"
      #ifdef USE_SSL
      "\n  -s             Listen with SSL"
      "\n  -k  <PEM file> SSL private key (PEM) for listening"
      "\n  -c  <PEM file> SSL certificate file (PEM) for listening"
      #endif
      "\n  -v             Enable verbose output (useful for debugging)"
      "\n  -i             List available interfaces to listen on\n\n", argv);
      
  fprintf (stdout, "\n  Press any key to continue . . .");
  fgetc (stdin);
  exit (0);
}

int main (int argc, char *argv[]) 
{
  int  i;
  char opt;
  char *address=NULL, *cert=NULL, *key=NULL;
    
  setbuf (stdout, NULL);
  setbuf (stderr, NULL);
  
  fprintf (stdout, 
      "\n  ZoPHER Server Component v"APP_VERSION
      "\n  Copyright (c) 2013 "AUTHOR_EMAIL"\n");
  
  for (i = 1; i < argc; i++) {
    if (argv[i][0] == '/' || argv[i][0] == '-') {
      opt = argv[i][1];
      switch (opt) {
        #ifdef USE_SSL
        case 'c' :
          if ((i + 1) < argc) {
            cert = argv[++i];
          } else {
            fprintf (stdout, "\n-c : missing cert file name.\n");
            return -1;
          }
          break;
        case 'k' :
          if ((i + 1) < argc) {
            key = argv[++i];
          } else {
            fprintf (stdout, "\n-k : missing key file name.\n");
            return -1;
          }
          break;
        case 's' :
          secure = 1;
          break;
        #endif
        case 'v' :
          verbose = 1;
          break;
        case 'i' :
          list_interfaces();
          return 0;
        case '?' :
        case 'h' :
          usage (argv[0]);
        default:
          fprintf (stdout, "\nUnknown option specified: %c\n", opt);
          usage (argv[0]);
      }
    } else {
      address = argv[i];
    }
  }
  zopher_server (address, cert, key);
  return 0;
}
