## ZoPHER v0.1b
Reverse HTTP Command Prompt using WinInet API

### Introduction

Zopher attempts to demonstrate using WinInet API, the creation of a persistent connection over HTTP or HTTPS for interacting with a Windows command prompt. It could in theory be used for many other features such as transfer of files between 2 hosts.<br><br>
The inbound data to cmd.exe is handled with a GET request and Chunked Transfer-Encoding which keeps the connection open.
The outbound data from cmd.exe is handled with a POST request which is also kept open until cmd.exe or connection abruptly terminates.

It hasn't been extensively tested in many environments and may not operate as intended where a proxy server is in operation.

### Prerequisites

zopher_s.c requires pthreads and libssl (if you decide to use SSL)
Both of these aren't native to Windows so you'll need to download separately if you want to compile for Windows using MSVC.

zopher_c.c uses only Windows API and should compile without problems using MSVC or Mingw.

### SSL support

A self-signed certificate and RSA private key is required to work.
An ASN1 encoded certificate and key is embedded in zopher_s.c already but as
a reminder to myself and in response to any questions on how to do this..

Follow these steps.

#### Generate a Private key
openssl genrsa -out RSA_KEY 2048
#### Generate a Certificate Signing Request
openssl req -new -key RSA_KEY -out server.csr
#### Generate a Self-Signed certificate
openssl x509 -req -days 365 -in server.csr -signkey RSA_KEY -out SSL_CERT<br>
<br>
At this point you can supply both SSL_CERT and RSA_KEY to zopher_s
using the -k and -c options or continue to create cert.h and key.h using
the DER formats.
<br>
#### Convert PEM files to DER
openssl x509 -in SSL_CERT -inform PEM -out SSL_CERT_DER -outform DER<br>
openssl rsa -in RSA_KEY -inform PEM -out RSA_KEY_DER -outform DER
#### Convert DER files into C header files
xxd -i SSL_CERT_DER > cert.h<br>
xxd -i RSA_KEY_DER > key.h<br>
### Known issues
Some proxy servers like older versions of Squid will perform requests using HTTP 1.0 even if the WinInet client uses HTTP 1.1. Therefore, the initial GET response from zopher_s will be considered invalid because it uses Chunked Transfer-Encoding which is only part of the 1.1 specifications.
<br><br>
SSL works fine because Squid can't modify the headers or see what's being sent back. But of course, SSL strippers will most likely drop the connection because the Content-Length: in POST request is 0.
So if you plan on using something like BurpSuite to examine the communication, this is unlikely to work.<br>
<br>
October 2013<br>
@cmpxchg8
