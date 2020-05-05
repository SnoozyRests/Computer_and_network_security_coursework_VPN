/*
  Author: [REDACTED] - 15008632
  Name: tls.case
  Purpose: Contains functions and variables relevant to the tls functionality.
*/

#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <signal.h>

//DEFINITIONS
#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CA_DIR "ca_client"
#define BUFF_SIZE 2000

//GLOBAL VARIABLES
struct sockaddr_in server_addr;
SSL *ssl;
int TLSsockfd;
int TLStunfd;

//PROTOTYPING
int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx);
SSL* setupTLSClient(const char* hostname);
int setupTCPClient(const char* hostname, int port);
void TLStunSelected(int tunfd, int sockfd, SSL* ssl);
void TLSsocketSelected(int tunfd, int sockfd, SSL* ssl);
void processErr(int errcode, SSL* ssl);
int clientAuth(SSL *ssl);
void closeHandler();

/*
  Name: closeHandler()
  Operation: Ensures all the necessary preparations are made upon closing the
              program, including notifying the server.
  Inputs: N/A
  Outputs: Close notification packet client->server
  Notes: N/A
*/
void closeHandler(){
  //Initialise closing.
  printf("\nClosing...\n");
  char buff[BUFF_SIZE] = "&client&closed";
  buff[strlen(buff)] = '\0';

  //Tell server client has closed, close all relevant structs.
  if(ssl != NULL){
    SSL_write(ssl, buff, BUFF_SIZE-1);
    SSL_shutdown(ssl);
    SSL_free(ssl);
  }
  close(TLSsockfd);
  close(TLStunfd);
  exit(0);
}

/*
  Name: clientAuth()
  Operation: Client side of the server side client authentication.
  Inputs: SSL *ssl
  Outputs: Sucess Value 0.
  Notes: N/A
*/
int clientAuth(SSL *ssl){
  //initialise variables.
  char uName[100];
  int i = 0;
  char sendBuff[BUFF_SIZE];
  bzero(sendBuff, BUFF_SIZE);

  //get username.
  printf("Enter username:\n");
  scanf("%s", uName);
  getchar();

  //get password.
  char password[100];
  printf("Enter password:\n");
  scanf("%s", password);

  //send username and password to server.
  int sendLen = sprintf(sendBuff, "%s$%s", uName, password);
  sendBuff[sendLen] = '\0';
  SSL_write(ssl, sendBuff, sendLen);

  //await reply
  char recvBuff[BUFF_SIZE];
  bzero(recvBuff, BUFF_SIZE);
  int recvLen = SSL_read(ssl, recvBuff, BUFF_SIZE-1);
  recvBuff[recvLen] = '\0';

  //Verification approved.
  if(strstr(recvBuff, "&auth&ok") != NULL){
    printf("Server returns: Authentication Successful, Connection Established.\n");
    return 0;
  }

  //Verification failed, direct to close handler.
  printf("Auth Failed. Terminating.\n");
  closeHandler();
}

/*
  Name: verify_callback()
  Operation: Performs verification of the recieved x509 certificate.
  Inputs: int preverify_ok - Verification status.
          X509_STORE_CTX *x509_ctx - cert
  Outputs: N/A
  Notes: N/A
*/
int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx){
  //get current certificate
  char  buf[300];
  X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
  X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
  printf("subject= %s\n", buf);

  //check for verification.
  if (preverify_ok == 1) {
    printf("Verification passed.\n");
  } else {
    //If verification fails, get error, move to close handler.
    int err = X509_STORE_CTX_get_error(x509_ctx);
    printf("Verification failed: %s.\n", X509_verify_cert_error_string(err));
    closeHandler();
  }
}

/*
  Name: setupTLSClient()
  Operation: Loads all the relevant TLS functions and directories.
  Inputs: const char* hostname - server is hosts.etc
  Outputs: SSL* ssl - ssl context.
  Notes: Moved here from main.c
*/
SSL* setupTLSClient(const char* hostname){

  //Load SSL library stuff
  SSL_library_init();
  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();

  //Initialise variables for creating SSL context.
  SSL_METHOD *meth;
  SSL_CTX* ctx;
  SSL* ssl;

  //Establish method, add method to context.
  meth = (SSL_METHOD *)TLSv1_2_method();
  ctx = SSL_CTX_new(meth);

  //Set verification type, verification function, and add them to context.
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
  if(SSL_CTX_load_verify_locations(ctx,NULL, CA_DIR) < 1){
	   printf("Error setting the verify locations. \n");
	   exit(0);
   }

   //Write context to SSL.
   ssl = SSL_new (ctx);

   //Verify
   X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);
   X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

   //return context
   return ssl;
}

/*
  Name: setupTCPClient()
  Operation: Establishes the TCP client to allow connectivity and the beginning
              of the TLS handshake.
  Inputs: const char* hostname - server hostname as in hosts.etc
          int port - port the respective server is running on.
  Outputs: int sockfd - socket file descriptor.
  Notes: N/A
*/
int setupTCPClient(const char* hostname, int port){
  struct sockaddr_in server_addr;

  //Get the IP address from hostname
  struct hostent* hp = gethostbyname(hostname);

  //Create a TCP socket
  int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  //Fill in the destination information (IP, port #, and family)
  memset (&server_addr, '\0', sizeof(server_addr));
  memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
  server_addr.sin_port   = htons(port);
  server_addr.sin_family = AF_INET;

  //Connect to the destination
  connect(sockfd, (struct sockaddr*) &server_addr, sizeof(server_addr));

  return sockfd;
}

/*
  Name: TLStunSelected()
  Operation: Read and direct packets from the TUN interface to the socket.
  Inputs: int tunfd - TUN interface file descriptor
          int sockfd - Socket file descriptor.
          SSL* ssl - SSL context.
  Outputs: Packet client->server
  Notes: Modified from the UDP version, requires the ssl context and the usage
          of SSL_write in place of sendto().
*/
void TLStunSelected(int tunfd, int sockfd, SSL* ssl){
  //Initialisation
  int len;
  char buff[BUFF_SIZE];
  //printf("Got a packet from TUN\n");

  //read from TUN, write to socket.
  bzero(buff, BUFF_SIZE);
  len = read(tunfd, buff, BUFF_SIZE);
  buff[len] = '\0';
  SSL_write(ssl, buff, len);
}

/*
  Name: TLSsocketSelected()
  Operation: Read packets from the socket and write them to the TUN interface.
  Inputs: int tunfd - TUN interface file descriptor.
          int sockfd - socket file descriptor.
          SSL* ssl - ssl context.
  Outputs: server->client->TUN
  Notes: N/A
*/
void TLSsocketSelected(int tunfd, int sockfd, SSL* ssl){
  //Initialisation
  int len;
  char buff[BUFF_SIZE];

  //printf("Got a packet from the tunnel\n");
  //read from socket, write to tunnel.
  bzero(buff, BUFF_SIZE);
  len = SSL_read(ssl, buff, BUFF_SIZE);
  buff[len] = '\0';
  write(tunfd, buff, len);
}

/*
  Name: processErr()
  Operation: Deeper diagnoses of SSL errors during connection and context
              creation.
  Inputs: int err - SSL error code identifier
          SSL* ssl - ssl context.
  Outputs: Error diagnoses via command line.
  Notes: Mainly for debugging, could probably be removed for the most part.
*/
void processErr(int err, SSL* ssl){
  //Get error code
  int errorCode = SSL_get_error(ssl, err);

  //Diagnoses
  switch(errorCode){
    case SSL_ERROR_NONE:
      break;
	  case SSL_ERROR_ZERO_RETURN:
		  fprintf(stderr,"SSL connect returned 0.\n");
		  break;
	  case SSL_ERROR_WANT_READ:
      fprintf(stderr,"SSL connect: Read Error.\n");
      break;
	  case SSL_ERROR_WANT_WRITE:
      fprintf(stderr,"SSL connect: Write Error\n");
			break;
	  case SSL_ERROR_WANT_CONNECT:
      fprintf(stderr,"SSL connect: Error  connect.\n");
			break;
	  case SSL_ERROR_WANT_ACCEPT:
		  fprintf(stderr,"SSL connect: Error accept.\n");
			break;
	  case SSL_ERROR_WANT_X509_LOOKUP:
		  fprintf(stderr,"SSL connect error: X509 lookup.\n");
      break;
	  case SSL_ERROR_SYSCALL:
      fprintf(stderr,"SSL connect: Error in system call.\n");
      break;
	  case SSL_ERROR_SSL:
      fprintf(stderr,"SSL connect: Protocol Error.\n");
			break;
	  default: fprintf(stderr,"Failed SSL connect.\n");
  }
  CHK_SSL(err);
}
