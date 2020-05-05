/*
  Author: [REDACTED] - 15008632
  Name: tls.c
  Operation: Contains all the functions relevant to the TCP/TLS operations/
*/
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>
#include <shadow.h>
#include <crypt.h>

//DEFINITIONS
#define BUFF_SIZE 2000
#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }

//SOCKET STRUCTURE
struct sockaddr_in peerAddr;

//PROTOTYPING
int setupTCPServer();
void TLStunSelected(int originfd, int sockfd, SSL *ssl);
void TLSsocketSelected(int tunfd, int sockfd, SSL *ssl);
void processErr(int errcode, SSL* ssl);
int authClient(SSL* ssl, int sockfd);
void clientClosed(char buff[], SSL* ssl, int sockfd);
void pipeTUNSelected(int tunfd, int pipefd);

/*
  Name: clientClosed()
  Operation: A checking algorithm for traffic coming from the socket.
              If it contains the client closure identifier, then the current
                child process is terminated and all its structures closed or
                freed.
  Inputs: char buff[] - packet contents
          SSL* ssl - current SSL context
          int sockfd - socket file descriptor.
  Outputs: N/A
  Notes: N/A
*/
void clientClosed(char buff[], SSL* ssl, int sockfd){
  //Only does anything if this IF statement is true.
  if((buff[0] != '\0') && strstr(buff, "&client&closed") != NULL){
    printf("Client has been closed, terminating connection...");
    if(ssl != NULL){
      SSL_shutdown(ssl);
      SSL_free(ssl);
    }
    close(sockfd);
    exit(0);
  }
}

/*
  Name: authClient()
  Operation: Authenticates client by recieving username and password entered
              clientside and comparing them against the shadowfile.
  Inputs: SSL* ssl - current SSL context
          int sockfd - socket file descriptor.
  Outputs: int -1 - Authentication Failed.
           int 1 - Authentication Success.
  Notes: Only uncomment prints for debugging purposes.
*/
int authClient(SSL* ssl, int sockfd){
  //create and initialise variables.
  char uName[100];
  char pword[100];
  char sendNegResp[] = "&not&ok&auth";
  char sendPosResp[] = "&auth&ok";
  char recvBuff[BUFF_SIZE];
  bzero(recvBuff, BUFF_SIZE);
  memset(&uName, 0x00, sizeof(uName));
  memset(&pword, 0x00, sizeof(pword));

  //Read the entered details
  int len = SSL_read(ssl, recvBuff, BUFF_SIZE-1);
  recvBuff[len] = '\0';
  char* pch = strtok(recvBuff, "$");

  //Get the username
  if(pch != NULL){
    strcpy(uName, pch);
    pch = strtok(NULL, "$");
  }

  //get the password
  if(pch != NULL){
    strcpy(pword, pch);
  }

  struct spwd *pw;
  char *epasswd;

  //Get shadowfile password by username, if there isnt one, fail.
  pw = getspnam(uName);
  if(pw == NULL){
    printf("No password for username\n");
    return -1;
  }

  //printf("Given Username: %s\n", uName);
  //printf("Given password: %s\n", pword);

  //Check password given matches password in the shadowfile.
  epasswd = crypt(pword, pw->sp_pwdp);
  if(strcmp(epasswd, pw->sp_pwdp)){ //No match, auth failed.
    printf("No Match.\n");
    SSL_write(ssl, sendNegResp, strlen(sendNegResp));
    return -1;
  }

  //Match, communicate success, return success.
  SSL_write(ssl, sendPosResp, strlen(sendPosResp));
  printf("Client Authentication Successful, establishing connection.\n");
  return 1;
}

/*
  Name: setupTCPServer()
  Operation: Establish the connection with the client via TCP.
  Inputs: N/A
  Outputs: int sockfd - Socket file descriptor.
  Notes: N/A
*/
int setupTCPServer(){
  //initialise variables.
  struct sockaddr_in sa_server;
  int sockfd, err;

  //Create socket
  sockfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  CHK_ERR(sockfd, "socket");

  //Define server characteristics
  memset (&sa_server, '\0', sizeof(sa_server));
  sa_server.sin_family = AF_INET;
  sa_server.sin_addr.s_addr = INADDR_ANY;
  sa_server.sin_port = htons (4433);

  //Bind server to socket.
  err = bind(sockfd, (struct sockaddr*)&sa_server, sizeof(sa_server));
  CHK_ERR(err, "bind");

  //Listen on socket
  err = listen(sockfd, 5);
  CHK_ERR(err, "listen");

  //return socket file descriptor
  return sockfd;
}

/*
  Name: pipeTUNSelected()
  Operation: Variation of TLStunSelected to work with the pipe.
  Inputs: int tunfd - TUN interface file descriptor.
          int pipefd - Pipe file descriptor.
  Outputs: TUN->PIPE
  Notes: N/A
*/
void pipeTUNSelected(int tunfd, int pipefd){
  //initialise variables.
  int len;
  char buff[BUFF_SIZE];
  bzero(buff, BUFF_SIZE);

  //Read from TUN, write to pipe.
  len = read(tunfd, buff, BUFF_SIZE);
  buff[len] = '\0';
  write(pipefd, buff, len);
}

/*
  Name: TLStunSelected()
  Operation: Reads traffic from TUN interface and writes it to socket.
  Inputs: int originfd - origin file descriptor.
          int sockfd - socket file descriptor.
          SSL *ssl - Current SSL context.
  Outputs: Socket<-TUN
  Notes: N/A
*/
void TLStunSelected(int originfd, int sockfd, SSL *ssl){
  //initialise variables.
  int len;
  char buff[BUFF_SIZE];
  bzero(buff, BUFF_SIZE);
  //printf("Got a packet from TUN\n");

  //read from TUN, write to socket.
  len = read(originfd, buff, BUFF_SIZE);
  buff[len] = '\0';
  SSL_write(ssl, buff, len);
}

/*
  Name: TLSsocketSelected()
  Operation: Reads traffic from socket, writes it to TUN interface.
  Inputs: int tunfd - TUN interface file descriptor.
          int sockfd - Socked file descriptor.
          SSL *ssl - Current SSL context.
  Outputs: N/A
*/
void TLSsocketSelected(int tunfd, int sockfd, SSL *ssl){
  //initialise variables.
  int len;
  char buff[BUFF_SIZE];
  bzero(buff, BUFF_SIZE);
  //printf("Got a packet from the tunnel\n");

  //read from socket, write to TUN
  len = SSL_read(ssl, buff, BUFF_SIZE);
  buff[len] = '\0';
  clientClosed(buff, ssl, sockfd); //check for closure identifier.
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
  //get error code
  int errorCode = SSL_get_error(ssl, err);

  //diagnoses
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
