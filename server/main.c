/*
  Author: [REDACTED] - 15008632
  Name: main.c
  Operation: Recipe for virtual private network functionality.
*/
#include "main.h"

/*
  Name: main()
  Operation: Direct user to selected program functionality.
  Inputs: int argc - number of command line arguments.
          char * argv[] - command line arguments.
  Outputs: N/A
  Notes: N/A
*/
int main(int argc, char * argv[]){
  //check for root.
  rootCheck();

  //Load "GUI"
  //I did this to make it a little more obvious it was running.
  int mode;
  system("clear");
  system("cat ./command_line_print/title.txt");
  printf("1.) UDP\n2.) TCP\n3.) Exit\n");
  do{
    scanf("%d", &mode);
    switch(mode){
      case 1: udpRUN();
        break;
      case 2: tlsRUN();
        break;
      case 3: exit(0);
        break;
      default: printf("Invalid Mode Input.\n");
        break;
    }
  }while(mode != 3);
}

/*
  Name: udpRUN()
  Operation: UDP functionality recipe.
  Inputs: N/A
  Outputs: N/A
  Notes: N/A
*/
void udpRUN(){
  //initialise variables.
  int tunfd, sockfd;

  //create and configure TUN interface.
  tunfd = createTUNDevice();
  routeServer();

  //create UDP session
  sockfd = initUDPServer();

  //Enter main loop;
  udpProcessPacket(tunfd, sockfd);
}

/*
  Name: tlsRUN()
  Operation: TCP/TLS functionality recipe.
  Inputs: N/A
  Outputs: N/A
  Notes: Attempted to move SSL initialisation to its own function as in the
          client implementation, but for some reason this causes it to stop on
          the creation of the TCP server.
*/
int tlsRUN(){
  //Pipe variables
  int fd[2];
  pid_t pid;

  //create and configure TUN interface.
  int tunfd = createTUNDevice();
  routeServer();

  //create pipe
  pipe(fd);

  //First fork.
  if((pid = fork()) == -1){
    perror("fork");
    exit(1);
  }

  if(pid > 0){ //child process.
    close(fd[0]); //close recieving end of pipe.
    while(1){
      /*This process only needs to send to other processes and not recieve,
        therefore it only requires the TUNFD IF unlike other implementations*/
      fd_set readFDSet;
      FD_ZERO(&readFDSet);
      FD_SET(tunfd, &readFDSet);
      select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
      if(FD_ISSET(tunfd, &readFDSet)){
        pipeTUNSelected(tunfd, fd[1]);
      }
    }
    exit(0);
  } else {
    //close sending end of pipe.
    close(fd[1]);

    //initialise socket variables.
    struct sockaddr_in sa_client;
    size_t client_len;
    int listenSock = setupTCPServer();

    while(1){
      int sockfd = accept(listenSock, (struct sockaddr*)&sa_client, &client_len);
      if (fork() == 0) { // The child process
        close (listenSock);

        //initialise SSL context variables.
        SSL_METHOD *meth;
        SSL_CTX* ctx;
        SSL *ssl;
        int err;

        //Load SSL libraries.
        SSL_library_init();
        SSL_load_error_strings();
        SSLeay_add_ssl_algorithms();

        //Establish TLS method, add it to context.
        meth = (SSL_METHOD *)TLSv1_2_method();
        ctx = SSL_CTX_new(meth);

        //Server performs a custom verification of client later.
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

        //Designate certificate and key to use.
        SSL_CTX_use_certificate_file(ctx, "cert_server/jserver-cert.pem", SSL_FILETYPE_PEM);
        SSL_CTX_use_PrivateKey_file(ctx, "cert_server/jserver-keynew.pem", SSL_FILETYPE_PEM);

        //create the SSL context
        ssl = SSL_new(ctx);

        //Create the SSL session.
        SSL_set_fd(ssl, sockfd);
        err = SSL_accept(ssl);
        processErr(err, ssl);
        printf("SSL connection established!\n");

        //Authenitcate client
        if(authClient(ssl, sockfd) != 1){
          printf("Auth failed, terminating child process.\n");
          SSL_shutdown(ssl);
          SSL_free(ssl);
          close(sockfd);
          return 0;
        }

        //direct traffic.
        while(1){
          //create file descriptor sets
          fd_set readFDSet;
          FD_ZERO(&readFDSet);
          FD_SET(sockfd, &readFDSet);
          FD_SET(fd[0], &readFDSet);
          select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

          if(FD_ISSET(fd[0], &readFDSet)){
            TLStunSelected(fd[0], sockfd, ssl);
          }//END PIPE IF

          if(FD_ISSET(sockfd, &readFDSet)){
            TLSsocketSelected(tunfd, sockfd, ssl);
          }//END SOCKET IF
       }

       SSL_shutdown(ssl);
       SSL_free(ssl);
       close(sockfd);
       return 0;
    } else { // The parent process
        close(sockfd);
    }
  }
}
}
