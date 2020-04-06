#include "main.h"

int main(int argc, char * argv[]){
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

void udpRUN(){
    system("sudo sysctl -w net.ipv4.ip_forward=1");
    int tunfd, sockfd;
    tunfd = createTUNDevice();
    system("sudo ifconfig tun0 10.4.2.5/24 up");
    system("sudo route add -net 10.4.2.0/24 tun0");
    sockfd = initUDPServer();

    //Enter main loop;
    while(1){
        fd_set readFDSet;
        FD_ZERO(&readFDSet);
        FD_SET(sockfd, &readFDSet);
        FD_SET(tunfd, &readFDSet);
        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

        if(FD_ISSET(tunfd, &readFDSet)){
            tunSelected(tunfd, sockfd);
        }

        if(FD_ISSET(sockfd, &readFDSet)){
            socketSelected(tunfd, sockfd);
        }
    }
}

int tlsRUN(){
  system("sudo sysctl -w net.ipv4.ip_forward=1");
  int tunfd = createTUNDevice();
  system("sudo ifconfig tun0 10.4.2.5/24 up");
  system("sudo route add -net 10.4.2.0/24 tun0");

  SSL_METHOD *meth;
  SSL_CTX* ctx;
  SSL *ssl;
  int err;

  // Step 0: OpenSSL library initialization
  // This step is no longer needed as of version 1.1.0.
  SSL_library_init();
  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();

  // Step 1: SSL context initialization
  meth = (SSL_METHOD *)TLSv1_2_method();
  ctx = SSL_CTX_new(meth);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  // Step 2: Set up the server certificate and private key
  SSL_CTX_use_certificate_file(ctx, "./cert_server/server-cert.pem", SSL_FILETYPE_PEM);
  SSL_CTX_use_PrivateKey_file(ctx, "./cert_server/server-key.pem", SSL_FILETYPE_PEM);
  // Step 3: Create a new SSL structure for a connection
  ssl = SSL_new (ctx);

  struct sockaddr_in sa_client;
  size_t client_len;
  int sockfd = setupTCPServer();

  while(1){
    int sock = accept(sockfd, (struct sockaddr*)&sa_client, &client_len);
    //if (fork() == 0) { // The child process
       close (sockfd);

       SSL_set_fd(ssl, sock);
       int err = SSL_accept(ssl);
       CHK_SSL(err);
       printf("SSL connection established!\n");
       while(1){
           fd_set readFDSet;
           FD_ZERO(&readFDSet);
           FD_SET(sockfd, &readFDSet);
           FD_SET(tunfd, &readFDSet);
           select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

           if(FD_ISSET(tunfd, &readFDSet)){
               TLStunSelected(tunfd, sockfd, ssl);
           }

           if(FD_ISSET(sockfd, &readFDSet)){
               TLSsocketSelected(tunfd, sockfd, ssl);
           }
       }
       close(sock);
       return 0;
    //} else { // The parent process
        //close(sock);
    //}
  }
}
