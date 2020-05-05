/*
  Author: [REDACTED] - 15008632
  Name: main.c
  Purpose: Recipe for various functionalities.
*/
#include "main.h"
/*
  Name: main
  Function: Allows the user to choose functionality.
  Inputs: int argc = number of command line Inputs
          char * argv = usually address and port for TCP/TLS
  Outputs: Return values = 0
           Never reached organically.
  Notes: Adapt user functionality to allow input of address and port instead
          of relying on command line input.
*/
int main(int argc, char * argv[]){
  rootCheck();

  int mode;
  //I implemented the title just for fun, and I like how it looks.
  system("clear");
  system("cat ./command_line_print/title.txt");
  printf("1.) UDP\n2.) TCP\n3.) Exit\n");

  do{
    scanf("%d", &mode);
    switch(mode){
      case 1:
        udpRUN();
        break;
      case 2:
        tlsRUN(argc, argv);
        break;
      case 3:
        exit(0);
        break;
      default: printf("Invalid Mode Input.\n");
        break;
    }//END OF SWITCH
  }while(mode != 3);
}//END OF MAIN

/*
  Name: udpRUN
  Function: UDP runtime recipe.
  Inputs: N/A
  Outputs: N/A
  Notes: Modify main input structure to allow input of IP and port, currently
          hardcoded -> security issue.
*/
void udpRUN(){
  //prompt address and port entry.
  int port;
  char *address;
  printf("\nEnter server address and port ([address] [port]): ");
  scanf("%s %d", address, &port);

  //create and initalise TUN device.
  tunfd = createTUNDevice();
  routeClient();

  //create UDP server session.
  sockfd = connectToUDPServer(address, port);

  //Enter main loop;
  udpProcess(tunfd, sockfd);
} //END OF UDPRUN

/*
  Name: tlsRUN
  Function: TCP/TLS runtime recipe.
  Inputs: int argc = command line arguments count
          char * argv = command line arguments
          Passed from main()
  Outputs: N/A
  Notes: Modify main() input structure to get and process hostname and port.
          Remove hardcoded defaults and implement input gate in main().
         For some reason moving SSL initialization functionality to an
          independent function causes setupTCPClient() to softlock?
*/
void tlsRUN(int argc, char * argv[]){
  //create TUN interface and configure it.
  tunfd = createTUNDevice();
  TLStunfd = tunfd;
  routeClient();

  //Bad initialization catch.
  if(argc < 3){
    printf("Input arguement error: sudo ./main [HOSTNAME] [PORT]\n");
    abort();
  }

  //2DO: move to main()
  char *hostname;
  int port;

  //grab address and port number from command line inputs.
  if (argc > 1) hostname = argv[1];
  if (argc > 2) port = atoi(argv[2]);

  //initialise TCP/TLS session.
  ssl = setupTLSClient(hostname);
  sockfd = setupTCPClient(hostname, port);
  TLSsockfd = sockfd;

  //Perform TLS handshake.
  SSL_set_fd(ssl, sockfd);
  int err = SSL_connect(ssl);
  processErr(err, ssl);
  printf("SSL connection is successful\n");
  printf ("SSL connection using %s\n", SSL_get_cipher(ssl));
  signal(SIGINT, closeHandler);

  //Prompt input of username and password for server side client authentication.
  clientAuth(ssl);

  //Mainloop
  while(1){
    fd_set readFDSet;
    FD_ZERO(&readFDSet);
    FD_SET(sockfd, &readFDSet);
    FD_SET(tunfd, &readFDSet);
    select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

    if(FD_ISSET(tunfd, &readFDSet)){
      TLStunSelected(tunfd, sockfd, ssl);
    } //TUNFD IF

    if(FD_ISSET(sockfd, &readFDSet)){
      TLSsocketSelected(tunfd, sockfd, ssl);
    }//SOCKFD IF
  }//END OF WHILE
}//END OF TLSRUN
