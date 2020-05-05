/*
  Author: [REDACTED] - 15008632
  Name: udp.c
  Operations: UDP revelant functions and structures.
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

//DEFINITIONS
#define BUFF_SIZE 2000

//NETWORK STRUCTURES
struct sockaddr_in server_addr;

//PROTOTYPING
void udpProcess(int tunfd, int sockfd);
int connectToUDPServer();
void tunSelected(int tunfd, int sockfd);
void socketSelected(int tunfd, int sockfd);

/*
  Name: udpProcess
  Function: Performs the udp packet directing.
  Input: int tunfd = tunnel file descriptor.
         int sockfd = socket file descriptor.
  Outputs: N/A
  Notes: In theory it will never exit the while loop, perhaps implement a way
          to exit that doesnt involve interrupting the program via commandline.
*/
void udpProcess(int tunfd, int sockfd){
  while(1){
    //initialise file descriptor sets.
    fd_set readFDSet;
    FD_ZERO(&readFDSet);
    FD_SET(sockfd, &readFDSet);
    FD_SET(tunfd, &readFDSet);
    select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

    //Direct traffic.
    if(FD_ISSET(tunfd, &readFDSet)){
      tunSelected(tunfd, sockfd);
    } //END OF TUNFD IF

    if(FD_ISSET(sockfd, &readFDSet)){
      socketSelected(tunfd, sockfd);
    } //END OF SOCKFD IF
  } //END OF WHILE
} //END OF udpProcess()

/*
  Credit: Computer Security: A Hands-on Approach by Wenliang Du
  name: connectToUDPServer()
  Function: Initiates connection to UDP Server.
  Inputs: N/A
  Outputs: int sockfd = socket file descriptor.
  Notes: Implement method to remove hardcoded IP and port.
          Manual input after selection of UDP?
*/
int connectToUDPServer(char *address, int port){
  //initialise variables.
  int sockfd;
  char *hello = "hello";

  //initialise server address structure.
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  server_addr.sin_addr.s_addr = inet_addr(address);

  //create socket, get socket file descriptor.
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);

  //Send a hello message to "connect" with the VPN server.
  sendto(sockfd, hello, strlen(hello), 0, (struct sockaddr *) &server_addr, sizeof(server_addr));

  return sockfd;
}

/*
  Credit: Computer Security: A Hands-on Approach by Wenliang Du
  Name: tunSelected
  Function: Read packet from tunnel, send to the socket.
  Inputs: int tunfd = tunnel file descriptor.
          int sockfd = socket file descriptor.
  Outputs: N/A
  Notes: Requires modification for TLS, hence separate functions.
*/
void tunSelected(int tunfd, int sockfd){
  //Initialise variables.
  int len ;
  char buff[BUFF_SIZE];
  //printf("Got a packet from TUN\n");

  //read packet from TUN interface, send to the socket.
  bzero(buff, BUFF_SIZE);
  len = read(tunfd, buff, BUFF_SIZE);
  sendto(sockfd, buff, len, 0, (struct sockaddr *) &server_addr, sizeof(server_addr));
}

/*
  Credit: Computer Security: A Hands-on Approach by Wenliang Du
  Name: socketSelected
  Function: Recieve packet from socket, write it to tunnel.
  Inputs: int tunfd = tunnel file descriptor.
          int sockfd = socket file descriptor.
  Outputs: N/A
  Notes: Requires modification for TLS, hence separate functions.
*/
void socketSelected(int tunfd, int sockfd){
  //initialise variables.
  int len;
  char buff[BUFF_SIZE];
  //printf("Got a packet from the tunnel\n");

  //recieve from socket, write to TUN interface.
  bzero(buff, BUFF_SIZE);
  len = recvfrom(sockfd, buff, BUFF_SIZE, 0, NULL, NULL);
  write(tunfd, buff, len);
}
