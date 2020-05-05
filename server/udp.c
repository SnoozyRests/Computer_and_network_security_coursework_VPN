/*
  Author: [REDACTED] - 15008632
  Name: udp.c
  Operation: Contains all the UDP functionality relevant functions.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

//DEFINITIONS
#define PORT_NUMBER 55555
#define BUFF_SIZE 2000

//SOCKET STRUCTURE
struct sockaddr_in peerAddr;

//PROTOTYPING
int initUDPServer();
void tunSelected();
void socketSelected();
void udpProcessPacket(int tunfd, int sockfd);

/*
  Name: udpProcessPacket()
  Operation: Directs traffic.
  Inputs: int tunfd - TUN interface file descriptor.
          int sockfd - Socket file descriptor.
  Outputs: N/A
  Notes: N/A
*/
void udpProcessPacket(int tunfd, int sockfd){
  while(1){
    //create file decriptor set.
    fd_set readFDSet;
    FD_ZERO(&readFDSet);
    FD_SET(sockfd, &readFDSet);
    FD_SET(tunfd, &readFDSet);
    select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

    //direct traffic.
    if(FD_ISSET(tunfd, &readFDSet)){
        tunSelected(tunfd, sockfd);
    }// END OF TUN IF

    if(FD_ISSET(sockfd, &readFDSet)){
        socketSelected(tunfd, sockfd);
    }// END OF SOCK IF
  }// END OF WHILE
}

/*
  Name: initUDPServer()
  Operation: Creates the UDP server.
  Inputs: N/A
  Outputs: int sockfd - socket file descriptor.
  Notes: N/A
*/
int initUDPServer(){
  //initialise variables.
  int sockfd;
  struct sockaddr_in server;
  char buff[100];

  //initialise server characteristics.
  memset(&server, 0, sizeof(server));
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = htonl(INADDR_ANY);
  server.sin_port = htons(PORT_NUMBER);

  //create and bind socket.
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  bind(sockfd, (struct sockaddr*) &server, sizeof(server));

  //Wait for client to connect
  printf("awaiting connection.\n");
  bzero(buff, 100);
  int peerAddrLen = sizeof(struct sockaddr_in);
  int len = recvfrom(sockfd, buff, 100, 0, (struct sockaddr *) &peerAddr, &peerAddrLen);

  //Successful connection.
  printf("Connected with client: %s\n", buff);
  return sockfd;
}

/*
  Name: tunSelected()
  Operation: Reads from TUN interface, writes to socket.
  Inputs: int tunfd - TUN interface file descriptor.
          int sockfd - Socket file descriptor.
  Outputs: N/A
  Notes: N/A
*/
void tunSelected(int tunfd, int sockfd){
  //initialise variables.
  int len ;
  char buff[BUFF_SIZE];
  bzero(buff, BUFF_SIZE);
  //printf("Got a packet from TUN\n");

  //read from TUN, write to socket.
  len = read(tunfd, buff, BUFF_SIZE);
  sendto(sockfd, buff, len, 0, (struct sockaddr *) &peerAddr, sizeof(peerAddr));
}

/*
  Name: socketSelected()
  Operation: Reads from socket, writes to TUN interface.
  Inputs: int tunfd - TUN interface file descriptor.
          int sockfd - Socket file descriptor.
  Outputs: N/A
  Notes: N/A
*/
void socketSelected(int tunfd, int sockfd){
  //initialise variables.
  int len;
  char buff[BUFF_SIZE];
  bzero(buff, BUFF_SIZE);
  //printf("Got a packet from the tunnel\n");

  //read from socket, write to TUN interface.
  len = recvfrom(sockfd, buff, BUFF_SIZE, 0, NULL, NULL);
  write(tunfd, buff, len);
}
