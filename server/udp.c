#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#define PORT_NUMBER 55555
#define BUFF_SIZE 2000
struct sockaddr_in peerAddr;

int initUDPServer();
void tunSelected();
void socketSelected();

int initUDPServer(){
    int sockfd;
    struct sockaddr_in server;
    char buff[100];

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(PORT_NUMBER);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    bind(sockfd, (struct sockaddr*) &server, sizeof(server));

    //Wait for client to "connect"
    printf("awaiting connection.\n");
    bzero(buff, 100);
    int peerAddrLen = sizeof(struct sockaddr_in);
    int len = recvfrom(sockfd, buff, 100, 0, (struct sockaddr *) &peerAddr, &peerAddrLen);

    printf("Connected with client: %s\n", buff);
    return sockfd;
}

void tunSelected(int tunfd, int sockfd){
    int len ;
    char buff[BUFF_SIZE];

    printf("Got a packet from TUN\n");

    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);
    sendto(sockfd, buff, len, 0, (struct sockaddr *) &peerAddr, sizeof(peerAddr));
}

void socketSelected(int tunfd, int sockfd){
    int len;
    char buff[BUFF_SIZE];

    printf("Got a packet from the tunnel\n");

    bzero(buff, BUFF_SIZE);
    len = recvfrom(sockfd, buff, BUFF_SIZE, 0, NULL, NULL);
    write(tunfd, buff, len);
}
