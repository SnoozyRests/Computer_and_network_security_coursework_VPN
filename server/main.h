/*
  Author: [REDACTED] - 15008632
  Name: main.h
  Operation: Bridge between main file and class files.
*/
#include "tls.c"
#include "udp.c"
#include "misc.c"

//DEFINITIONS
#define PORT_NUMBER 55555
#define BUFF_SIZE 2000

//SOCKET STRUCTURE
struct sockaddr_in peerAddr;

//PROTOTYPING
void udpRUN();
int tlsRUN();
