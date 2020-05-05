/*
  Author: [REDACTED] - 15008632
  Name: main.h
  Operation: Bridge between main and c class files.
*/
#include "udp.c"
#include "tls.c"
#include "misc.c"

int tunfd;
int sockfd;
void udpRUN();
void tlsRUN(int argc, char * argv[]);
