#include "tls.c"
#include "udp.c"
#include "misc.c"
#define PORT_NUMBER 55555
#define BUFF_SIZE 2000
struct sockaddr_in peerAddr;

void udpRUN();
int tlsRUN();
