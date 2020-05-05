/*
  Author: [REDACTED] - 15008632
  Name: misc.c
  Operation: Class for miscelleneous operations used by both UDP and TLS or
              elsewhere in program operation.
*/
#include <linux/if.h>
#include <linux/if_tun.h>
#include <shadow.h>
#include <unistd.h>
#include <sys/types.h>

//PROTOTYPING
int createTUNDevice();
int rootCheck();
void routeServer();

/*
  Name: createTUNDevice()
  Operation: Creates the TUN interface.
  Inputs: N/A
  Outputs: int tunfd - TUN interface file descriptor.
  Notes: N/A
*/
int createTUNDevice(){
  //Initialise variables
  int tunfd;
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));

  //Create TUN interface.
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  tunfd = open("/dev/net/tun", O_RDWR);
  ioctl(tunfd, TUNSETIFF, &ifr);
  printf("TUN file descriptor: %d \n", tunfd);

  //Return file descriptor.
  return tunfd;
}

/*
  Name: rootCheck()
  Operation: Checks if the program is currently running with root access.
  Inputs: N/A
  Outputs: int 0 - Success value - program is running in root.
  Notes: Program needs to run in root to work.
*/
int rootCheck(){
  if(getuid() != 0){
    printf("This server requires root access to function correctly.\n");
    abort();
  } else {
    return 0;
  }
}

/*
  Name: routeServer()
  Operation: Enables packet forwarding.
              Assigns TUN interface an address.
              Directs traffic towards TUN interface.
  Inputs: N/A
  Outputs: N/A
  Notes: Are system calls like this a security issue? I feel like they might be.
*/
void routeServer(){
  system("sudo sysctl -w net.ipv4.ip_forward=1");
  system("sudo ifconfig tun0 10.4.2.5/24 up");
  system("sudo route add -net 10.4.2.0/24 tun0");
}
