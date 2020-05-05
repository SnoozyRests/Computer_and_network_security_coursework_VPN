/*
  Author: [REDACTED] - 15008632
  Name: misc.c
  Purpose: Contains miscelleneous functions for the VPN implementation.
  Credits: Wenliang Du for createTUNDevice()
*/
#include <linux/if.h>
#include <linux/if_tun.h>

//PROTOTYPING
int createTUNDevice();
int rootCheck();
void routeClient();

/*
  Name: createTUNDevice
  Function: Creates a tunnel interface, will need configuring after.
  Input: N/A
  Output: int tunfd = tunnel file descriptor, used to identify tunnel interface.
  Notes: This function merely creates the interface, it will need configuring
          afterward, this can be done manually via command line or within this
          program using system() calls. See routeClient().
*/
int createTUNDevice(){
    int tunfd;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    tunfd = open("/dev/net/tun", O_RDWR);
    ioctl(tunfd, TUNSETIFF, &ifr);
    printf("TUN file descriptor: %d \n", tunfd);

    return tunfd;
}

/*
  Name: rootCheck()
  Function: Checks if the current program is running in route or not.
  Input: N/A
  Output: return value 0 if running in route.
  Notes: This program requires root to function correctly, and therefore must be
          ran in route privilege.
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
  Name: routeClient
  Function: Performs the necessary system calls to route the tunnel interface
            in the right direction.
  Input: N/A
  Output: N/A
  Notes: This will have to be configured to specific setups, perhaps research
          ways to do this dynamically? May fall out of bounds of the project
          scope.
          Client and Server TUN use format 10.4.2.X
          Internal Machines use IP format 192.168.60.X
*/
void routeClient(){
  system("sudo ifconfig tun0 10.4.2.99/24 up");
  system("sudo route add -net 10.4.2.0/24 tun0");
  system("sudo route add -net 192.168.60.0/24 tun0");
}
