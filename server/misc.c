#include <linux/if.h>
#include <linux/if_tun.h>

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
