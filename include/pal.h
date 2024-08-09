#ifndef PAL_H
#define PAL_H

#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <linux/sockios.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/route.h>

#define RETURN_CALL(fd, ip_address, netmask_address) \
  close(fd);                                         \
  free(ip_address);                                  \
  free(netmask_address);
#define INET_ADDRSTRLEN 16
#define RTDST           "192.168.11.0"
#define RTGATEWAY       "0.0.0.0"
#define RTGENMASK       "255.255.255.0"


int get_system_value(const char *, const char *);
int get_network_id_and_gateway(const char *, int);
int get_ipv4_info(struct ifreq, int, struct sockaddr_in *);
int get_mac_address(struct ifreq, int);
int get_vlan_info(const char *, int);


int set_system_value(const char *, const char *, const char *);
int set_ipv4_address(int, const char *, const char *);
int set_mac_address(int, const char *, const char *);
int set_vlan_id(int, const char *, const char *);
int set_gateway(const char *, int, const char *);
void print_values(const char *);

#endif
