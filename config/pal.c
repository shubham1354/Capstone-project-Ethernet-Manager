#include "pal.h"
#include "config.h"
#include "uil.h"

char *mac             = NULL;
char *ip_address      = NULL;
char *netmask_address = NULL;
char *network_id      = NULL;
char *gateway         = NULL;
struct vlan_ioctl_args vlan_args;
extern char print_flag;

/*<--------------------------------------------------------------------------------------->*/


/* Function will get network id and gateway address */
int get_network_id_and_gateway(const char *interface_name, int fd)
{
  FILE *fp;
  char line[256];
  char iface[16];
  unsigned long dest, gw, mask;
  struct in_addr addr;
  int found = 0;

  // Allocate memory for network_id and gateway
  network_id = (char *)malloc(20);
  if (network_id == NULL) {
    perror("Failed to allocate memory for network_id");
    close(fd);
    return -1;
  }

  gateway = (char *)malloc(20);
  if (gateway == NULL) {
    perror("Failed to allocate memory for gateway");
    free(network_id); // Free previously allocated memory
    close(fd);
    free(network_id);
    return -1;
  }

  fp = fopen("/proc/net/route", "r");
  if (fp == NULL) {
    perror("fopen");
    free(gateway);
    free(network_id);
    return -1;
  }

  // Skip the first line (header)
  if (!fgets(line, sizeof(line), fp)) {
    perror("fgets");
    fclose(fp);
    free(gateway);
    free(network_id);
    return -1;
  }

  while (fgets(line, sizeof(line), fp)) {
    if (sscanf(
          line, "%15s %lx %lx %*x %*d %*d %*d %lx", iface, &dest, &gw, &mask)
        != 4) {
      continue;
    }

    // Check if the line corresponds to the desired interface
    if (strcmp(iface, interface_name) == 0) {
      addr.s_addr = dest;
      strncpy(network_id, inet_ntoa(addr), INET_ADDRSTRLEN - 1);
      network_id[INET_ADDRSTRLEN - 1] = '\0'; // Ensure null-termination
      addr.s_addr                     = gw;
      strncpy(gateway, inet_ntoa(addr), INET_ADDRSTRLEN - 1);
      gateway[INET_ADDRSTRLEN - 1] = '\0'; // Ensure null-termination

      found = 1;
      break;
    }
  }

  fclose(fp);

  if (!found) {
    fprintf(stderr, "No route found for interface %s\n", interface_name);
    free(gateway);
    free(network_id);
    return -1;
  }

  return 0;
}

/*<--------------------------------------------------------------------------------------->*/

/* Function to get system values based upon interface name and keyword */
int get_system_value(const char *interface_name, const char *keyword)
{
  struct ifreq interface_info;
  int fd                           = 0;
  ip_address                       = malloc(INET_ADDRSTRLEN);
  netmask_address                  = malloc(INET_ADDRSTRLEN);
  struct sockaddr_in *sock_address = NULL;

  // Validate interface name length
  if (strlen(interface_name) >= IFNAMSIZ) {
    fprintf(stderr, "Error: Invalid device name\n");
    free(ip_address);
    free(netmask_address);
    return -1;
  }

  // Create a socket
  fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    fprintf(stderr, "Failed to create socket\n");
    free(ip_address);
    free(netmask_address);
    return -1;
  }

  // Copy interface name to ifreq structure
  snprintf(interface_info.ifr_name, IFNAMSIZ, "%s", interface_name);

  // Get configuration based on keyword
  if (strcmp(keyword, "IPV4") == 0) {
    if (get_ipv4_info(interface_info, fd, sock_address)) {
      RETURN_CALL(fd, ip_address, netmask_address);
      return -1;
    }

  } else if (strcmp(keyword, "MAC") == 0) {
    if ((get_mac_address(interface_info, fd))) {
      RETURN_CALL(fd, ip_address, netmask_address);
      return -1;
    }

  } else if (strcmp(keyword, "VLAN") == 0) {
    if (get_vlan_info(interface_name, fd)) {
      RETURN_CALL(fd, ip_address, netmask_address);
      return -1;
    }

  } else if (strcmp(keyword, "ROUTE") == 0) {
    if (get_network_id_and_gateway(interface_name, fd)) {
      RETURN_CALL(fd, ip_address, netmask_address);
      return -1;
    }

  } else {
    fprintf(stderr, "Invalid keyword \n");
    RETURN_CALL(fd, ip_address, netmask_address);
    return -1;
  }

  // print values when user option is 'g'
  if (print_flag == 1) {
    print_values(keyword);
  }

  RETURN_CALL(fd, ip_address, netmask_address)
  return 0;
}

/*<--------------------------------------------------------------------------------------->*/

/* Function will get system value of IPV4 using system calls */
int get_ipv4_info(struct ifreq interface_info,
                  int fd,
                  struct sockaddr_in *sock_address)
{
  // get IP address
  if (ioctl(fd, SIOCGIFADDR, &interface_info) < 0) {
    fprintf(
      stderr,
      "ioctl error / Invalid interface name / No specification present\n");
    return -1;
  }

  sock_address = (struct sockaddr_in *)&interface_info.ifr_addr;

  if (!inet_ntop(
        AF_INET, &sock_address->sin_addr, ip_address, INET_ADDRSTRLEN)) {
    fprintf(stderr, "Error: inet_ntop failed\n");
    return -1;
  }

  // Get the subnet-mask
  if (ioctl(fd, SIOCGIFNETMASK, &interface_info) < 0) {
    fprintf(stderr, "ioctl error/Invalid interface name\n");
    return -1;
  }
  sock_address = (struct sockaddr_in *)&interface_info.ifr_netmask;

  if (!inet_ntop(
        AF_INET, &sock_address->sin_addr, netmask_address, INET_ADDRSTRLEN)) {
    fprintf(stderr, "Error: inet_ntop failed\n");
    return -1;
  }

  return 0;
}

/*<--------------------------------------------------------------------------------------->*/

/* Function will get system value of MAC using system calls */
int get_mac_address(struct ifreq interface_info, int fd)
{
  // Get the MAC address
  if (ioctl(fd, SIOCGIFHWADDR, &interface_info) < 0) {
    fprintf(stderr, "ioctl error/Invalid interface name\n");
    return -1;
  }

  mac = interface_info.ifr_hwaddr.sa_data;
  return 0;
}

/*<--------------------------------------------------------------------------------------->*/

/* Function will get system value of VLAN using system calls */
int get_vlan_info(const char *interface_name, int fd)
{
  // Initialize the vlan_args structure
  memset(&vlan_args, 0, sizeof(struct vlan_ioctl_args));
  vlan_args.cmd = GET_VLAN_VID_CMD;
  strncpy(vlan_args.device1, interface_name, sizeof(vlan_args.device1) - 1);

  // Get the VLAN ID
  if (ioctl(fd, SIOCGIFVLAN, &vlan_args) < 0) {
    fprintf(stderr, "Failed to get VLAN information for %s\n", interface_name);
    return -1;
  }
  return 0;
}

/*<--------------------------------------------------------------------------------------->*/


/* Function will print the system values when user gives 'g' option */
void print_values(const char *keyword)
{
  if (strcmp(keyword, "IPV4") == 0) {
    printf("IP Address = %s\n", ip_address);
    printf("Subnet-mask = %s\n", netmask_address);
  }

  else if (strcmp(keyword, "MAC") == 0) {
    printf("MAC address = %02x:%02x:%02x:%02x:%02x:%02x\n",
           mac[0],
           mac[1],
           mac[2],
           mac[3],
           mac[4],
           mac[5]);
  }

  else if (strcmp(keyword, "VLAN") == 0) {
    printf("VLAN ID = %d\n", vlan_args.u.VID);
  }

  else if (strcmp(keyword, "ROUTE") == 0) {
    printf("Network Id is %s, Gateway Id is %s\n", network_id, gateway);
    free(gateway);
    free(network_id);
  }
}

/*<--------------------------------------------------------------------------------------->*/

/* Funtion will set user given value to the system setting */
int set_system_value(const char *interface_name,
                     const char *keyword,
                     const char *value)
{
  int fd = 0;

  // Validate interface name length
  if (strlen(interface_name) >= IFNAMSIZ) {
    fprintf(stderr, "Error: Invalid device name\n");
    return -1;
  }

  // Create a socket
  fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    fprintf(stderr, "Failed to create socket\n");
    return -1;
  }

  // Set configuration based on keyword
  if (strcmp(keyword, "IPV4") == 0) {
    if (set_ipv4_address(fd, interface_name, value) < 0) {
      close(fd);
      return -1;
    }
  } else if (strcmp(keyword, "MAC") == 0) {
    if (set_mac_address(fd, interface_name, value) < 0) {
      close(fd);
      return -1;
    }

  } else if (strcmp(keyword, "VLAN") == 0) {
    if (set_vlan_id(fd, interface_name, value) < 0) {
      close(fd);
      return -1;
    }

  } else if (strcmp(keyword, "ROUTE") == 0) {
    if (set_gateway(interface_name, fd, value) < 0) {
      close(fd);
      return -1;
    }

  } else {
    fprintf(stderr, "Invalid keyword\n");
    close(fd);
    return -1;
  }

  close(fd);
  return 0;
}

/*<--------------------------------------------------------------------------------------->*/

/* Function to set IPv4 address */
int set_ipv4_address(int fd, const char *interface_name, const char *value)
{
  struct ifreq interface_info;
  struct sockaddr_in addr;

  // Copy interface name to ifreq structure
  snprintf(interface_info.ifr_name, IFNAMSIZ, "%s", interface_name);
  addr.sin_family = AF_INET;

  if (inet_pton(AF_INET, value, &addr.sin_addr) <= 0) {
    fprintf(
      stderr, "Invalid IP address format %s for %s\n", value, interface_name);
    return -1;
  }
  memcpy(&interface_info.ifr_addr, &addr, sizeof(struct sockaddr_in));
  if (ioctl(fd, SIOCSIFADDR, &interface_info) < 0) {
    perror("ioctl SIOCSIFADDR");
    return -1;
  }
  return 0;
}

/*<--------------------------------------------------------------------------------------->*/

/* Function to set MAC address */
int set_mac_address(int fd, const char *interface_name, const char *value)
{
  struct ifreq interface_info;
  unsigned char mac[25];

  // Copy interface name to ifreq structure
  snprintf(interface_info.ifr_name, IFNAMSIZ, "%s", interface_name);
  if (sscanf(value,
             "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
             &mac[0],
             &mac[1],
             &mac[2],
             &mac[3],
             &mac[4],
             &mac[5])
      != 6) {
    fprintf(
      stderr, "Invalid MAC address format %s for %s\n", value, interface_name);
    return -1;
  }

  memcpy(interface_info.ifr_hwaddr.sa_data, mac, 6);
  interface_info.ifr_hwaddr.sa_family = ARPHRD_ETHER;

  if (ioctl(fd, SIOCSIFHWADDR, &interface_info) < 0) {
    perror("ioctl SIOCSIFHWADDR");
    return -1;
  }
  return 0;
}

/*<--------------------------------------------------------------------------------------->*/

/* Function to set VLAN ID */
int set_vlan_id(int fd, const char *interface_name, const char *value)
{
  struct vlan_ioctl_args vlan_args;

  // Initialize the vlan_args structure
  memset(&vlan_args, 0, sizeof(struct vlan_ioctl_args));
  vlan_args.cmd = ADD_VLAN_CMD; // Command to add VLAN
  strncpy(vlan_args.device1, interface_name, sizeof(vlan_args.device1) - 1);

  // Convert the value to VLAN ID
  int vlan_id = atoi(value);
  if (vlan_id <= 0 || vlan_id > 4094) { // VLAN ID must be between 1 and 4094
    fprintf(stderr, "Invalid VLAN ID\n");
    return -1;
  }
  vlan_args.u.VID = vlan_id;

  // Set the VLAN ID
  if (ioctl(fd, SIOCSIFVLAN, &vlan_args) < 0) {
    perror("ioctl SIOCSIFVLAN");
    return -1;
  }

  return 0;
}

/*<--------------------------------------------------------------------------------------->*/

int set_gateway(const char *interface_name, int fd, const char *gateway)
{
  int sockfd;
  struct rtentry route;
  struct sockaddr_in *addr;
  int err = 0;

  // create the socket
  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket");
    return -1;
  }

  memset(&route, 0, sizeof(route));

  // Set up the gateway address
  addr                  = (struct sockaddr_in *)&route.rt_gateway;
  addr->sin_family      = AF_INET;
  addr->sin_addr.s_addr = inet_addr(gateway);

  // Set up the destination address (network)
  addr                  = (struct sockaddr_in *)&route.rt_dst;
  addr->sin_family      = AF_INET;
  addr->sin_addr.s_addr = inet_addr(RTDST);

  // Set up the subnet mask
  addr                  = (struct sockaddr_in *)&route.rt_genmask;
  addr->sin_family      = AF_INET;
  addr->sin_addr.s_addr = inet_addr(RTGENMASK);

  route.rt_dev    = (char *)interface_name;
  route.rt_flags  = RTF_UP | RTF_GATEWAY;
  route.rt_metric = 0;

  if ((err = ioctl(sockfd, SIOCADDRT, &route)) != 0) {
    perror("SIOCADDRT failed");
    close(sockfd);
    return -1;
  }

  close(sockfd);
  return 0;
}

/*<--------------------------------------------------------------------------------------->*/
