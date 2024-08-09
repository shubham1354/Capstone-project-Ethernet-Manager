#ifndef CONFIG_H
#define CONFIG_H

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <arpa/inet.h>


#define CHECK_NODE_CREATION(ptr) \
  if (!(ptr))                    \
  return -1
#define LINE_LENGTH 1024
#define MAX         1024


struct ipv4_config {
  char ipv4_address[MAX];
  char subnet_mask[MAX];
};

struct mac_config {
  char mac_address[MAX];
};

struct vlan_config {
  int vlan_id;
};

struct route_config {
  char route_network[MAX];
  char route_gateway[MAX];
};

struct confignode {
  char interface_name[MAX];
  struct ipv4_config ipv4;
  struct mac_config mac;
  struct vlan_config vlan;
  struct route_config route;
  struct confignode *next;
};


int load_configuration(char **, const char *);
struct confignode *get_node(const char *);
int validate_configuration(int);
int validate_duplicate(void);
int has_same_first_7_digits(const char *, const char *);
int validate_ip(const char *);
int validate_vlan_id(const int);
int validate_mac(const char *);
struct confignode *search_interface(const char *);
int set_configuration(const char *, const char *, char *);
int validate_commandline_arguments(int, char **);
int is_sync_with_system(void);
int update_config_file(const char *);
void free_config_nodes(void);

#endif
