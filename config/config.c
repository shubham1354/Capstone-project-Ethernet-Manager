#include "config.h"
#include "pal.h"

struct confignode *head = NULL;

extern char *mac;
extern char *ip_address;
extern char *netmask_address;
extern char *network_id;
extern char *gateway;
extern struct vlan_ioctl_args vlan_args;

/*<--------------------------------------------------------------------------------------->*/

/* Function to check config file info is in sync with system values */
int is_sync_with_system(void)
{
  struct confignode *current = head;

  while (current != NULL) {
    // get system value for IPV4 and compare it with config file
    if (strlen(current->ipv4.ipv4_address) > 0) {
      if (get_system_value(current->interface_name, "IPV4") == 0) {
        if (strcmp(ip_address, current->ipv4.ipv4_address) != 0) {
          // if not sync --> update system values
          if (set_system_value(
                current->interface_name, "IPV4", current->ipv4.ipv4_address)
              != 0) {
            fprintf(stderr,
                    "Failed to set IPV4 for %s in synchronisation\n",
                    current->interface_name);
            return -1;
          }
        }
      } else {
        fprintf(stderr, "Sync failed\n");
        return -1;
      }
    }

    // get system value for MAC and compare it with config file
    if (strlen(current->mac.mac_address) > 0) {
      if (get_system_value(current->interface_name, "MAC") == 0) {
        if (strcmp(mac, current->mac.mac_address) != 0) {
          // if not sync --> update system values
          if (set_system_value(
                current->interface_name, "MAC", current->mac.mac_address)
              != 0) {
            printf("*%s\n", current->mac.mac_address);

            fprintf(stderr,
                    "Failed to set MAC %s for %s in synchronisation\n",
                    current->mac.mac_address,
                    current->interface_name);
            return -1;
          }
        }
      } else {
        fprintf(stderr, "Sync failed\n");
        return -1;
      }
    }
    // Check synchronization of VLAN ID
    if (current->vlan.vlan_id != 0) {
      char buffer[MAX];
      snprintf(buffer, MAX, "%d", current->vlan.vlan_id);

      if (get_system_value(current->interface_name, "VLAN") == 0) {
        // Check if VLAN ID is already set in the system
        char system_vlan[MAX];
        if (get_system_value(current->interface_name, "VLAN") == 0) {
          snprintf(system_vlan, MAX, "%d", vlan_args.u.VID);
          if (strcmp(buffer, system_vlan) != 0) {
            // if not sync --> update system values
            if (set_system_value(current->interface_name, "VLAN", buffer)
                != 0) {
              fprintf(stderr,
                      "Failed to set VLAN for %s in synchronisation\n",
                      current->interface_name);
              return -1;
            }
          }
        } else {
          fprintf(stderr, "Failed to retrieve system VLAN ID\n");
          return -1;
        }
      } else {
        fprintf(stderr, "Sync failed\n");
        return -1;
      }
    }


    // get system value for ROUTE and compare it with config file
    if (strlen(current->route.route_gateway) > 0) {
      if (get_system_value(current->interface_name, "ROUTE") == 0) {
        if (strcmp(gateway, current->route.route_gateway) != 0) {
          // if not sync --> update system values
          if (set_system_value(
                current->interface_name, "ROUTE", current->route.route_gateway)
              != 0) {
            fprintf(stderr,
                    "Failed to set ROUTE for %s in synchronisation\n",
                    current->interface_name);
            return -1;
          }
        }
      } else {
        fprintf(stderr, "Sync failed\n");
        return -1;
      }
    }
    current = current->next;
  }

  return 0;
}

/*<--------------------------------------------------------------------------------------->*/

/* Function will update the config file after updating the system values */
int update_config_file(const char *file_path)
{
  FILE *file = fopen(file_path, "w");
  if (file == NULL) {
    perror("Error opening file");
    return -1;
  }

  struct confignode *current = head;
  while (current != NULL) {
    if (strlen(current->ipv4.ipv4_address) > 1
        && strlen(current->ipv4.subnet_mask) > 1) {
      fprintf(file,
              "IPV4 = \"%s\", \"%s\", \"%s\"\n",
              current->interface_name,
              current->ipv4.ipv4_address,
              current->ipv4.subnet_mask);
    }
    if (strlen(current->mac.mac_address) > 1) {
      fprintf(file,
              "MAC = \"%s\", \"%s\"\n",
              current->interface_name,
              current->mac.mac_address);
    }
    if (current->vlan.vlan_id != 0) {
      fprintf(file,
              "VLAN = \"%s\", %d\n",
              current->interface_name,
              current->vlan.vlan_id);
    }
    if (strlen(current->route.route_network) > 1
        && strlen(current->route.route_gateway) > 1) {
      fprintf(file,
              "ROUTE = \"%s\", \"%s\", \"%s\"\n",
              current->interface_name,
              current->route.route_network,
              current->route.route_gateway);
    }

    current = current->next;
  }

  fclose(file);
  return 0;
}

/*<--------------------------------------------------------------------------------------->*/

/* Function will Creat database by reading a config file and call for the validate */
int load_configuration(char **argv, const char *filename)
{
  char line[LINE_LENGTH];
  char interface_name[MAX];
  char value1[MAX];
  char value2[MAX];
  int value3     = 0;
  int line_count = 0;

  FILE *fp = fopen(filename, "r");
  if (!fp) {
    perror("Failed to open configuration file");
    return -1;
  }

  // getting data from the config_file to create node and validate data
  while (fgets(line, sizeof(line), fp)) {
    // skip blank line
    if (strlen(line) < 2) {
      continue;
    } else {
      line_count++;
    }

    // extract the keywords from the line and process
    if (sscanf(line,
               "IPV4 = \"%[^\"]\", \"%[^\"]\", \"%[^\"]\"",
               interface_name,
               value1,
               value2)
        == 3) {
      struct confignode *new = get_node(interface_name);
      CHECK_NODE_CREATION(new);

      snprintf(new->interface_name,
               (strlen(interface_name) + 1),
               "%s",
               interface_name);
      snprintf(new->ipv4.ipv4_address, (strlen(value1) + 1), "%s", value1);
      snprintf(new->ipv4.subnet_mask, (strlen(value2) + 1), "%s", value2);


    } else if (sscanf(
                 line, "MAC = \"%[^\"]\", \"%[^\"]\"", interface_name, value1)
               == 2) {
      struct confignode *new = get_node(interface_name);
      CHECK_NODE_CREATION(new);

      snprintf(new->interface_name,
               (strlen(interface_name) + 1),
               "%s",
               interface_name);
      snprintf(new->mac.mac_address, (strlen(value1) + 1), "%s", value1);

    } else if (sscanf(line, "VLAN = \"%[^\"]\", %d", interface_name, &value3)
               == 2) {
      struct confignode *new = get_node(interface_name);
      CHECK_NODE_CREATION(new);


      snprintf(new->interface_name,
               (strlen(interface_name) + 1),
               "%s",
               interface_name);
      new->vlan.vlan_id = value3;

    } else if (sscanf(line,
                      "ROUTE = \"%[^\"]\", \"%[^\"]\", \"%[^\"]\"",
                      interface_name,
                      value1,
                      value2)
               == 3) {
      struct confignode *new = get_node(interface_name);
      CHECK_NODE_CREATION(new);

      snprintf(new->interface_name,
               (strlen(interface_name) + 1),
               "%s",
               interface_name);
      snprintf(new->route.route_network, (strlen(value1) + 1), "%s", value1);
      snprintf(new->route.route_gateway, (strlen(value2) + 1), "%s", value2);

    } else {
      fprintf(stderr, "Invalid configuration line: %s", line);
      fclose(fp);
      return -1;
    }
  }

  fclose(fp);

  // Call for a function to validate the specifications
  if (validate_configuration(line_count)) {
    return -1;
  }

  //	print_nodes();

  // call for a fucntion check config file sync with system values
  if (is_sync_with_system()) {
    return -1;
  } else {
    printf("Sync successfull\n");
  }

  return 0;
}

/*<--------------------------------------------------------------------------------------->*/

/* Function will give node address to load the specifications */
struct confignode *get_node(const char *interface_name)
{
  struct confignode *current = head;
  struct confignode *last    = NULL;

  while (current != NULL) {
    // return address of node if previously interface name is present
    if (strcmp(current->interface_name, interface_name) == 0) {
      return current;
    }
    last    = current;
    current = current->next;
  }

  // create new node if no node present with given interface name
  struct confignode *new_node = calloc(1, sizeof(struct confignode));
  if (!new_node) {
    fprintf(stderr, "Malloc failed\n");
    return NULL;
  }
  memset(new_node, 0, sizeof(struct confignode));
  new_node->next = NULL;

  // if this is the first node
  if (last == NULL) {
    head = new_node;
  } else {
    last->next = new_node;
  }

  return new_node;
}

/*<--------------------------------------------------------------------------------------->*/

/* function to validate the duplicate and will call to functions which will validate the specifications */
int validate_configuration(int line_count)
{
  struct confignode *current = NULL;

  // checking for empty file
  if (line_count == 0) {
    printf("Given Configuration file is empty\n");
    return -1;
  }

  // duplicate specification in config file checking
  if (validate_duplicate()) {
    return -1;
  }

  for (current = head; current != NULL; current = current->next) {
    // check for --> first 7 digits of gateway and network specifications of Route should be same
    if (has_same_first_7_digits(current->route.route_network,
                                current->route.route_gateway)
        && strlen(current->route.route_network) > 0) {
      return -1;
    }

    // check for --> valid VLAN ID
    if (validate_vlan_id(current->vlan.vlan_id)) {
      return -1;
    }

    // check for --> valid IPV4 Address
    if (validate_ip(current->ipv4.ipv4_address)) {
      return -1;
    }

    // check for --> valid Mac address
    if (validate_mac(current->mac.mac_address)) {
      return -1;
    }
  }
  return 0;
}

/*<--------------------------------------------------------------------------------------->*/

int validate_duplicate()
{
  struct confignode *current = head;
  struct confignode *compare;

  while (current != NULL) {
    // Check for duplicate IPV4
    for (compare = current->next; compare != NULL; compare = compare->next) {
      if (strlen(current->ipv4.ipv4_address) > 0
          && strlen(compare->ipv4.ipv4_address) > 0) {
        if (strcmp(current->ipv4.ipv4_address, compare->ipv4.ipv4_address)
            == 0) {
          fprintf(stderr,
                  "Duplicate IPV4 address found: %s\n",
                  current->ipv4.ipv4_address);
          return -1;
        }
      }
      // Check for duplicate MAC
      if (strlen(current->mac.mac_address) > 0
          && strlen(compare->mac.mac_address) > 0) {
        if (strcmp(current->mac.mac_address, compare->mac.mac_address) == 0) {
          fprintf(stderr,
                  "Duplicate MAC address found: %s\n",
                  current->mac.mac_address);
          return -1;
        }
      }
      // Check for duplicate VLAN
      char buffer1[20]; // Large enough to hold all possible int values
      char buffer2[20];
      // Convert integer to string
      sprintf(buffer1, "%d", compare->vlan.vlan_id);
      sprintf(buffer2, "%d", current->vlan.vlan_id);


      if (strlen(buffer1) > 1 && strlen(buffer2) > 1) {
        if (current->vlan.vlan_id == compare->vlan.vlan_id) {
          fprintf(
            stderr, "Duplicate VLAN ID found: %d\n", current->vlan.vlan_id);
          return -1;
        }
      }

      // Check for duplicate ROUTE
      if (strlen(current->route.route_network) > 0
          && strlen(compare->route.route_network) > 0) {
        if (strcmp(current->route.route_network, compare->route.route_network)
            == 0) {
          fprintf(stderr,
                  "Duplicate ROUTE found: %s\n",
                  current->route.route_network);
          return -1;
        }
      }
    }
    current = current->next;
  }
  return 0; // No duplicates found
}

/*<--------------------------------------------------------------------------------------->*/

/* function will check first 7 digits of network and gateway of Route are same or not  */
int has_same_first_7_digits(const char *network, const char *gateway)
{
  if ((strncmp(network, gateway, 9) != 0)) {
    fprintf(stderr,
            "Gateway address %s does not match network address %s in the first "
            "7 digits\n",
            gateway,
            network);
    return -1;
  }
  return 0;
}

/*<--------------------------------------------------------------------------------------->*/

/* Function to validate IP Adrress*/
int validate_ip(const char *ip)
{
  // if no ip is present for the interface name
  if (*ip == 0) {
    return 0;
  }

  int num       = 0;
  int dots      = 0;
  char *ptr     = NULL;
  char *temp_ip = strdup(ip);

  // cut the string using dot delimiter
  ptr = strtok(temp_ip, ".");
  if (ptr == NULL) {
    free(temp_ip);
    fprintf(stderr, "Invalid ip %s\n", ip);
    return -1;
  }

  while (ptr) {
    char *endptr;
    errno = 0;

    // convert substring to number using strtol
    num = strtol(ptr, &endptr, 10);

    // check if the conversion was successful
    if (errno != 0 || *endptr != '\0' || num < 0 || num > 255) {
      free(temp_ip);
      fprintf(stderr, "Invalid ip %s\n", ip);
      return -1;
    }

    // cut the next part of the string
    ptr = strtok(NULL, ".");
    if (ptr != NULL) {
      dots++; // increase the dot count
    }
  }

  // if the number of dots is not 3, return false
  if (dots != 3) {
    free(temp_ip);
    fprintf(stderr, "Invalid ip %s\n", ip);
    return -1;
  }

  free(temp_ip);
  return 0;
}

/*<--------------------------------------------------------------------------------------->*/

/* Function will validate vlan id */
int validate_vlan_id(const int vlan_id)
{
  // if vlan id not present for given interface name
  if (vlan_id == 0) {
    return 0;
  }

  if (vlan_id >= 1 && vlan_id <= 4094) {
    return 0; // Valid VLAN ID
  } else {
    fprintf(stderr, "Invalid VLAN ID %d\n", vlan_id);
    return -1; // Invalid VLAN ID
  }
}

/*<--------------------------------------------------------------------------------------->*/

/* Function will check for valid Mac Address */
int validate_mac(const char *mac_address)
{
  // if no MAC present for the interface
  if (*mac_address == 0) {
    return 0;
  }

  int len = strlen(mac_address);
  int i   = 0;

  // Check for format XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
  if (len == 17) {
    for (i = 0; i < 17; i++) {
      if (i % 3 == 2) {
        if (mac_address[i] != ':' && mac_address[i] != '-') {
          fprintf(stderr, "Invalid MAC Address %s\n", mac_address);
          return -1;
        }
      } else {
        if (!isxdigit(mac_address[i])) {
          fprintf(stderr, "Invalid MAC Address %s\n", mac_address);
          return -1;
        }
      }
    }
    return 0;

  } else {
    fprintf(stderr, "Invalid MAC Address %s\n", mac_address);
    return -1;
  }

  return 0;
}

/*<--------------------------------------------------------------------------------------->*/

/* Function will search for a given interface name */
struct confignode *search_interface(const char *interfacename)
{
  struct confignode *current = head;
  while (current != NULL) {
    if (strcmp(current->interface_name, interfacename) == 0) {
      return current;
    }
    current = current->next;
  }
  return NULL;
}

/*<--------------------------------------------------------------------------------------->*/

/* Function will update linked list */
int set_configuration(const char *interface_name,
                      const char *keyword,
                      char *value)
{
  struct confignode *node = search_interface(interface_name);
  if (!node) {
    fprintf(stderr, "Interface %s not found\n", interface_name);
    return -1;
  }

  if (strcmp(keyword, "IPV4") == 0) {
    snprintf(
      node->ipv4.ipv4_address, sizeof(node->ipv4.ipv4_address), "%s", value);
  } else if (strcmp(keyword, "MAC") == 0) {
    snprintf(node->mac.mac_address, sizeof(node->mac.mac_address), "%s", value);
  } else if (strcmp(keyword, "VLAN") == 0) {
    node->vlan.vlan_id = atoi(value);
  } else if (strcmp(keyword, "ROUTE") == 0) {
    snprintf(node->route.route_network,
             sizeof(node->route.route_network),
             "%s",
             value);
  } else {
    fprintf(stderr, "Unknown keyword %s\n", keyword);
    return -1;
  }

  return 0;
}

/*<--------------------------------------------------------------------------------------->*/

void free_config_nodes()
{
  struct confignode *current = head;
  struct confignode *next;

  while (current != NULL) {
    next = current->next; // Save the next node
    free(current);        // Free the current node
    current = next;       // Move to the next node
  }

  head = NULL; // Ensure the head pointer is set to NULL after freeing all nodes
}

/*<--------------------------------------------------------------------------------------->*/
