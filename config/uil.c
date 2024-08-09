#include "config.h"
#include "uil.h"
#include "pal.h"

char print_flag;
extern struct confignode *head;

/*<--------------------------------------------------------------------------------------->*/

/* Function will check for the user demand and process the same */
int user_demand_to_config(char **argv, char *file_path)
{
  // if user want to get the data
  if (*argv[1] == 'g') {
    print_flag = 1;
    if (get_system_value(argv[2], argv[3])) {
      return -1;
    }
    print_flag = 0;

    return 0;

    // if user wants to set the data
  } else if (*argv[1] == 's') {
    // before updating check given value is not duplicate with the other interface values
    if (validate_value_duplicate(argv[3], argv[4])) {
      fprintf(stderr, "Given value %s is duplicate\n", argv[4]);
      return -1;
    }

    if (set_system_value(argv[2], argv[3], argv[4])) {
      return -1;
    }


    // update the database in linked list
    if (set_configuration(argv[2], argv[3], argv[4])) {
      return -1;
    }

    // update the configuration file
    if (update_config_file(file_path)) {
      return -1;
    }

    printf("%s is set successfully to %s\n", argv[3], argv[4]);
    return 0;
  }
  return 0;
}

/*<--------------------------------------------------------------------------------------->*/

/* Function will check user given data for duplicate  */
int validate_value_duplicate(const char *keyword, char *value)
{
  struct confignode *current = head;

  while (current != NULL) {
    if (strcmp(keyword, "IPV4") == 0) {
      if ((strcmp(current->ipv4.ipv4_address, value) == 0)) {
        return -1; // Duplicate IPV4 found
      }
    } else if (strcmp(keyword, "MAC") == 0) {
      if (strcmp(current->mac.mac_address, value) == 0) {
        return -1; // Duplicate MAC found
      }
    } else if (strcmp(keyword, "VLAN") == 0) {
      if (current->vlan.vlan_id == atoi(value)) {
        return -1; // Duplicate VLAN found
      }
    } else if (strcmp(keyword, "ROUTE") == 0) {
      if (strcmp(current->route.route_network, value) == 0) {
        return -1; // Duplicate ROUTE found
      }
    }
    current = current->next;
  }
  return 0; // No duplicate found
}

/*<--------------------------------------------------------------------------------------->*/
