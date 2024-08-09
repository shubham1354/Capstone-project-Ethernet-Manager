#include "config.h"
#include "uil.h"
#include "pal.h"


/*<--------------------------------------------------------------------------------------->*/

/******* M A I N  F U N C T I O N *******/
int main(int argc, char **argv)
{
  if ((validate_commandline_arguments(argc, argv))) {
    return EXIT_FAILURE;
  }

  // calling function to process configuration file and create database
  if ((load_configuration(argv, "/home/shubhamp/capston/test_files/test6"))) {
    free_config_nodes();
    return EXIT_FAILURE;
  }

  // call for uil layer to check user demand
  if (user_demand_to_config(argv, "/home/shubhamp/capston/test_files/test6")) {
    free_config_nodes();
    return EXIT_FAILURE;
  }

  free_config_nodes();
  return EXIT_SUCCESS;
}

/*<--------------------------------------------------------------------------------------->*/

/* Function will validate the command line arguments */
int validate_commandline_arguments(int argc, char **argv)
{
  if (argc < 2) {
    fprintf(stderr, "Usage: ./a.out < g / s > eth0 IPV4\n");
    return -1;
  }

  if (*argv[1] == 's') {
    if (argc != 5) {
      fprintf(stderr, "Usage: ./a.out s eth0 IPV4 11.22.33.44\n");
      return -1;
    }
  }

  else if (*argv[1] == 'g') {
    if (argc != 4) {
      fprintf(stderr, "Usage: ./a.out g eth0 IPV4\n");
      return -1;
    }
  }

  else {
    fprintf(stderr, "Usage: ./a.out < g / s > eth0 IPV4\n");
    return -1;
  }
  return 0;
}

/*<--------------------------------------------------------------------------------------->*/
