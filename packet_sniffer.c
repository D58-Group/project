#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* usage =
    "Usage:"
    " %s -i <interface> [-o <filename>] [-p <protocol>] [-t <duration>] [-h]\n"
    "  -i <interface>    Interface to sniff on\n"
    "  -o <filename>     File to save captured packets (default=stdout)\n"
    "  -p <protocol>     Protocol to filter (default=any)\n"
    "  -t <duration>     Duration to sniff in seconds (default=unlimited)\n"
    "  -h                View usage information\n";

int main(int argc, char* argv[]) {
  char* interface = NULL;
  char* filename = NULL;
  char* protocol = NULL;
  int duration = -1;

  // parse command-line arguments
  for (int i = 1; i < argc; i++) {
    // usage
    if (strcmp(argv[i], "-h") == 0) {
      printf(usage, argv[0]);
      return 0;
    }

    // flags
    if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
      interface = argv[++i];
    } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
      filename = argv[++i];
    } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
      protocol = argv[++i];
    } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
      duration = atoi(argv[++i]);
    } else {
      printf("Unknown argument: %s\n", argv[i]);
      printf(usage, argv[0]);
      return 1;
    }
  }

  if (interface == NULL) {
    printf("Interface is required.\n");
    return 1;
  }

  printf("interface: %s\n", interface);
  printf("protocol: %s\n", protocol ? protocol : "any");
  printf("output file: %s\n", filename ? filename : "stdout");
  printf("duration: %d seconds\n", duration);
}