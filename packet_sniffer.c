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

struct options {
  char* interface;
  char* filename;
  char* protocol;
  int duration;
} typedef options_t;

int main(int argc, char* argv[]) {
  // Define default options
  options_t options;
  options.interface = NULL;
  options.filename = NULL;
  options.protocol = NULL;
  options.duration = -1;

  // Parse command-line arguments
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
      options.interface = argv[++i];
    } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
      options.filename = argv[++i];
    } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
      options.protocol = argv[++i];
    } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
      options.duration = atoi(argv[++i]);
    } else if (strcmp(argv[i], "-h") == 0) {
      printf(usage, argv[0]);
      return 0;
    } else {
      printf("Unknown option: %s\n", argv[i]);
      printf(usage, argv[0]);
      return 1;
    }
  }

  if (options.interface == NULL) {
    printf("Error: Interface is required.\n");
    printf(usage, argv[0]);
    return 1;
  }

  printf("Sniffing on interface: %s\n", options.interface);
  printf("Output file: %s\n", options.filename ? options.filename : "stdout");
  printf("Protocol filter: %s\n", options.protocol ? options.protocol : "any");
  printf("Duration: %d\n", options.duration);

  return 0;
}