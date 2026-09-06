#define _FILE_OFFSET_BITS 64

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define CHUNK_SIZE (64 * 1024)

static int scan_range(int fd, unsigned long long start, unsigned long long end,
                      char **markers, int marker_count,
                      unsigned long long *counts) {
  size_t longest = 1;
  for (int i = 0; i < marker_count; i++) {
    size_t length = strlen(markers[i]);
    if (length > longest)
      longest = length;
  }

  unsigned char *buffer = malloc(CHUNK_SIZE + longest);
  if (buffer == NULL)
    return -1;

  size_t carried = 0;
  unsigned long long cursor = start;
  while (cursor < end) {
    size_t wanted = CHUNK_SIZE;
    if (end - cursor < wanted)
      wanted = (size_t)(end - cursor);

    ssize_t received;
    do {
      received = pread(fd, buffer + carried, wanted, (off_t)cursor);
    } while (received < 0 && errno == EINTR);
    if (received <= 0) {
      free(buffer);
      return -1;
    }

    size_t available = carried + (size_t)received;
    for (int marker_index = 0; marker_index < marker_count; marker_index++) {
      size_t marker_length = strlen(markers[marker_index]);
      for (size_t offset = 0; offset + marker_length <= available; offset++) {
        if (offset + marker_length <= carried)
          continue;
        if (memcmp(buffer + offset, markers[marker_index], marker_length) == 0)
          counts[marker_index]++;
      }
    }

    size_t overlap = longest - 1;
    carried = available < overlap ? available : overlap;
    memmove(buffer, buffer + available - carried, carried);
    cursor += (unsigned long long)received;
  }

  free(buffer);
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 4) {
    fprintf(stderr, "usage: proc-memory-scanner PID MAPPING_NEEDLE MARKER...\n");
    return 2;
  }

  char *pid_end = NULL;
  long pid = strtol(argv[1], &pid_end, 10);
  if (pid <= 0 || pid_end == NULL || *pid_end != '\0') {
    fprintf(stderr, "invalid pid: %s\n", argv[1]);
    return 2;
  }

  char maps_path[64];
  char mem_path[64];
  snprintf(maps_path, sizeof(maps_path), "/proc/%ld/maps", pid);
  snprintf(mem_path, sizeof(mem_path), "/proc/%ld/mem", pid);

  FILE *maps = fopen(maps_path, "r");
  if (maps == NULL) {
    perror("open maps");
    return 1;
  }
  int mem = open(mem_path, O_RDONLY | O_CLOEXEC);
  if (mem < 0) {
    perror("open mem");
    fclose(maps);
    return 1;
  }

  int marker_count = argc - 3;
  unsigned long long *counts = calloc((size_t)marker_count, sizeof(*counts));
  if (counts == NULL) {
    fprintf(stderr, "unable to allocate marker counters\n");
    close(mem);
    fclose(maps);
    return 1;
  }

  unsigned long long ranges = 0;
  unsigned long long executable = 0;
  char *line = NULL;
  size_t line_capacity = 0;
  int status = 0;
  while (getline(&line, &line_capacity, maps) >= 0) {
    unsigned long long start;
    unsigned long long end;
    char permissions[5] = {0};
    char path[4096] = {0};
    int fields = sscanf(line, "%llx-%llx %4s %*s %*s %*s %4095[^\n]", &start,
                        &end, permissions, path);
    if (fields != 4 || permissions[0] != 'r' ||
        strstr(path, argv[2]) == NULL)
      continue;

    ranges++;
    if (permissions[2] == 'x')
      executable++;
    if (scan_range(mem, start, end, argv + 3, marker_count, counts) != 0) {
      fprintf(stderr, "unable to scan %llx-%llx: %s\n", start, end,
              strerror(errno));
      status = 1;
      break;
    }
  }

  if (ferror(maps)) {
    perror("read maps");
    status = 1;
  }
  if (status == 0) {
    printf("ranges=%llu\n", ranges);
    printf("executable=%llu\n", executable);
    for (int i = 0; i < marker_count; i++)
      printf("marker=%s count=%llu\n", argv[i + 3], counts[i]);
  }

  free(line);
  free(counts);
  close(mem);
  fclose(maps);
  return status;
}
