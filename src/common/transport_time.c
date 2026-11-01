#include "transport_internal.h"
#include <time.h>
uint64_t transport_get_time_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}
uint64_t transport_get_monotonic_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}
int64_t transport_get_time_ms(void) {
  return (int64_t)(transport_get_monotonic_ns() / 1000000U);
}
