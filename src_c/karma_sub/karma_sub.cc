#include "karma_sub.h"

#pragma hls_top
int karma_sub(int a, int b) {
  return a - b;

  // Normally this statement shouldn't be reached. If it was reached, it means
  // there was an issue.
  return -2;
}
