#include "karma_add.h"

#pragma hls_top
unsigned short karma_add(unsigned short a, unsigned short b) {
  return a + b;

  // Normally this statement shouldn't be reached. If it was reached, it means
  // there was an issue.
  return -2;
}
