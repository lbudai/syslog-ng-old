#include "path_getmaxlen.h"
#include <limits.h>
#include <unistd.h>

#ifdef PATH_MAX
static const size_t max_len = PATH_MAX;
#else
#define PATH_MAX 1024
static const size_t max_len = 0;
#endif

size_t path_get_max_len()
{
  size_t len = max_len;

  if (len != 0)
    return len;

  if ((len = pathconf("/", _PC_PATH_MAX)) < 0)
    len = PATH_MAX;

  return len;
}
