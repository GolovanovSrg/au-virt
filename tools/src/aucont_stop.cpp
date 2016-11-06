#include <iostream>
#include <cstdlib>
#include <csignal>
#include <cerrno>

#include "utils.h"

int main(int argc, char* argv[])
{
  if (argc < 2 || argc > 3)
  {
    std::cout << "Invalid parameters number" << std::endl;
    exit(1);
  }

  int id = atoi(argv[1]);
  if (find_in_contlist(id))
  {
    int signal = (argc == 3 ? atoi(argv[2]) : SIGTERM);
    if (kill(id, signal) < 0 && errno != ESRCH)
    {
      std::cout << "Can not send signal" << std::endl;
      exit(1);
    }

    del_from_contlist(id);
  }
  else
  {
    std::cout << "Can not find container id" << std::endl;
  }

  return 0;
}
