#include <fstream>
#include <iostream>

#include "utils.h"

int main(int argc, char* argv[])
{
  std::vector<int> conts_ids = get_all_contlist();

  for (int id : conts_ids)
  {
    std::cout << id << std::endl;
  }

  return 0;
}
