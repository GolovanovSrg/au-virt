#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <cstdio>
#include <fcntl.h>

#include "utils.h"

namespace
{

void set_namespace(std::string pid, std::string ns_name)
{
  std::string ns_path = "/proc/" + pid + "/ns/" + ns_name;
  int d = open(ns_path.c_str(), O_RDONLY);
  if (d < 0)
  {
    std::cout << "Can not open namespace descriptor for " + ns_name << std::endl;
    exit(1);
  }

  if (setns(d, 0) < 0)
  {
    std::cout << "Can not set namespace " + ns_name << std::endl;
    close(d);
    exit(1);
  }

  close(d);
}

} // anonymous namespace

int main(int argc, char* argv[])
{
  if (argc < 2)
  {
    std::cout << "Invalid parameters number" << std::endl;
    exit(1);
  }

  std::vector<char*> args;
  int i = 1;
  int id = atoi(argv[i++]);
  while (i < argc)
  {
    args.push_back(argv[i++]);
  }
  args.push_back(nullptr);

  if (!find_in_contlist(id))
  {
    std::cout << "Can not find container id" << std::endl;
    exit(1);
  }

  std::string id_str = std::to_string(id);

  set_namespace(id_str, "user");
  set_namespace(id_str, "pid");
  set_namespace(id_str, "ipc");
  set_namespace(id_str, "net");
  set_namespace(id_str, "uts");
  set_namespace(id_str, "mnt");

  if (execvp(args[0], args.data()) < 0)
  {
    std::cout << "Can not run command in container" << std::endl;
    exit(1);
  }

  return 0;
}
