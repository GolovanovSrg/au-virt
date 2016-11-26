#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <cstdio>
#include <fcntl.h>
#include <sys/wait.h>
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

void set_cpu_cgroup(const std::string& pid)
{
  std::string cpu_cgroup_dir = CGROUPS_DIR + "/cpu";
  std::string mount_cgroups_cmd = "sudo mount -t cgroup -o cpu none " + cpu_cgroup_dir;
std::string unmount_cgroups_cmd = "sudo umount " + cpu_cgroup_dir;

  if (system(mount_cgroups_cmd.c_str()) < 0)
  {
    std::cout << "Can not mount cpu cgroup";
    exit(1);
  }

  std::string proc_cgroup_dir = cpu_cgroup_dir + "/" + pid;
  std::string set_pid_cmd = "echo " + std::to_string(getpid()) + " >> " + proc_cgroup_dir + "/cgroup.procs";

  if (system(set_pid_cmd.c_str()) < 0)
  {
    std::cout << "Can not make cpu cgpup for process " << getpid() << std::endl;
    system(unmount_cgroups_cmd.c_str());
    exit(1);
  }

  if (system(unmount_cgroups_cmd.c_str()) < 0)
  {
    std::cout << "Can not unmount cpu cgroup";
    exit(1);
  }
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

  set_cpu_cgroup(id_str);
  set_namespace(id_str, "user");
  set_namespace(id_str, "pid");
  set_namespace(id_str, "ipc");
  set_namespace(id_str, "net");
  set_namespace(id_str, "uts");
  set_namespace(id_str, "mnt");

  int pid = fork();
  if (pid == 0)
  {
    if (execvp(args[0], args.data()) < 0)
    {
      std::cout << "Can not run command in container" << std::endl;
      exit(1);
    }
  }
  else
  {
    waitpid(pid, NULL, 0);
  }
  return 0;
}
