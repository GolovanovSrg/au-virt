#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <thread>

#include <cstring>
#include <cstdlib>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <linux/sched.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/syscall.h>

#include "utils.h"

#define STACK_SIZE (1024 * 1024)

namespace
{

char cont_stack[STACK_SIZE];

struct container_parameters
{
  std::string img_path = "";
  bool is_daemon = false;
  int cpu_perc = 100;
  std::string ip = "";
  std::vector<char*> args;

  int pipe1_fd[2];
  int pipe2_fd[2];
};

container_parameters get_cont_parameters(int argc, char* argv[])
{
  container_parameters params;

  if (argc < 3)
  {
    std::cout << "Invalid parameters number" << std::endl;
    exit(1);
  }

  for (int i = 1; i < argc; ++i)
  {
    if (std::strcmp(argv[i], "-d") == 0)
    {
      params.is_daemon = true;
    }
    else if(std::strcmp(argv[i], "--cpu") == 0)
    {
      if (i + 1 >= argc || std::any_of(argv[i + 1], argv[i + 1] + strlen(argv[i + 1]),
                                      [](char ch){return !std::isdigit(ch);}))
      {
        std::cout << "Invalid value for --cpu" << std::endl;
        exit(1);
      }

      params.cpu_perc = std::atoi(argv[++i]);
      if (params.cpu_perc < 1 || params.cpu_perc > 100)
      {
        std::cout << "Value for --cpu must be in [1, 100]" << std::endl;
        exit(1);
      }
    }
    else if (std::strcmp(argv[i], "--net") == 0)
    {
      in_addr address;
      if (!inet_aton(argv[++i], &address))
      {
        std::cout << "Invalid value for --net" << std::endl;
        exit(1);
      }

      params.ip = inet_ntoa(address);
    }
    else
    {
      params.img_path = std::string(argv[i++]);
      while (i < argc)
      {
        params.args.push_back(argv[i++]);
      }
      params.args.push_back(NULL);
    }
  }

  return params;
}

void configure_uts()
{
  std::string name = "container";
  if (sethostname(name.c_str(), name.length()) < 0)
  {
    std::cout << "Can not set hostname" << std::endl;
    exit(1);
  }
}

void configure_user(int pid)
{
  std::string gid = std::to_string(getgid());
  std::string uid = std::to_string(getuid());

  std::string proc_path = "/proc/" + std::to_string(pid);
  std::string set_uid_cmd = "echo \'0 " + uid  + " 1\' > " + proc_path + "/uid_map";
  std::string set_setgroups_cmd = "echo deny > " + proc_path + "/setgroups";
  std::string set_gid_cmd = "echo \'0 " + gid  + " 1\' > " + proc_path + "/gid_map";

  if (system(set_uid_cmd.c_str()) < 0 ||
      system(set_setgroups_cmd.c_str()) < 0 ||
      system(set_gid_cmd .c_str()) < 0)
  {
    std::cout << "Can not configure user"  << std::endl;
    exit(1);
  }
}

void configure_fs(const std::string& root)
{
  std::string proc = root + "/proc";
  if (!dir_exists(proc))
    make_dir(proc, 0666);
  if (mount(NULL, proc.c_str(), "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) < 0)
  {
    std::cout << "Can not mount /proc." << std::endl;
    exit(1);
  }

  std::string sys = root + "/sys";
  if (!dir_exists(sys))
    make_dir(sys, 0666);
  if (mount(NULL, sys.c_str(), "sysfs", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) < 0)
  {
    std::cout << "Can not mount /sys." << std::endl;
    exit(1);
  }

  std::string zero = root + "/dev/zero";
  mknod(zero.c_str(), 0666, 0);
  if (mount("/dev/zero", zero.c_str(), "", MS_BIND, NULL) < 0)
  {
    std::cout << "Can not mount /dev/zero." << std::endl;
    exit(1);
  }

  std::string null = root + "/dev/null";
  mknod(null.c_str(), 0666, 0);
  if (mount("/dev/null", null.c_str(), "", MS_BIND, NULL) < 0)
  {
    std::cout << "Can not mount /dev/null." << std::endl;
    exit(1);
  }

  std::string shm = root + "/dev/shm";
  if (!dir_exists(shm))
    make_dir(shm, 0666);
  if (mount("/dev/shm", shm.c_str(), "", MS_BIND, NULL) < 0)
  {
    std::cout << "Can not mount /dev/shm." << std::endl;
    exit(1);
  }

  std::string mqueue = root + "/dev/mqueue";
  if (!dir_exists(mqueue))
    make_dir(mqueue, 0666);
  if (mount("/dev/mqueue", mqueue.c_str(), "", MS_BIND, NULL) < 0)
  {
    std::cout << "Can not mount /dev/mqueue." << std::endl;
    exit(1);
  }

  std::string old_root = root + "/old_root";
  if (!dir_exists(old_root))
    make_dir(old_root, 0777);
  if (mount(root.c_str(), root.c_str(), "bind", MS_BIND | MS_REC, NULL) < 0)
  {
    std::cout << "Can not mount new root" << std::endl;
    exit(1);
  }
  if (syscall(SYS_pivot_root, root.c_str(), old_root.c_str()) < 0)
  {
    std::cout << "Can not change root" << std::endl;
    exit(1);
  }

  if (chdir("/") < 0)
  {
    std::cout << "Can not change work directory" << std::endl;
    exit(1);
  }

  if (umount2("/old_root", MNT_DETACH) < 0)
  {
    std::cout << "Can not unmount old root" << std::endl;
    exit(1);
  }
}

void configure_cpu(int pid, int cpu_perc)
{
  std::string cpu_cgroup_dir = CGROUPS_DIR + "/cpu";

  std::string mount_cgroups_cmd = "sudo mount -t cgroup -o cpu none " + cpu_cgroup_dir;
  std::string umount_cgroups_cmd = "sudo umount " + cpu_cgroup_dir;

  if (system(mount_cgroups_cmd.c_str()) < 0)
  {
    std::cout << "Can not mount cpu cgroup";
    exit(1);
  }

  std::string proc_cgroup_dir = cpu_cgroup_dir + "/" + std::to_string(pid);
  std::string mkdir_cmd = "sudo mkdir -p " + proc_cgroup_dir;
  std::string chown_cmd = "sudo chown -R " + std::to_string(getuid()) + ":" + std::to_string(getgid()) + " " + proc_cgroup_dir;

  if (system(mkdir_cmd.c_str()) < 0 || system(chown_cmd.c_str()) < 0)
  {
    std::cout << "Can not make directory " +  proc_cgroup_dir << std::endl;
    system(umount_cgroups_cmd.c_str());
    exit(1);
  }

  std::string set_period_cmd = "echo 1000000 >> " + proc_cgroup_dir + "/cpu.cfs_period_us";
  int quota = 1000000 * std::thread::hardware_concurrency() / 100 * cpu_perc;
  std::string set_quota_cmd = "echo " + std::to_string(quota) + " >> " + proc_cgroup_dir + "/cpu.cfs_quota_us";
  std::string set_pid_cmd = "echo " + std::to_string(pid) + " >> " + proc_cgroup_dir + "/cgroup.procs";

  if (system(set_period_cmd.c_str()) < 0 ||
      system(set_quota_cmd.c_str()) < 0 ||
      system(set_pid_cmd.c_str()) < 0)
  {
    std::cout << "Can not make cpu cgpup for process " << pid << std::endl;
    std::string remove_proc_dir = "sudo rm -r " + proc_cgroup_dir;
    system(umount_cgroups_cmd.c_str());
    system(remove_proc_dir.c_str());
    exit(1);
  }

  if (system(umount_cgroups_cmd.c_str()) < 0)
  {
    std::cout << "Can not unmount cpu cgroup";
    exit(1);
  }
}

std::string increment_ip(const std::string& address_string)
{
    in_addr_t address = inet_addr(address_string.c_str());
    address = ntohl(address);
    address += 1;
    address = htonl(address);
    struct in_addr address_struct;
    address_struct.s_addr = address;
    return std::string(inet_ntoa(address_struct));
}

void configure_container_net(const std::string& ip)
{
  std::string cmd1 = "ip link set v1-" + ip + " up";
  std::string cmd2 = "ip addr add " + ip + "/24 dev v1-" + ip;
  std::string cmd3 = "ip link set lo up";
  std::string cmd4 = "ip route add default via " + increment_ip(ip);

  if (system(cmd1.c_str()) < 0 ||
      system(cmd2.c_str()) < 0 ||
      system(cmd3.c_str()) < 0 ||
      system(cmd4.c_str()) < 0)
  {
    std::cout << "Can not configure net on container" << std::endl;
    exit(1);
  }
}

void configure_host_net(const std::string& ip, int cont_pid)
{
  std::string cmd1 = "sudo ip link add v0-" + ip + " type veth peer name v1-" + ip;
  std::string cmd2 = "sudo ip link set v0-" + ip + " up";
  std::string cmd3 = "sudo ip link set v1-" + ip + " netns " + std::to_string(cont_pid);
  std::string cmd4 = "sudo ip addr add " + increment_ip(ip) + "/24 dev v0-" + ip;
  std::string cmd5 = "sudo sysctl net.ipv4.conf.all.forwarding=1 > /dev/null";

  if (system(cmd1.c_str()) < 0 ||
      system(cmd2.c_str()) < 0 ||
      system(cmd3.c_str()) < 0 ||
      system(cmd4.c_str()) < 0 ||
      system(cmd5.c_str()) < 0)
  {
    std::cout << "Can not configure net on host" << std::endl;
    exit(1);
  }
}

int cont_init(void *arg)
{
  container_parameters* params = (container_parameters*) arg;

  if (params->is_daemon)
  {
    if (daemon(0, 0) < 0)
    {
      std::cout << "Can not demonize container" << std::endl;
      exit(1);
    }
  }

  if (unshare(CLONE_NEWPID) < 0)
  {
    std::cout << "Can not unshare pid namespace" << std::endl;
    exit(1);
  }

  int pid = fork();
  if (pid > 0)
  {
    write_int(params->pipe2_fd[1], pid);

    if (waitpid(pid, NULL, 0) < 0)
    {
        std::cout << "Wait container process failed" << std::endl;
        exit(1);
    }

    exit(0);
  }

  read_int(params->pipe1_fd[0]);

  if (params->ip != "")
  {
    configure_container_net(params->ip);
  }
  configure_uts();
  configure_fs(params->img_path);

  write_int(params->pipe2_fd[1], 1);

  close(params->pipe1_fd[0]);
  close(params->pipe2_fd[1]);
  close(params->pipe1_fd[1]);
  close(params->pipe2_fd[0]);

  if (execvp(params->args[0], params->args.data()) < 0)
  {
    std::cout << "Can not run command in container" << std::endl;
    exit(1);
  }

  return 0;
}

} // anonymous namespace

int main(int argc, char* argv[])
{
  container_parameters params = get_cont_parameters(argc, argv);

  if (pipe(params.pipe1_fd) < 0 || pipe(params.pipe2_fd) < 0)
  {
    std::cout << "Can not open pipes for synchronize with container"  << std::endl;
    exit(1);
  }

  int clone_namespaces = CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWNS |
                         CLONE_NEWUTS | CLONE_NEWUSER | SIGCHLD;

  if (clone(cont_init, cont_stack + STACK_SIZE, clone_namespaces, &params) < 0)
  {
    std::cout << "Can not create container process"  << std::endl;
  }

  int cont_pid = read_int(params.pipe2_fd[0]);

  configure_user(cont_pid);
  configure_cpu(cont_pid, params.cpu_perc);
  if (params.ip != "")
  {
    configure_host_net(params.ip, cont_pid);
  }

  write_int(params.pipe1_fd[1], 1);

  if (read_int(params.pipe2_fd[0]) == 1)
  {
    add_to_contlist(cont_pid);
    std::cout << cont_pid << std::endl;

    if (!params.is_daemon)
    {
      if (wait(NULL) < 0)
      {
          std::cout << "Wait container failed" << std::endl;

          close(params.pipe1_fd[0]);
          close(params.pipe1_fd[1]);
          close(params.pipe2_fd[0]);
          close(params.pipe2_fd[1]);

          exit(1);
      }

      del_from_contlist(cont_pid);
    }
  }

  close(params.pipe1_fd[0]);
  close(params.pipe1_fd[1]);
  close(params.pipe2_fd[0]);
  close(params.pipe2_fd[1]);

  return 0;
}
