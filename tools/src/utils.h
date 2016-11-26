#pragma once

#include <vector>

#include <unistd.h>
#include <cstdlib>
#include <string>
#include <sys/stat.h>
#include <cerrno>
#include <fstream>

#define AUCONT_DIR std::string(".aucont")
#define CONTLIST_FILE_PATH (AUCONT_DIR + "/contlist")
#define CGROUPS_DIR std::string(".aucont/cgroup")

int read_int(int fd)
{
  int res = 0;
  if (read(fd, &res, sizeof(res)) <= 0)
  {
    std::cout << "Reading from fd failed" << std::endl;
    exit(1);
  }

  return res;
}

void write_int(int fd, int value)
{
  if (write(fd, &value, sizeof(value)) <= 0)
  {
    std::cout << "Writing to fd failed" << std::endl;
    exit(1);
  }
}

inline bool dir_exists(const std::string& dir_path)
{
  struct stat st;
  return !(stat(dir_path.c_str(), &st)  < 0 && errno == ENOENT);
}

inline void make_dir(const std::string& dir_path, int flags)
{
  if (mkdir(dir_path.c_str(), flags) < 0)
  {
    std::cout << "Can not create directory " + dir_path << std::endl;
    exit(1);
  }
}

inline void check_aucont_dir()
{
  if (!dir_exists(AUCONT_DIR))
  {
    make_dir(AUCONT_DIR, 0777);
    std::ofstream(CONTLIST_FILE_PATH).close();
  }
}

inline void add_to_contlist(int id)
{
  check_aucont_dir();

  std::ofstream contlist_file(CONTLIST_FILE_PATH, std::ofstream::out | std::ofstream::app);
  if (!contlist_file.is_open())
  {
    std::cout << "File with list of containers is not opened" << std::endl;
    exit(1);
  }

  contlist_file << id << std::endl;
  contlist_file.close();
}

inline std::vector<int> get_all_contlist()
{
  check_aucont_dir();

  std::ifstream contlist_file(CONTLIST_FILE_PATH);
  if (!contlist_file.is_open())
  {
    std::cout << "File with list of containers is not opened" << std::endl;
    exit(1);
  }

  std::vector<int> result;
  int cur_id;
  while(contlist_file >> cur_id)
  {
    result.push_back(cur_id);
  }

  contlist_file.close();

  return result;
}

inline void del_from_contlist(int id)
{
  std::vector<int> conts_ids = get_all_contlist();

  std::ofstream contlist_file(CONTLIST_FILE_PATH);
  if (!contlist_file.is_open())
  {
    std::cout << "File with list of containers is not opened" << std::endl;
    exit(1);
  }

  for (int cur_id : conts_ids)
  {
    if (cur_id != id)
      contlist_file << cur_id << std::endl;
  }

  contlist_file.close();
}

inline bool find_in_contlist(int id)
{
  check_aucont_dir();

  std::ifstream contlist_file(CONTLIST_FILE_PATH);
  if (!contlist_file.is_open())
  {
    std::cout << "File with list of containers is not opened" << std::endl;
    exit(1);
  }

  int cur_id;
  while(contlist_file >> cur_id)
  {
    if (cur_id == id)
    {
      contlist_file.close();
      return true;
    }
  }

  contlist_file.close();
  return false;
}
