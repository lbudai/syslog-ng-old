#include "libtest/testutils.h"
#include "affile/affile-common.h"
#include "lib/messages.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#define CREATE_DIRS 0x01
#define NEEDS_PRIV 0x02
#define PIPE 0x04

#define PIPE_OFLAGS (O_RDWR | O_NOCTTY | O_NONBLOCK | O_LARGEFILE)

static gboolean
_open_file(char *fname, int open_flags, int extra_flags, FilePermOptions *perm_opts, int *fd)
{
  FileOpenOptions open_opts;

  open_opts.open_flags = open_flags;
  open_opts.needs_privileges = !!(extra_flags & NEEDS_PRIV);
  open_opts.create_dirs = !!(extra_flags & CREATE_DIRS);
  open_opts.is_pipe = !!(extra_flags & PIPE);

  return affile_open_file(fname, &open_opts, perm_opts, fd);
}

static gboolean
_open_file_with_default_perm(char *fname, int open_flags, int extra_flags, int *fd)
{
  FilePermOptions perm_opts;

  file_perm_options_defaults(&perm_opts);

  return _open_file(fname, open_flags, extra_flags, &perm_opts, fd);
}

void assert_if_file_is_not_pipe(const char *fname)
{
  struct stat st;
  
  stat(fname, &st);
  assert_gboolean(S_ISFIFO(st.st_mode) != 0, TRUE,  "[%s][%s][%d]", __FILE__, __func__, __LINE__);
}

void assert_if_file_is_not_regular(const char *fname)
{
  struct stat st;
  
  stat(fname, &st);
  assert_gboolean(S_ISREG(st.st_mode) != 0, TRUE,  "[%s][%s][%d]", __FILE__, __func__, __LINE__);
}

void assert_if_regular_file_can_be_open(char *fname)
{
  gint fd;

  assert_gboolean(_open_file_with_default_perm(fname, O_CREAT, 0, &fd), FALSE,
                  "[%s][%s][%d]", __FILE__, __func__, __LINE__);
}

void assert_if_file_uid_not_equals(char *fname, uid_t expected)
{
  struct stat st;

  stat(fname, &st);
  assert_guint32(st.st_uid, expected,  "[%s][%s][%d]", __FILE__, __func__, __LINE__);
}

void assert_if_create_regular_file_with_uid_fail(char *fname, uid_t uid)
{
  gint fd;
  FilePermOptions perm_opts;

  file_perm_options_defaults(&perm_opts);
  perm_opts.file_uid = uid;

  assert_gboolean(_open_file(fname, O_CREAT, 0, &perm_opts, &fd), TRUE,
                  "[%s][%s][%d]", __FILE__, __func__, __LINE__);

  assert_gboolean(fd != -1, TRUE, "%s : bad fd", __func__);

  close(fd);
}

void assert_if_create_pipe_with_uid_fail(char *fname, uid_t uid)
{
  gint fd;
  FilePermOptions perm_opts;

  file_perm_options_defaults(&perm_opts);
  perm_opts.file_uid = uid;
  
  assert_gboolean(_open_file(fname, PIPE_OFLAGS, PIPE, &perm_opts, &fd), TRUE,
                  "[%s][%s][%d]", __FILE__, __func__, __LINE__);

  assert_gboolean(fd != -1, TRUE, "[%s][%s][%d]", __FILE__, __func__, __LINE__);

  close(fd);
}

void test_spurious_path()
{
  assert_if_regular_file_can_be_open("/tmp/../test.fname");
  assert_if_regular_file_can_be_open("../../../test.fname");
}

void test_create_regular_file()
{
  gchar test_file[] = "/tmp/test1.txt";

  remove(test_file);
  assert_if_create_regular_file_with_uid_fail(test_file, getuid());
  assert_if_file_is_not_regular(test_file);
  assert_if_file_uid_not_equals(test_file, getuid());

  remove(test_file);
  assert_if_create_regular_file_with_uid_fail(test_file, getuid()+1);
  assert_if_file_is_not_regular(test_file);
  assert_if_file_uid_not_equals(test_file, getuid());
}

void test_write_regular_file_with_content_check()
{
  gchar test_file[] = "/tmp/testfile.txt";
  gchar content[] = "test";
  gchar readbuf[128] = {0};
  gint fd;

  remove(test_file);

  assert_gboolean(_open_file_with_default_perm(test_file, O_CREAT|O_WRONLY, 0, &fd), TRUE,
                  "[%s][%s][%d]", __FILE__, __func__, __LINE__);

  assert_gint32(write(fd, content, sizeof(content)), sizeof(content),
               "[%s][%s][%d]", __FILE__, __func__, __LINE__);

  assert_gint32(read(fd, readbuf, sizeof(readbuf)), -1,
                "[%s][%s][%d]", __FILE__, __func__, __LINE__);
  close(fd);

  assert_gboolean(_open_file_with_default_perm(test_file, O_RDONLY, 0, &fd), TRUE,
                  "[%s][%s][%d]", __FILE__, __func__, __LINE__);

  assert_gint32(read(fd, readbuf, sizeof(readbuf)), sizeof(content),
                "[%s][%s][%d]", __FILE__, __func__, __LINE__);

  assert_nstring(content, sizeof(content), readbuf, sizeof(content),
                 "[%s][%s][%d]", __FILE__, __func__, __LINE__);
  close(fd);
}

void test_create_pipe()
{
  gchar test_file[] = "/tmp/test.pipe";

  remove(test_file);
  assert_if_create_pipe_with_uid_fail(test_file, getuid());
  assert_if_file_is_not_pipe(test_file);
  assert_if_file_uid_not_equals(test_file, getuid());

  remove(test_file);
  assert_if_create_pipe_with_uid_fail(test_file, getuid()+1);
  assert_if_file_is_not_pipe(test_file);
  assert_if_file_uid_not_equals(test_file, getuid());
}

void test_write_pipe_with_content_check()
{
  gchar test_file[] = "/tmp/test.pipe";
  gchar content[] = "test";
  gchar readbuf[128] = {0};
  gint fd;

  remove(test_file);

  assert_gboolean(_open_file_with_default_perm(test_file, PIPE_OFLAGS, PIPE, &fd), TRUE,
                  "[%s][%s][%d]", __FILE__, __func__, __LINE__);
  
  assert_if_file_is_not_pipe(test_file);

  assert_gint32(write(fd, content, sizeof(content)), sizeof(content),
                "[%s][%s][%d]", __FILE__, __func__, __LINE__);

  assert_gint32(read(fd, readbuf, sizeof(readbuf)), sizeof(content),
                "[%s][%s][%d]", __FILE__, __func__, __LINE__);

  assert_nstring(content, sizeof(content), readbuf, sizeof(content),
                 "[%s][%s][%d]", __FILE__, __func__, __LINE__);

  close(fd);
}

void test_create_file_in_nonexistent_dir()
{
  gchar test_dir[] = "/tmp/test";
  gchar test_file[] = "/tmp/test/test1.txt";
  gint fd;

  remove(test_file);
  remove(test_dir);
  
  assert_gboolean(_open_file_with_default_perm(test_file, O_CREAT|O_WRONLY, 0, &fd), FALSE,
                  "[%s][%s][%d]", __FILE__, __func__, __LINE__);

  assert_gboolean(_open_file_with_default_perm(test_file, O_CREAT|O_WRONLY, CREATE_DIRS, &fd), TRUE,
                  "[%s][%s][%d]", __FILE__, __func__, __LINE__);
}

void setup()
{
  msg_init(FALSE);
}

int main(int argc, char **argv)
{
  setup();

  test_spurious_path();

  test_create_regular_file();
  test_write_regular_file_with_content_check();
  test_create_file_in_nonexistent_dir();

  test_create_pipe();
  test_write_pipe_with_content_check();

  return 0;
}
