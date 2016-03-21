#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif
// proof of work
#define POW

#include <arpa/inet.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <math.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <seccomp.h>
#ifdef POW
# include <openssl/sha.h>
#endif

int opt_pow_bits = 0;
int opt_pow_nonce = 8;
double opt_pow_sec = 30;
int opt_port = 2222;
int opt_timeout = 5000;

#define FOR(i, a, b) for (int i = (a); i < (b); i++)
#define REP(i, n) FOR(i, 0, n)

//// Utilities

enum { GN_POSITIVE = 1, GN_NON_NEGATIVE = 2 };

long get_long(const char *arg, int flags)
{
  char *end;
  errno = 0;
  long ret = strtol(arg, &end, 0);
  if (errno)
    errx(EX_USAGE, "get_long: %s", arg);
  if (*end)
    errx(EX_USAGE, "get_long: nonnumeric character");
  if (flags & GN_POSITIVE && ret <= 0)
    errx(EX_USAGE, "get_long: not positive");
  if (flags & GN_NON_NEGATIVE && ret < 0)
    errx(EX_USAGE, "get_long: negative");
  return ret;
}

int get_int(const char *arg, int flags)
{
  long r = get_long(arg, flags);
  if (r > INT_MAX)
    errx(EX_USAGE, "get_int: out of range");
  return r;
}

double get_double(const char *arg, int flags)
{
  char *end;
  errno = 0;
  double ret = strtod(arg, &end);
  if (errno)
    errx(EX_USAGE, "get_double: %s", arg);
  if (*end)
    errx(EX_USAGE, "get_double: nonumeric character");
  if (flags & GN_POSITIVE && ret <= 0)
    errx(EX_USAGE, "get_double: not positive");
  return ret;
}

void set_timer(double sec)
{
  struct itimerval timer;
  double integral, fractional;
  fractional = modf(sec, &integral);
  timer.it_value.tv_sec = integral;
  timer.it_value.tv_usec = (int)(fractional*1e6);
  timer.it_interval.tv_sec = integral;
  timer.it_interval.tv_usec = 0;
  setitimer(ITIMER_REAL, &timer, NULL);
}

int pty_open_master(char *slave_name, size_t sn_len)
{
  // /proc/sys/kernel/pty/max
  int master = posix_openpt(O_RDWR | O_NOCTTY);
  char *p;
  if (master < 0)
    return -1;
  if (grantpt(master) < 0 || unlockpt(master) < 0 || ! (p = ptsname(master))) {
    int saved = errno;
    close(master);
    errno = saved;
    return -1;
  }
  if (strlen(p) >= sn_len) {
    close(master);
    errno = EOVERFLOW;
    return -1;
  }
  strncpy(slave_name, p, sn_len);
  return master;
}

int pty_fork(int *master, char *slave_name, size_t sn_len, const struct termios *slave_termios)
{
  *master = pty_open_master(slave_name, sn_len);
  if (*master < 0)
    return -1;
  pid_t child = fork();
  if (child < 0) {
    int saved = errno;
    close(*master);
    errno = saved;
    return -1;
  }
  // parent
  if (child > 0)
    return child;
  // child
  if (setsid() < 0)
    err(EX_OSERR, "pty_fork:setsid");
  close(*master);
  int slave = open(slave_name, O_RDWR);
  if (slave < 0)
    err(EX_OSERR, "pty_fork:open slave");
  if (slave_termios)
    if (tcsetattr(slave, TCSANOW, slave_termios) < 0)
      err(EX_OSERR, "pty_fork:tcsetattr");
  REP(i, 3)
    if (dup2(slave, i) != i)
      err(EX_OSERR, "pty_fork:dup2(slave, %d)", i);
  close(slave);
  return 0;
}

void setup_seccomp(void)
{
  scmp_filter_ctx scmp_ctx = seccomp_init(SCMP_ACT_ERRNO(EPERM));
  if (! scmp_ctx)
    err(EX_OSERR, "seccomp_init");
  static const char *scmp_whitelist[] = {
    "access",
    "arch_prctl",
    "brk",
    "capget",
    "chdir",
    "clone",
    "close",
    "connect",
    "dup",
    "dup2",
    "execve",
    "exit",
    "exit_group",
    "faccessat",
    "fcntl",
    "fork",
    "fstat",
    "ftruncate", // w
    "futex",
    "getcwd",
    "getdents",
    "getdents64",
    "getegid",
    "geteuid",
    "getgid",
    "getpgid",
    "getpgrp",
    "getpid",
    "getppid",
    "getrandom",
    "getrlimit",
    "gettid",
    "getuid",
    "getxattr",
    "ioctl", // w
    "lseek",
    "lstat",
    "madvise",
    "mkdir", // w
    "mmap",
    "mprotect",
    "munmap",
    "newfstatat",
    "open",
    "pipe",
    "pipe2",
    "poll",
    "prlimit64",
    "pselect6",
    "read",
    "readv",
    "readlink",
    "rmdir", // w
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "sched_getaffinity",
    "select",
    "set_robust_list",
    "set_tid_address",
    "setpgid",
    "sigaltstack",
    "socket",
    "stat",
    "sysinfo",
    "uname",
    "unlink", // w
    "unlinkat", // w
    "utimensat",
    "wait4",
    "write", // w
    "writev", // w
    NULL};
  for (int i = 0; scmp_whitelist[i]; i++) {
    int num = seccomp_syscall_resolve_name(scmp_whitelist[i]);
    if (num < 0)
      errx(EX_DATAERR, "seccomp_syscall_resolve_name %s", scmp_whitelist[i]);
    if (seccomp_rule_add(scmp_ctx, SCMP_ACT_ALLOW, num, 0) < 0)
      err(EX_OSERR, "seccomp_rule_add %s", scmp_whitelist[i]);
  }
  if (seccomp_load(scmp_ctx) < 0)
      err(EX_OSERR, "seccomp_load");
}

void setup_rlimit(void)
{
  static int limits[][2] = {
    {RLIMIT_CORE, 0}, // CPU time in sec
    {RLIMIT_CPU, 1}, // CPU time in sec
    {RLIMIT_FSIZE, 1024*1024}, // maximum filesize
    {RLIMIT_DATA, 8*1024*1024}, // max data size
    {-1, -1},
  };
  struct rlimit rlim;
  for (int i = 0; limits[i][0] >= 0; i++) {
    rlim.rlim_cur = rlim.rlim_max = limits[i][1];
    setrlimit(limits[i][0], &rlim); // ignore errors
  }
}

#ifdef POW
bool check_proof_of_work(const char *proof)
{
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha;
  SHA256_Init(&sha);
  SHA256_Update(&sha, proof, strlen(proof));
  SHA256_Final(hash, &sha);
  int s = 0;
  REP(i, SHA256_DIGEST_LENGTH) {
    if (hash[i]) {
      s += __builtin_clz(hash[i])-24;
      break;
    }
    s += 8;
  }
  return s >= opt_pow_bits;
}

void proof_of_work()
{
  char proof[64] = {};
  REP(i, opt_pow_nonce)
    proof[i] = 'a'+rand()%26;
  int proof_len = sizeof proof-1-opt_pow_nonce;
  printf("I would like some proof of work. Send me a string starting with '%s', no whitespace, of length <= %zd, such that its sha256 in binary starts with %d bits of zeros.\r\n", proof, sizeof proof-1, opt_pow_bits);
  set_timer(opt_pow_sec);
  REP(i, sizeof proof-1) {
    char c;
    int r = read(STDIN_FILENO, &c, 1);
    if (r < 0)
      errx(EX_DATAERR, "read");
    if (i < opt_pow_nonce) {
      if (! r || proof[i] != c)
        errx(EX_DATAERR, "Incorrect prefix");
    } else if (! r || ! c || isspace(c))
      break;
    else
      proof[i] = c;
  }
  set_timer(0);
  if (! check_proof_of_work(proof))
    errx(EX_DATAERR, "Invalid proof");
}
#endif

void handle_client(int fd)
{
  if (dup2(fd, 0) < 0 || dup2(fd, 1) < 0 || dup2(fd, 2) < 0)
    return;
  setbuf(stdout, NULL);
  srand(time(NULL));
#ifdef POW
  if (opt_pow_bits)
    proof_of_work();
#endif
  close(fd);
  {
    char buf[99];
    sprintf(buf, "%d", rand()%100);
    chdir("/tmp");
    mkdir(buf, 0111);
    chdir(buf);
  }

  // non-blocking
  int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
  if (flags < 0 || fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK) < 0)
    err(EX_OSERR, "fcntl");

  // fork and create a pseudoterminal pair
  char slave_name[100];
  int master;
  int child = pty_fork(&master, slave_name, sizeof slave_name, NULL);
  if (child < 0)
    err(EX_OSERR, "pty_fork");
  if (! child) {
    setup_rlimit();
    setup_seccomp();
    execlp("bash", "-bash", NULL);
    err(EX_OSERR, "execlp");
  }

  // restore SIGCHLD
  //if (signal(SIGCHLD, SIG_DFL) < 0)
  //  err(EX_OSERR, "signal");

  // communicate
  #define BUFSIZE 4096
  struct pollfd pfd[2];
  char buf[2][BUFSIZE];
  int hd[2] = {}, tl[2] = {};
  bool hup = false;
  pfd[0].fd = STDIN_FILENO;
  pfd[1].fd = master;
  for(;;) {
    REP(i, 2)
      pfd[i].events = POLLIN | POLLHUP | (hd[i^1] != tl[i^1] ? POLLOUT : 0);
    int ready = poll(pfd, 2, opt_timeout);
    if (ready < 0)
      err(EX_OSERR, "poll");
    if (! ready)
      errx(EX_DATAERR, "timeout");
    REP(i, 2)
      if (pfd[i].revents & POLLIN) {
        int max_read = hd[i] > tl[i] ? hd[i]-tl[i]-1 : BUFSIZE-tl[i]-!hd[i];
        if (! max_read)
          errx(EX_UNAVAILABLE, "receiving buffer overflows");
        int r = read(pfd[i].fd, buf[i]+tl[i], max_read);
        if (r < 0)
          err(EX_IOERR, "read %d", pfd[i].fd);
        if (! r)
          errx(EX_DATAERR, "eof");
        tl[i] += r;
        if (tl[i] == BUFSIZE)
          tl[i] = 0;
      }
    REP(i, 2)
      if (pfd[i^1].revents & POLLOUT) {
        int r = write(pfd[i^1].fd, buf[i]+hd[i], hd[i] > tl[i] ? BUFSIZE-hd[i] : tl[i]-hd[i]);
        if (r < 0)
          err(EX_IOERR, "write %d", pfd[i^1].fd);
        hd[i] += r;
        if (hd[i] == BUFSIZE)
          hd[i] = 0;
      }
    REP(i, 2)
      if (pfd[i].revents & POLLHUP)
        hup = true;
    if (hd[0] == tl[0] && hd[1] == tl[1] && hup)
      errx(EX_DATAERR, "hup");
  }
}

void print_help(FILE *fh)
{
  fprintf(fh, "Usage: %s [OPTIONS]\n", program_invocation_short_name);
  fputs(
        "\n"
        "Options:\n"
        "  --port            listening port\n"
        "  --pow-bits        proof of work: number of leading zero bits\n"
        "  --pow-time        proof of work: wait for $pow-time seconds\n"
        "  --timeout         idle timeout in milliseconds, -1 means an infinite timeout\n"
        "  --help            display this help and exit\n"
        ""
        , fh);
  exit(fh == stdout ? 0 : EX_USAGE);
}

int main(int argc, char *argv[])
{
  int opt;
  static struct option long_options[] = {
    {"port",            required_argument,  0,   'p'},
    {"timeout",         required_argument,  0,   't'},
#ifdef POW
    {"pow-bits",        required_argument,  0,   1},
    {"pow-time",        required_argument,  0,   2},
#endif
    {0,                 0,                  0,   0},
  };
  while ((opt = getopt_long(argc, argv, "hp:t:", long_options, NULL)) != -1) {
    switch (opt) {
#ifdef POW
    case 1:
      opt_pow_bits = get_int(optarg, GN_NON_NEGATIVE);
      break;
    case 2:
      opt_pow_sec = get_double(optarg, GN_POSITIVE);
      break;
#endif
    case 'h':
      print_help(stdout);
      break;
    case 'p':
      opt_port = get_int(optarg, GN_POSITIVE);
      break;
    case 't':
      opt_timeout = get_int(optarg, GN_POSITIVE);
      break;
    case '?':
      print_help(stderr);
      break;
    }
  }

  // ignore SIGPIPE & SIGCHLD
  if (signal(SIGPIPE, SIG_IGN) < 0)
    err(EX_OSERR, "signal");
  if (signal(SIGCHLD, SIG_IGN) < 0)
    err(EX_OSERR, "signal");

  // TCP4 socket
  int sockfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0), on = 1;
  if (sockfd < 0)
    err(EX_OSERR, "socket");
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on) < 0)
    err(EX_OSERR, "setsockopt SO_REUSEADDR");
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof addr);
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(opt_port);
  if (bind(sockfd, (struct sockaddr *)&addr, sizeof addr) < 0)
    err(EX_OSERR, "bind port %d", opt_port);
  if (listen(sockfd, 10) < 0)
    err(EX_OSERR, "listen");

  // serve clients
  for(;;) {
    int fd = accept(sockfd, NULL, NULL);
    if (fd < 0)
      errx(EX_OSERR, "accept");
    pid_t child = fork();
    if (child < 0) {
      dprintf(fd, "fork: %s\n", strerror(errno));
      close(fd);
    } else if (child > 0)
      close(fd);
    else {
      handle_client(fd);
      return 0;
    }
  }
  return 0;
}
