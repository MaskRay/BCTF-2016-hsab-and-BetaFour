#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif
// proof of work
#define POW

#include <arpa/inet.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <math.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>
#include <seccomp.h>
#ifdef POW
# include <openssl/sha.h>
#endif

int opt_pow_bits = 0;
int opt_pow_nonce = 8;
double opt_pow_sec = 30;
int opt_port = 2223;
int opt_games = 10;
int opt_passing_score = 14;
double opt_cpu_sec = 0.3;
double opt_human_sec = 4;
const int MAXM = 12, MAXN = 12;

#define FOR(i, a, b) for (int i = (a); i < (b); i++)
#define REP(i, n) FOR(i, 0, n)
#define ROF(i, a, b) for (int i = (b); --i >= (a); )

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
  timer.it_value.tv_usec = int(fractional*1e6);
  timer.it_interval.tv_sec = integral;
  timer.it_interval.tv_usec = 0;
  setitimer(ITIMER_REAL, &timer, NULL);
}

//// Hardening

void setup_seccomp()
{
  scmp_filter_ctx scmp_ctx = seccomp_init(SCMP_ACT_ERRNO(EPERM));
  if (! scmp_ctx)
    err(EX_OSERR, "seccomp_init");
  static const char *scmp_whitelist[] = {
    "brk",
    "clock_gettime",
    "execve",
    "exit",
    "exit_group",
    "lseek",
    "read",
    "readv",
    "setitimer",
    "write",
    "writev",
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

//// Connect Four

typedef uint8_t Move;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
enum Color { WHITE, BLACK, };
enum Status { UNDETERMINED, WIN, DRAW, LOSE, };
const Move NULL_MOVE = 0xFF;

class Bitboard
{
public:
  Bitboard(u64 a0, u64 a64, u64 a128) {
    a[0] = a0;
    a[1] = a64;
    a[2] = a128;
  }
  bool operator==(const Bitboard &x) const {
    return a[0] == x.a[0] && a[1] == x.a[1] && a[2] == x.a[2];
  }
  Bitboard operator>>(int x) const {
    return Bitboard(a[1] << (64 - x) | a[0] >> x,
                    a[2] << (64 - x) | a[1] >> x,
                    a[2] >> x);
  }
  Bitboard operator&(const Bitboard &x) const {
    return Bitboard(a[0] & x.a[0], a[1] & x.a[1], a[2] & x.a[2]);
  }
  Bitboard operator|(const Bitboard &x) const {
    return Bitboard(a[0] | x.a[0], a[1] | x.a[1], a[2] | x.a[2]);
  }
  Bitboard operator+(const Bitboard &x) const {
    return Bitboard(a[0] + x.a[0], a[1] + x.a[1], a[2] + x.a[2]);
  }
  operator bool() const {
    return (a[0] | a[1] | a[2]) != 0;
  }
  void set(int x) {
    a[x >> 6] |= 1ULL << (x & 63);
  }
  bool test(int x) const {
    return a[x >> 6] & 1ULL << (x & 63);
  }
  int pop() const {
    return __builtin_popcountll(a[0]) + __builtin_popcountll(a[1]) + __builtin_popcountll(a[2]);
  }
  union {
    u64 a[3];
    u16 b[12];
  };
};

class Position
{
public:
  Position(int m, int n)
  : m(m), n(n), side2move(BLACK)
    , w(0, 0, 0), b(0, 0, 0) {}
  void play(Move x) {
    (side2move == WHITE ? w : b).set(x);
    side2move = side2move == WHITE ? BLACK : WHITE;
  }
  int gen_moves(Move moves[]) const {
    Bitboard occ = w | b;
    occ = occ + Bitboard(0x0001000100010001ULL, 0x0001000100010001ULL, 0x0001000100010001ULL);
    int cnt = 0;
    REP(y, n) {
      int top = __builtin_ctz(occ.b[y]);
      if (top < m) {
        moves[y] = top + 16 * y;
        cnt++;
      } else
        moves[y] = NULL_MOVE;
    }
    return cnt;
  }
  Status status() const {
    if (win(w)) return side2move == WHITE ? WIN : LOSE;
    if (win(b)) return side2move == BLACK ? WIN : LOSE;
    return (w | b).pop() == m * n ? DRAW : UNDETERMINED;
  }
  static bool win(const Bitboard &w) {
    Bitboard vert = w & w >> 1 & w >> 2 & w >> 3;
    Bitboard hori = w & w >> 16 & w >> 32 & w >> 48;
    Bitboard bslash = w & w >> 15 & w >> 30 & w >> 45;
    Bitboard slash = w & w >> 17 & w >> 34 & w >> 51;
    return (hori | vert | bslash | slash).pop() > 0;
  }
  void dump() const {
    REP(i, n)
      printf("%d", i%10);
    putchar('\n');
    ROF(i, 0, m) {
      REP(j, n) {
        int t = j*16+i;
        if (b.test(t))
          putchar('o');
        else if (w.test(t))
          putchar('x');
        else
          putchar('.');
      }
      putchar('\n');
    }
  }
  Color side2move;
  int m, n;
  Bitboard w, b;
};

class Node;
Node *pool = NULL;
int alloc, pool_cap = 0;

class Node
{
public:
  Node(const Position &pos) : score(0), visited(0) {
    Status end = pos.status();
    if (end != UNDETERMINED)
      nuntried = 0;
    else
      nuntried = pos.gen_moves(moves);
    memset(ch, 0xFF, sizeof ch);
  }
  static void init(size_t cap) {
    pool_cap = cap;
    pool = (Node *)malloc(sizeof(Node) * cap);
    if (! pool)
      err(EX_OSERR, "malloc");
  }
  void *operator new(size_t) {
    if (alloc == pool_cap) {
      pool_cap = size_t(pool_cap * 1.3);
      pool = (Node *)realloc(pool, sizeof(Node) * pool_cap);
      if (! pool)
        err(EX_OSERR, "realloc");
    }
    return &pool[alloc++];
  }
  int opt_child() const {
    int opt = -1;
    float optScore = -1;
    REP(i, MAXN)
      if (ch[i] >= 0) {
        float score = pool[ch[i]].score * -0.5f / pool[ch[i]].visited +
          sqrt(2 * log(float(visited)) / pool[ch[i]].visited);
        if (score > optScore) {
          optScore = score;
          opt = i;
        }
      }
    return opt;
  }
  int ch[MAXN];
  Move moves[MAXN];
  int nuntried, score, visited;
};

Move MCTS(const Position &pos, Move lastMove)
{
  struct timespec start, now;
  if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start) < 0)
    err(EX_OSERR, "clock_gettime CLOCK_THREAD_CPUTIME_ID");
  int n = pos.n, m = pos.m;
  if (pool == NULL)
    Node::init(40000);
  alloc = 0;
  int root = new Node(pos) - pool, path[MAXM*MAXN+1];

  for (int _ = 0; ; _++) {
    int npath = 0, p = root;
    Position pos2 = pos;
    path[npath++] = p;

    // select
    while (pool[p].nuntried == 0) {
      int idx = pool[p].opt_child();
      if (idx < 0) break;
      pos2.play(pool[p].moves[idx]);
      p = pool[p].ch[idx];
      path[npath++] = p;
    }

    // expand
    if (pool[p].nuntried > 0)
      for (int i = rand() % n; ; ) {
        if (pool[p].ch[i] == -1 && pool[p].moves[i] != NULL_MOVE) {
          pos2.play(pool[p].moves[i]);
          pool[p].nuntried--;
          pool[p].ch[i] = new Node(pos2) - pool;
          p = pool[p].ch[i];
          path[npath++] = p;
          break;
        }
        if (++i == n) i = 0;
      }

    // play out
    Status end;
    Move moves[MAXN];
    int side2move = pos2.side2move, nn = 0;
    pos2.gen_moves(moves);
    REP(i, n)
      if (moves[i] != NULL_MOVE)
        moves[nn++] = moves[i];
    while ((end = pos2.status()) == UNDETERMINED) {
      int i = rand() % nn;
      pos2.play(moves[i]);
      if (++moves[i] % 16 >= m)
        moves[i] = moves[--nn];
    }
    int delta = end == DRAW ? 1 : end == (pos2.side2move == side2move ? WIN : LOSE) ? 2 : 0;

    // backpropagate
    while (npath > 0) {
      p = path[--npath];
      pool[p].score += delta;
      pool[p].visited++;
      delta = 2 - delta;
    }

    if (_ % 256 == 0) {
      if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &now) < 0)
        err(EX_OSERR, "clock_gettime CLOCK_THREAD_CPUTIME_ID");
      if (now.tv_sec-start.tv_sec+(now.tv_nsec-start.tv_nsec)*1e-9 > opt_cpu_sec)
        break;
    }
  }

  Move opt_move = NULL_MOVE;
  int opt_visited = 0;
  REP(i, n)
    if (pool[root].moves[i] != NULL_MOVE) {
      opt_move = pool[root].moves[i];
      break;
    }
  REP(i, n)
    if (pool[root].ch[i] >= 0 && pool[pool[root].ch[i]].visited > opt_visited) {
      opt_visited = pool[pool[root].ch[i]].visited;
      opt_move = pool[root].moves[i];
    }
  return opt_move;
}

void sigalrm(int)
{
  puts("\ntimeout");
  exit(EX_NOINPUT);
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
  set_timer(opt_pow_sec);
  REP(i, opt_pow_nonce)
    proof[i] = 'a'+rand()%26;
  int proof_len = sizeof proof-1-opt_pow_nonce;
  printf("I would like some proof of work. Send me a string starting with '%s', no whitespace, of length <= %zd, such that its sha256 in binary starts with %d bits of zeros.\n", proof, sizeof proof-1, opt_pow_bits);
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
  close(fd);
  setbuf(stdout, NULL);
  signal(SIGALRM, sigalrm);
  srand(time(NULL));
  setup_seccomp();

  printf("BetaFour\n\nShall we play %d games? You need to score %d or more (win=2; draw=1; lose=0) to get the flag. Each move should be made in %lg seconds. 0~%d are allowed for the column number. Good luck!\n", opt_games, opt_passing_score, opt_human_sec, MAXN-1);
#ifdef POW
  if (opt_pow_bits)
    proof_of_work();
#endif

  int score = 0;
  REP(game, opt_games) {
    printf("\n\n### Game %d ###\n", game);
    int m = MAXM, n = MAXN, turn = game % 2, last = -1;
    Position pos(m, n);
    printf("You play %s.\n", turn ? "white(x)" : "black(o)");
    for (; ; turn ^= 1) {
      if (turn)
        last = MCTS(pos, last);
      else {
        int column;
        pos.dump();
        printf("Column? ");
        set_timer(opt_human_sec);
        if (scanf("%d", &column) != 1 || ! (0 <= column && column < n))
          errx(EX_DATAERR, "Invalid column");
        set_timer(0);
        Move moves[MAXN];
        pos.gen_moves(moves);
        if (moves[column] == NULL_MOVE)
          errx(EX_DATAERR, "Column %d is full", column);
        last = moves[column];
      }
      pos.play(last);
      int r = pos.status();
      if (r == DRAW) {
        pos.dump();
        puts("Draw");
        score++;
        break;
      } else if (r == LOSE) {
        pos.dump();
        printf("You %s!\n", turn ? "lose" : "win");
        if (! turn)
          score += 2;
        break;
      }
    }
    printf("Score: %d\n", score);
  }

  if (score >= opt_passing_score)
    puts("The flag is: BCTF{no_c++1y_because_this_is_a_damn_windows_project_ArtificialIntelligence2013Spring}");
  else
    printf("You need to score %d or more to get the flag.\n", opt_passing_score);
}

void print_help(FILE *fh)
{
  fprintf(fh, "Usage: %s [OPTIONS]\n", program_invocation_short_name);
  fputs(
        "\n"
        "Options:\n"
        "  --cpu-time        thinking time for each move (seconds in CPU time) (default: 0.3)\n"
        "  --games           number of games\n"
        "  --human-time      time for human for each move (seconds in wall clock time) (double: 4.0)\n"
        "  --passing-score   passing score to get the flag\n"
        "  --port            listening port\n"
        "  --pow-bits        proof of work: number of leading zero bits\n"
        "  --pow-time        proof of work: wait for $pow-time seconds\n"
        "  --help            display this help and exit\n"
        ""
        , fh);
  exit(fh == stdout ? 0 : EX_USAGE);
}

int main(int argc, char *argv[])
{
  int opt;
  static struct option long_options[] = {
    {"cpu-time",        required_argument,  0,   't'},
    {"games",           required_argument,  0,   'g'},
    {"human-time",      required_argument,  0,   'T'},
    {"passing-score",   required_argument,  0,   's'},
    {"port",            required_argument,  0,   'p'},
#ifdef POW
    {"pow-bits",        required_argument,  0,   1},
    {"pow-time",        required_argument,  0,   2},
#endif
    {0,                 0,                  0,   0},
  };
  while ((opt = getopt_long(argc, argv, "hg:p:s:t:T:", long_options, NULL)) != -1) {
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
    case 'g':
      opt_games = get_int(optarg, GN_POSITIVE);
      break;
    case 'p':
      opt_port = get_int(optarg, GN_POSITIVE);
      break;
    case 's':
      opt_passing_score = get_int(optarg, GN_POSITIVE);
      break;
    case 't':
      opt_cpu_sec = get_double(optarg, GN_POSITIVE);
      break;
    case 'T':
      opt_human_sec = get_double(optarg, GN_POSITIVE);
      break;
    case '?':
      print_help(stderr);
      break;
    }
  }
  if (opt_port >= 65536)
    errx(EX_USAGE, "Prerequisite not satisfied: 0 < port < 65536");
  if (! (opt_passing_score <= 2*opt_games))
    err(EX_USAGE, "Prerequisite not satisfied: 0 < required_score <= 2*games");

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
}
