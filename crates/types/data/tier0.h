/* The Tier-0 prototypes of ghidorah (design Section 9.4).
 *
 * Source: hand-written for ghidorah from the C standard, POSIX and the glibc manual pages.
 * The file holds no text of a third-party header. License: Apache-2.0, as a part of ghidorah.
 *
 * Format: one prototype on each line in the `sig` mode of the C parser, then a line comment.
 * The comment starts with the category: file, network, process, memory, string, crypto,
 * environment, anti_debug, time or io. Attributes follow, separated by spaces:
 *   noreturn            the function does not return
 *   fmt(printf,N)       parameter N is a printf format string
 *   fmt(scanf,N)        parameter N is a scanf format string
 *   nonnull(N,...)      the parameters must not be null
 *   reads_str(N)        the function reads parameter N as a C string
 *   writes(N) writes(N,M) the function writes the buffer of parameter N, with the length in M
 *   allocates           the function returns new heap memory
 *   returns_arg(N)      the function returns parameter N
 *   alias(a,b,...)      linked names with the same prototype
 * Parameter numbers start at 1. Lines inside a block comment are comments.
 */

int printf(const char *format, ...); // io fmt(printf,1) nonnull(1)
int fprintf(FILE *stream, const char *format, ...); // io fmt(printf,2) nonnull(1,2)
int dprintf(int fd, const char *format, ...); // io fmt(printf,2)
int sprintf(char *str, const char *format, ...); // string fmt(printf,2) writes(1)
int snprintf(char *str, size_t size, const char *format, ...); // string fmt(printf,3) writes(1,2)
int vprintf(const char *format, va_list ap); // io fmt(printf,1)
int vfprintf(FILE *stream, const char *format, va_list ap); // io fmt(printf,2)
int vsprintf(char *str, const char *format, va_list ap); // string fmt(printf,2) writes(1)
int vsnprintf(char *str, size_t size, const char *format, va_list ap); // string fmt(printf,3) writes(1,2)
int scanf(const char *format, ...); // io fmt(scanf,1) alias(__isoc99_scanf,__isoc23_scanf)
int fscanf(FILE *stream, const char *format, ...); // io fmt(scanf,2) alias(__isoc99_fscanf,__isoc23_fscanf)
int sscanf(const char *str, const char *format, ...); // string fmt(scanf,2) reads_str(1) alias(__isoc99_sscanf,__isoc23_sscanf)
int puts(const char *s); // io reads_str(1) nonnull(1)
int fputs(const char *s, FILE *stream); // io reads_str(1) nonnull(1,2)
int putchar(int c); // io
int fputc(int c, FILE *stream); // io
int putc(int c, FILE *stream); // io alias(_IO_putc)
int getchar(void); // io
int fgetc(FILE *stream); // io
int getc(FILE *stream); // io alias(_IO_getc)
int ungetc(int c, FILE *stream); // io
char *fgets(char *s, int size, FILE *stream); // io writes(1,2) returns_arg(1)
char *gets(char *s); // io writes(1) returns_arg(1)
ssize_t getline(char **lineptr, size_t *n, FILE *stream); // io allocates
FILE *fopen(const char *pathname, const char *mode); // file reads_str(1) reads_str(2) alias(fopen64)
FILE *fdopen(int fd, const char *mode); // file reads_str(2)
FILE *freopen(const char *pathname, const char *mode, FILE *stream); // file reads_str(1) alias(freopen64)
int fclose(FILE *stream); // file
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream); // file writes(1)
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream); // file
int fseek(FILE *stream, long offset, int whence); // file alias(fseeko,fseeko64)
long ftell(FILE *stream); // file alias(ftello,ftello64)
void rewind(FILE *stream); // file
int fflush(FILE *stream); // io
int setvbuf(FILE *stream, char *buf, int mode, size_t size); // io
void perror(const char *s); // io reads_str(1)
int remove(const char *pathname); // file reads_str(1)
int rename(const char *oldpath, const char *newpath); // file reads_str(1) reads_str(2)
FILE *popen(const char *command, const char *type); // process reads_str(1)
int pclose(FILE *stream); // process
int feof(FILE *stream); // file
int ferror(FILE *stream); // file
int fileno(FILE *stream); // file
FILE *tmpfile(void); // file alias(tmpfile64)
int open(const char *pathname, int flags, ...); // file reads_str(1) alias(open64,__open_2,__open64_2)
int openat(int dirfd, const char *pathname, int flags, ...); // file reads_str(2) alias(openat64)
int creat(const char *pathname, mode_t mode); // file reads_str(1) alias(creat64)
int close(int fd); // file
ssize_t read(int fd, void *buf, size_t count); // io writes(2,3)
ssize_t write(int fd, const void *buf, size_t count); // io
off_t lseek(int fd, off_t offset, int whence); // file alias(lseek64)
ssize_t pread(int fd, void *buf, size_t count, off_t offset); // io writes(2,3) alias(pread64)
ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset); // io alias(pwrite64)
int unlink(const char *pathname); // file reads_str(1)
int mkdir(const char *pathname, mode_t mode); // file reads_str(1)
int rmdir(const char *pathname); // file reads_str(1)
int chdir(const char *path); // file reads_str(1)
int chroot(const char *path); // file reads_str(1)
char *getcwd(char *buf, size_t size); // file writes(1,2) returns_arg(1)
int access(const char *pathname, int mode); // file reads_str(1)
int chmod(const char *pathname, mode_t mode); // file reads_str(1)
int chown(const char *pathname, uid_t owner, gid_t group); // file reads_str(1)
int stat(const char *pathname, struct stat *statbuf); // file reads_str(1) alias(stat64)
int fstat(int fd, struct stat *statbuf); // file alias(fstat64)
int lstat(const char *pathname, struct stat *statbuf); // file reads_str(1) alias(lstat64)
int dup(int oldfd); // file
int dup2(int oldfd, int newfd); // file
int pipe(int pipefd[2]); // process
int fcntl(int fd, int cmd, ...); // file alias(fcntl64)
int ioctl(int fd, unsigned long request, ...); // io
ssize_t readlink(const char *pathname, char *buf, size_t bufsiz); // file reads_str(1) writes(2,3)
int symlink(const char *target, const char *linkpath); // file reads_str(1) reads_str(2)
int truncate(const char *path, off_t length); // file reads_str(1) alias(truncate64)
int ftruncate(int fd, off_t length); // file alias(ftruncate64)
int fsync(int fd); // file
int mkstemp(char *template); // file writes(1) alias(mkstemp64)
DIR *opendir(const char *name); // file reads_str(1)
struct dirent *readdir(DIR *dirp); // file alias(readdir64)
int closedir(DIR *dirp); // file
int isatty(int fd); // io
int poll(struct pollfd *fds, nfds_t nfds, int timeout); // io
int epoll_create1(int flags); // io
int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout); // io
int inotify_init(void); // file
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset); // memory alias(mmap64)
int munmap(void *addr, size_t length); // memory
int mprotect(void *addr, size_t len, int prot); // memory
void *malloc(size_t size); // memory allocates
void *calloc(size_t nmemb, size_t size); // memory allocates
void *realloc(void *ptr, size_t size); // memory allocates
void *reallocarray(void *ptr, size_t nmemb, size_t size); // memory allocates
void free(void *ptr); // memory
void *aligned_alloc(size_t alignment, size_t size); // memory allocates
int posix_memalign(void **memptr, size_t alignment, size_t size); // memory allocates nonnull(1)
void *memcpy(void *dest, const void *src, size_t n); // memory nonnull(1,2) writes(1,3) returns_arg(1)
void *memmove(void *dest, const void *src, size_t n); // memory nonnull(1,2) writes(1,3) returns_arg(1)
void *memset(void *s, int c, size_t n); // memory nonnull(1) writes(1,3) returns_arg(1)
int memcmp(const void *s1, const void *s2, size_t n); // memory nonnull(1,2)
void *memchr(const void *s, int c, size_t n); // memory nonnull(1)
void qsort(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *)); // memory
void *bsearch(const void *key, const void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *)); // memory
size_t strlen(const char *s); // string nonnull(1) reads_str(1)
size_t strnlen(const char *s, size_t maxlen); // string
char *strcpy(char *dest, const char *src); // string nonnull(1,2) writes(1) reads_str(2) returns_arg(1)
char *strncpy(char *dest, const char *src, size_t n); // string nonnull(1,2) writes(1,3) returns_arg(1)
char *stpcpy(char *dest, const char *src); // string nonnull(1,2) writes(1) reads_str(2)
char *strcat(char *dest, const char *src); // string nonnull(1,2) writes(1) reads_str(2) returns_arg(1)
char *strncat(char *dest, const char *src, size_t n); // string nonnull(1,2) writes(1) returns_arg(1)
int strcmp(const char *s1, const char *s2); // string nonnull(1,2) reads_str(1) reads_str(2)
int strncmp(const char *s1, const char *s2, size_t n); // string nonnull(1,2)
int strcasecmp(const char *s1, const char *s2); // string reads_str(1) reads_str(2)
int strncasecmp(const char *s1, const char *s2, size_t n); // string
int strcoll(const char *s1, const char *s2); // string reads_str(1) reads_str(2)
char *strchr(const char *s, int c); // string reads_str(1)
char *strrchr(const char *s, int c); // string reads_str(1)
char *strstr(const char *haystack, const char *needle); // string reads_str(1) reads_str(2)
char *strdup(const char *s); // string allocates reads_str(1)
char *strndup(const char *s, size_t n); // string allocates
char *strtok(char *str, const char *delim); // string reads_str(2)
char *strtok_r(char *str, const char *delim, char **saveptr); // string reads_str(2)
size_t strspn(const char *s, const char *accept); // string reads_str(1) reads_str(2)
size_t strcspn(const char *s, const char *reject); // string reads_str(1) reads_str(2)
char *strpbrk(const char *s, const char *accept); // string reads_str(1) reads_str(2)
char *strerror(int errnum); // string
long strtol(const char *nptr, char **endptr, int base); // string reads_str(1) alias(__isoc23_strtol)
unsigned long strtoul(const char *nptr, char **endptr, int base); // string reads_str(1) alias(__isoc23_strtoul)
long long strtoll(const char *nptr, char **endptr, int base); // string reads_str(1) alias(__isoc23_strtoll)
unsigned long long strtoull(const char *nptr, char **endptr, int base); // string reads_str(1) alias(__isoc23_strtoull)
double strtod(const char *nptr, char **endptr); // string reads_str(1)
int atoi(const char *nptr); // string reads_str(1)
long atol(const char *nptr); // string reads_str(1)
double atof(const char *nptr); // string reads_str(1)
int tolower(int c); // string
int toupper(int c); // string
int isalpha(int c); // string
int isdigit(int c); // string
int isspace(int c); // string
int isprint(int c); // string
_Noreturn void exit(int status); // process noreturn
_Noreturn void _exit(int status); // process noreturn
_Noreturn void _Exit(int status); // process noreturn
_Noreturn void abort(void); // process noreturn
_Noreturn void quick_exit(int status); // process noreturn
int atexit(void (*function)(void)); // process
pid_t fork(void); // process
pid_t vfork(void); // process
int execve(const char *pathname, char *const argv[], char *const envp[]); // process reads_str(1)
int execv(const char *pathname, char *const argv[]); // process reads_str(1)
int execvp(const char *file, char *const argv[]); // process reads_str(1)
int execl(const char *pathname, const char *arg, ...); // process reads_str(1)
int execlp(const char *file, const char *arg, ...); // process reads_str(1)
int system(const char *command); // process reads_str(1)
pid_t wait(int *wstatus); // process
pid_t waitpid(pid_t pid, int *wstatus, int options); // process
int kill(pid_t pid, int sig); // process
int raise(int sig); // process
pid_t getpid(void); // process
pid_t getppid(void); // process
uid_t getuid(void); // process
uid_t geteuid(void); // process
gid_t getgid(void); // process
int setuid(uid_t uid); // process
int setgid(gid_t gid); // process
void (*signal(int signum, void (*handler)(int)))(int); // process alias(sysv_signal,bsd_signal)
int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact); // process
int setjmp(jmp_buf env); // process alias(_setjmp)
_Noreturn void longjmp(jmp_buf env, int val); // process noreturn alias(_longjmp)
_Noreturn void siglongjmp(sigjmp_buf env, int val); // process noreturn
int prctl(int option, ...); // process
long syscall(long number, ...); // process
int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg); // process
int pthread_join(pthread_t thread, void **retval); // process
int pthread_detach(pthread_t thread); // process
_Noreturn void pthread_exit(void *retval); // process noreturn
int pthread_mutex_lock(pthread_mutex_t *mutex); // process
int pthread_mutex_unlock(pthread_mutex_t *mutex); // process
int sched_yield(void); // process
void *dlopen(const char *filename, int flags); // process reads_str(1)
void *dlsym(void *handle, const char *symbol); // process reads_str(2)
int dlclose(void *handle); // process
int __libc_start_main(int (*main)(int, char **, char **), int argc, char **argv, void (*init)(void), void (*fini)(void), void (*rtld_fini)(void), void *stack_end); // process
int *__errno_location(void); // process
int __cxa_atexit(void (*func)(void *), void *arg, void *dso_handle); // process
void __cxa_finalize(void *d); // process
_Noreturn void __stack_chk_fail(void); // process noreturn
_Noreturn void __assert_fail(const char *assertion, const char *file, unsigned int line, const char *function); // process noreturn
long ptrace(int request, ...); // anti_debug
char *getenv(const char *name); // environment reads_str(1)
char *secure_getenv(const char *name); // environment reads_str(1)
int setenv(const char *name, const char *value, int overwrite); // environment reads_str(1) reads_str(2)
int unsetenv(const char *name); // environment reads_str(1)
int putenv(char *string); // environment reads_str(1)
int gethostname(char *name, size_t len); // environment writes(1,2)
int uname(struct utsname *buf); // environment
struct passwd *getpwnam(const char *name); // environment reads_str(1)
struct passwd *getpwuid(uid_t uid); // environment
char *getlogin(void); // environment
long sysconf(int name); // environment
int getopt(int argc, char *const argv[], const char *optstring); // environment reads_str(3)
char *setlocale(int category, const char *locale); // environment
time_t time(time_t *tloc); // time
int clock_gettime(clockid_t clockid, struct timespec *tp); // time
int gettimeofday(struct timeval *tv, void *tz); // time
clock_t clock(void); // time
struct tm *localtime(const time_t *timep); // time
struct tm *gmtime(const time_t *timep); // time
time_t mktime(struct tm *tm); // time
size_t strftime(char *s, size_t max, const char *format, const struct tm *tm); // time writes(1,2) reads_str(3)
double difftime(time_t time1, time_t time0); // time
unsigned int sleep(unsigned int seconds); // time
int usleep(useconds_t usec); // time
int nanosleep(const struct timespec *req, struct timespec *rem); // time
unsigned int alarm(unsigned int seconds); // time
int socket(int domain, int type, int protocol); // network
int socketpair(int domain, int type, int protocol, int sv[2]); // network
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen); // network
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen); // network
int listen(int sockfd, int backlog); // network
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen); // network
int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags); // network
ssize_t send(int sockfd, const void *buf, size_t len, int flags); // network
ssize_t recv(int sockfd, void *buf, size_t len, int flags); // network writes(2,3)
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen); // network
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen); // network writes(2,3)
int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen); // network
int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen); // network
int shutdown(int sockfd, int how); // network
int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout); // network
uint16_t htons(uint16_t hostshort); // network
uint16_t ntohs(uint16_t netshort); // network
uint32_t htonl(uint32_t hostlong); // network
uint32_t ntohl(uint32_t netlong); // network
in_addr_t inet_addr(const char *cp); // network reads_str(1)
int inet_aton(const char *cp, struct in_addr *inp); // network reads_str(1)
char *inet_ntoa(struct in_addr in); // network
int inet_pton(int af, const char *src, void *dst); // network reads_str(2)
const char *inet_ntop(int af, const void *src, char *dst, socklen_t size); // network writes(3,4) returns_arg(3)
struct hostent *gethostbyname(const char *name); // network reads_str(1)
int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res); // network
void freeaddrinfo(struct addrinfo *res); // network
char *crypt(const char *key, const char *salt); // crypto reads_str(1) reads_str(2)
int rand(void); // crypto
void srand(unsigned int seed); // crypto
long random(void); // crypto
void srandom(unsigned int seed); // crypto
ssize_t getrandom(void *buf, size_t buflen, unsigned int flags); // crypto writes(1,2)
uint32_t arc4random(void); // crypto
_Noreturn void err(int eval, const char *fmt, ...); // io noreturn fmt(printf,2)
_Noreturn void errx(int eval, const char *fmt, ...); // io noreturn fmt(printf,2)
void warn(const char *fmt, ...); // io fmt(printf,1)
void warnx(const char *fmt, ...); // io fmt(printf,1)
void syslog(int priority, const char *format, ...); // io fmt(printf,2)
int __printf_chk(int flag, const char *format, ...); // io fmt(printf,2)
int __fprintf_chk(FILE *stream, int flag, const char *format, ...); // io fmt(printf,3)
int __sprintf_chk(char *s, int flag, size_t slen, const char *format, ...); // string fmt(printf,4) writes(1,3)
int __snprintf_chk(char *s, size_t maxlen, int flag, size_t slen, const char *format, ...); // string fmt(printf,5) writes(1,2)
int __vfprintf_chk(FILE *stream, int flag, const char *format, va_list ap); // io fmt(printf,3)
void *__memcpy_chk(void *dest, const void *src, size_t len, size_t destlen); // memory writes(1,3) returns_arg(1)
void *__memmove_chk(void *dest, const void *src, size_t len, size_t destlen); // memory writes(1,3) returns_arg(1)
void *__memset_chk(void *s, int c, size_t len, size_t destlen); // memory writes(1,3) returns_arg(1)
char *__strcpy_chk(char *dest, const char *src, size_t destlen); // string writes(1,3) reads_str(2) returns_arg(1)
char *__strncpy_chk(char *dest, const char *src, size_t len, size_t destlen); // string writes(1,3) returns_arg(1)
char *__strcat_chk(char *dest, const char *src, size_t destlen); // string writes(1,3) reads_str(2) returns_arg(1)
ssize_t __read_chk(int fd, void *buf, size_t nbytes, size_t buflen); // io writes(2,3)
char *__fgets_chk(char *s, size_t size, int n, FILE *stream); // io writes(1,2) returns_arg(1)
