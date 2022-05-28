#include <atomic>

// C header files must be included with C linkage to prevent name mangling.
extern "C" {
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <poll.h>
}

#include <atomic>
#include "utils.h"

static void on_library_load() __attribute__((constructor));

void on_library_load() {
  printf("*** IO trap loaded ***\n");
  printf("Unsetting LD_PRELOAD environment variable\n");
  unsetenv("LD_PRELOAD");
}

static void about_to_block()
{
  if (!Utils::IOMonitor::thread_doing_overt_io() &&
      !Utils::IOMonitor::thread_allows_covert_io())
  {
    fprintf(stderr, "Trapping disallowed I/o - abort\n"); fflush(stderr);
    abort();
  }
}

#define RETURN_CALL_REAL_FUNCTION(FUNCTION, ...)                               \
  do {                                                                         \
    using FunctionType = decltype(&FUNCTION);                                  \
    static std::atomic<FunctionType> func(nullptr);                            \
    if (!func)                                                                 \
    {                                                                          \
      func = (FunctionType)dlsym(RTLD_NEXT, #FUNCTION);                        \
    }                                                                          \
    return (*func)(__VA_ARGS__);                                               \
  } while (0)


#define HANDLE_NON_FD_CALL(FUNCTION, ...)                                      \
  do {                                                                         \
    about_to_block();                                                          \
    RETURN_CALL_REAL_FUNCTION(FUNCTION, __VA_ARGS__);                          \
  } while (0)

#define HANDLE_FD_CALL(FUNCTION, FD, ...)                                      \
  do {                                                                         \
    if ((fcntl((FD), F_GETFL) & O_NONBLOCK) == 0)                              \
    {                                                                          \
      about_to_block();                                                        \
    }                                                                          \
                                                                               \
    RETURN_CALL_REAL_FUNCTION(FUNCTION, FD, __VA_ARGS__);                      \
  } while (0)



extern "C" ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
  HANDLE_FD_CALL(recv, sockfd, buf, len, flags);
}

extern "C" ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                            struct sockaddr *dest_addr, socklen_t* addrlen)
{
  HANDLE_FD_CALL(recvfrom, sockfd, buf, len, flags, dest_addr, addrlen);
}

extern "C" ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags)
{
  HANDLE_FD_CALL(recvmsg, sockfd, msg, flags);
}

extern "C" ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
  HANDLE_FD_CALL(send, sockfd, buf, len, flags);
}

extern "C" ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
                          const struct sockaddr *dest_addr, socklen_t addrlen)
{
  HANDLE_FD_CALL(sendto, sockfd, buf, len, flags, dest_addr, addrlen);
}

extern "C" ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
  HANDLE_FD_CALL(sendmsg, sockfd, msg, flags);
}

extern "C" int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
  HANDLE_FD_CALL(connect, sockfd, addr, addrlen);
}

extern "C" int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
  HANDLE_FD_CALL(accept, sockfd, addr, addrlen);
}

extern "C" int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
  HANDLE_FD_CALL(accept4, sockfd, addr, addrlen, flags);
}

extern "C" int select(int nfds, fd_set *readfds, fd_set *writefds,
                      fd_set *exceptfds, struct timeval *timeout)
{
  HANDLE_NON_FD_CALL(select, nfds, readfds, writefds, exceptfds, timeout);
}

extern "C" int pselect(int nfds, fd_set *readfds, fd_set *writefds,
                       fd_set *exceptfds, const struct timespec *timeout,
                       const sigset_t *sigmask)
{
  HANDLE_NON_FD_CALL(pselect, nfds, readfds, writefds, exceptfds, timeout, sigmask);
}

extern "C" int epoll_wait(int epfd, struct epoll_event *events,
                          int maxevents, int timeout)
{
  HANDLE_NON_FD_CALL(epoll_wait, epfd, events, maxevents, timeout);
}

extern "C" int epoll_pwait(int epfd, struct epoll_event *events,
                           int maxevents, int timeout,
                           const sigset_t *sigmask)
{
  HANDLE_NON_FD_CALL(epoll_pwait, epfd, events, maxevents, timeout, sigmask);
}

extern "C" int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
  HANDLE_NON_FD_CALL(poll, fds, nfds, timeout);
}

extern "C" int ppoll(struct pollfd *fds, nfds_t nfds,
                     const struct timespec *tmo_p, const sigset_t *sigmask)
{
  HANDLE_NON_FD_CALL(ppoll, fds, nfds, tmo_p, sigmask);
}

extern "C" int __poll_chk(struct pollfd *fds, nfds_t nfds, int timeout, __SIZE_TYPE__ fds_len)
{
  HANDLE_NON_FD_CALL(__poll_chk, fds, nfds, timeout, fds_len);
}

extern "C" int __poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
  HANDLE_NON_FD_CALL(__poll, fds, nfds, timeout);
}


