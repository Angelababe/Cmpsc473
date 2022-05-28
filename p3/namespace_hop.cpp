#include <atomic>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <string>

#include "namespace_hop.h"
#include "log.h"

static int recv_file_descriptor(int socket)
{
  char data[1] = {0};

  struct iovec iov[1] = {{0}};
  iov[0].iov_base = data;
  iov[0].iov_len = sizeof(data);

  char ctrl_buf[CMSG_SPACE(sizeof(int))] = {0};

  struct msghdr message = {0};
  message.msg_name = NULL;
  message.msg_namelen = 0;
  message.msg_control = ctrl_buf;
  message.msg_controllen = CMSG_SPACE(sizeof(int));
  message.msg_iov = iov;
  message.msg_iovlen = 1;

  int res = ::recvmsg(socket, &message, 0);
  if (res <= 0)
  {
    TRC_WARNING("Failed to retrieve cross-namespace socket - recvmsg returned %d (%d %s)", res, errno, strerror(errno));
    return -1;
  }

  struct cmsghdr *control_message = NULL;
  for (control_message = CMSG_FIRSTHDR(&message);
       control_message != NULL;
       control_message = CMSG_NXTHDR(&message, control_message))
  {
    if ((control_message->cmsg_level == SOL_SOCKET) &&
        (control_message->cmsg_type == SCM_RIGHTS))
    {
      return *((int*)CMSG_DATA(control_message));
    }
  }

  TRC_ERROR("No cross-namespace socket received\n");
  return -1;
}

int create_connection_in_namespace(const char* host,
                                   const char* port,
                                   const char* socket_factory_path)
{
  std::string target = (host + std::string(":") + port);

  TRC_DEBUG("Get cross-namespace socket to %s via %s",
            target.c_str(),
            socket_factory_path);
  
  struct sockaddr_un addr = {AF_LOCAL};
  size_t sfp_size = strlen(socket_factory_path) + 1;
  size_t asp_size = sizeof(addr.sun_path);
  size_t max_chars = std::min(asp_size, sfp_size);

  TRC_DEBUG("Size of path is: %d, size of addr.sun_path: %d, max_chars: %d",
            sfp_size,
            asp_size,
            max_chars);

  strncpy(addr.sun_path, socket_factory_path, max_chars);
  int fd = socket(AF_LOCAL, SOCK_STREAM, 0);

  if (fd < 0)
  {
    TRC_ERROR("Failed to create client socket to cross-namespace socket factory");
    return fd;
  }

  int ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
  if (ret != 0)
  {
    int err = errno;
    TRC_ERROR("Failed to connect to cross-namespace socket factory %s on FD: %d with result: %d and error: %d - 0x%x - %s",
              socket_factory_path,
              fd,
              ret,
              err,
              err,
              strerror(err));
    return -1;
  }


  ret = send(fd, target.c_str(), target.size(), 0);
  if (ret < 0)
  {
    TRC_ERROR("Error sending target '%s' to %s: %s",
              target.c_str(),
              socket_factory_path,
              strerror(errno));
    return -2;
  }

  return recv_file_descriptor(fd);
}


int create_connection_in_signaling_namespace(const char* host,
                                             const char* port)
{
  return create_connection_in_namespace(host,
                                        port,
                                        "/tmp/clearwater_signaling_namespace_socket");
}

int create_connection_in_management_namespace(const char* host,
                                              const char* port)
{
  return create_connection_in_namespace(host,
                                        port,
                                        "/tmp/clearwater_management_namespace_socket");
}
