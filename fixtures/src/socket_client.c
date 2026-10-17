/* socket_client: a TCP client that connects to a fixed address and port. */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "fixture.h"

NOIPA int connect_to(const char *ip, uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

NOIPA int send_hello(int fd) {
    static const char msg[] = "HELLO ghidorah\r\n";
    char reply[64];
    if (send(fd, msg, sizeof msg - 1, 0) < 0) {
        return -1;
    }
    ssize_t n = recv(fd, reply, sizeof reply - 1, 0);
    if (n <= 0) {
        return -1;
    }
    reply[n] = '\0';
    return puts(reply);
}

int main(void) {
    int fd = connect_to("127.0.0.1", 8080);
    if (fd < 0) {
        puts("connect failed");
        return 1;
    }
    send_hello(fd);
    close(fd);
    return 0;
}
