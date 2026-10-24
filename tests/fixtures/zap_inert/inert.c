/* SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
 * SPDX-License-Identifier: Apache-2.0
 * Closed first-party inert fixture. This file contains no bubblewrap source.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/un.h>
#include <unistd.h>

#define QUOTA_BYTES UINT64_C(67108864)
#define QUOTA_INODES UINT64_C(1024)
static const char setup_bytes[] = "1337 ZAP inert setup v1\n";
static const char report_bytes[] = "1337 ZAP inert late-report v1\n";
static const char *aliases[] = {"/home", "/tmp", "/session", "/report", "/dev/shm"};

static volatile sig_atomic_t completion_released = 0;

static void ReleaseCompletion(int selected_signal) {
    if (selected_signal == SIGUSR1) completion_released = 1;
}

static void Refuse(void) {
    if (write(2, "closed inert fixture refused\n", 28) < 0) _exit(4);
    _exit(4);
}

static void Require(int condition) {
    if (!condition) Refuse();
}

static uint16_t U16(const unsigned char *value) {
    return (uint16_t)((value[0] << 8) | value[1]);
}

static void Put64(unsigned char *target, uint64_t value) {
    for (int i = 7; i >= 0; --i) {
        target[i] = (unsigned char)(value & 255);
        value >>= 8;
    }
}

static int PermissionDenied(int result, const char *label, int readonly_write) {
    int observed = errno;
    Require(result == -1 && (observed == EPERM || observed == EACCES ||
        (readonly_write && observed == EROFS)));
    Require(printf("DENIED %s %d\n", label, observed) > 0);
    return observed;
}

static void Lockdown(void) {
    PermissionDenied(mount(NULL, "/work", NULL, MS_REMOUNT | MS_NODEV | MS_NOSUID |
        MS_NOEXEC, "size=134217728,nr_inodes=2048"), "quota-remount", 0);
    PermissionDenied(mount("tmpfs", "/work/tmp", "tmpfs", MS_NODEV | MS_NOSUID |
        MS_NOEXEC, "size=4096,nr_inodes=8,mode=0700"), "new-tmpfs", 0);
    int user_result = unshare(CLONE_NEWUSER);
    int user_error = errno;
    Require(user_result == -1 && (user_error == EPERM || user_error == EACCES ||
        user_error == ENOSPC));
    Require(printf("DENIED new-userns %d\n", user_error) > 0);
    PermissionDenied(unshare(CLONE_NEWNS), "new-mountns", 0);
    PermissionDenied(unshare(CLONE_NEWNET), "new-netns", 0);
    PermissionDenied(open("/forbidden", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600),
        "root-write", 1);
    PermissionDenied(open("/request.bin", O_WRONLY | O_CLOEXEC | O_NOFOLLOW), "input-write", 1);
}

static struct sockaddr_in Address(uint16_t port) {
    struct sockaddr_in result;
    memset(&result, 0, sizeof(result));
    result.sin_family = AF_INET;
    result.sin_port = htons(port);
    result.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return result;
}

static int Network(uint16_t sink_port, uint16_t private_port) {
    int sink = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    Require(sink >= 0);
    struct sockaddr_in sink_address = Address(sink_port);
    int result = connect(sink, (struct sockaddr *)&sink_address, sizeof(sink_address));
    Require(result == -1);
    int error = errno;
    if (error == EINPROGRESS) {
        struct pollfd pending = {.fd = sink, .events = POLLOUT};
        Require(poll(&pending, 1, 500) > 0);
        socklen_t length = sizeof(error);
        Require(getsockopt(sink, SOL_SOCKET, SO_ERROR, &error, &length) == 0);
    }
    Require(error == ECONNREFUSED || error == ENETUNREACH || error == EHOSTUNREACH);
    close(sink);
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    Require(listener >= 0);
    struct sockaddr_in private_address = Address(private_port);
    Require(bind(listener, (struct sockaddr *)&private_address, sizeof(private_address)) == 0);
    Require(listen(listener, 1) == 0);
    int client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    Require(client >= 0);
    Require(connect(client, (struct sockaddr *)&private_address, sizeof(private_address)) == 0);
    int accepted = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    Require(accepted >= 0 && write(client, "I", 1) == 1);
    char byte = 0;
    Require(read(accepted, &byte, 1) == 1 && byte == 'I');
    close(accepted);
    close(client);
    Require(printf("NETWORK host-refused private-connected\n") > 0);
    return listener;
}

static void WriteOriginal(const char *path, const char *bytes, size_t length, int announce) {
    int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    Require(descriptor >= 0 && write(descriptor, bytes, length) == (ssize_t)length);
    Require(fsync(descriptor) == 0);
    struct stat info;
    Require(fstat(descriptor, &info) == 0);
    Require(close(descriptor) == 0);
    if (announce) {
        Require(printf("LATE %ju %ju %ju %ju %ju %ju %ju %ju\n",
            (uintmax_t)info.st_dev, (uintmax_t)info.st_ino, (uintmax_t)info.st_mode,
            (uintmax_t)info.st_uid, (uintmax_t)info.st_nlink, (uintmax_t)info.st_size,
            (uintmax_t)info.st_mtim.tv_sec * UINT64_C(1000000000) + info.st_mtim.tv_nsec,
            (uintmax_t)info.st_ctim.tv_sec * UINT64_C(1000000000) + info.st_ctim.tv_nsec) > 0);
        Require(fflush(stdout) == 0);
    }
}

static ssize_t ReceiveAckPart(int channel, unsigned char *raw, size_t capacity) {
    char ack_control[CMSG_SPACE(16 * sizeof(int))];
    struct iovec ack_iov = {.iov_base = raw, .iov_len = capacity};
    struct msghdr ack_message;
    memset(&ack_message, 0, sizeof(ack_message));
    ack_message.msg_iov = &ack_iov;
    ack_message.msg_iovlen = 1;
    ack_message.msg_control = ack_control;
    ack_message.msg_controllen = sizeof(ack_control);
    ssize_t length = recvmsg(channel, &ack_message, MSG_WAITALL | MSG_CMSG_CLOEXEC);
    Require(length >= 0);
    int extra_control = 0;
    for (struct cmsghdr *item = CMSG_FIRSTHDR(&ack_message); item != NULL;
         item = CMSG_NXTHDR(&ack_message, item)) {
        extra_control = 1;
        if (item->cmsg_level == SOL_SOCKET && item->cmsg_type == SCM_RIGHTS &&
            item->cmsg_len >= CMSG_LEN(0)) {
            size_t control_length = item->cmsg_len - CMSG_LEN(0);
            Require(control_length <= sizeof(ack_control));
            for (size_t offset = 0; offset + sizeof(int) <= control_length; offset += sizeof(int)) {
                int unexpected_fd;
                memcpy(&unexpected_fd, CMSG_DATA(item) + offset, sizeof(unexpected_fd));
                close(unexpected_fd);
            }
        }
    }
    Require(!extra_control && !(ack_message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)));
    return length;
}

static void Ready(const unsigned char *request) {
    int directory = open("/work", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    Require(directory >= 0);
    struct stat info;
    struct statvfs quota;
    Require(fstat(directory, &info) == 0 && fstatvfs(directory, &quota) == 0);
    Require((uint64_t)quota.f_frsize * quota.f_blocks == QUOTA_BYTES &&
        quota.f_files == QUOTA_INODES);
    unsigned char ready[96];
    memcpy(ready, "1337ZRD1", 8);
    memcpy(ready + 8, request + 16, 48);
    Put64(ready + 56, info.st_dev);
    Put64(ready + 64, info.st_ino);
    Put64(ready + 72, quota.f_frsize);
    Put64(ready + 80, quota.f_blocks);
    Put64(ready + 88, quota.f_files);
    int channel = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    Require(channel >= 0);
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, "/control.sock", 14);
    Require(connect(channel, (struct sockaddr *)&address, sizeof(address)) == 0);
    char ancillary[CMSG_SPACE(sizeof(int))];
    memset(ancillary, 0, sizeof(ancillary));
    struct iovec iov = {.iov_base = ready, .iov_len = sizeof(ready)};
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = ancillary;
    message.msg_controllen = sizeof(ancillary);
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &directory, sizeof(directory));
    Require(sendmsg(channel, &message, MSG_NOSIGNAL) == (ssize_t)sizeof(ready));
    close(directory);
    unsigned char ack[57];
    Require(ReceiveAckPart(channel, ack, sizeof(ack)) == 56);
    Require(memcmp(ack, "1337ZAK1", 8) == 0 && memcmp(ack + 8, request + 16, 48) == 0);
    unsigned char eof;
    Require(ReceiveAckPart(channel, &eof, 1) == 0);
    close(channel);
}

static void ByteLimit(void) {
    int descriptors[5];
    char path[64];
    for (int i = 0; i < 5; ++i) {
        Require(snprintf(path, sizeof(path), "%s/bytes", aliases[i]) > 0);
        descriptors[i] = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        Require(descriptors[i] >= 0);
    }
    char page[4096];
    memset(page, 'Q', sizeof(page));
    uint64_t total = 0;
    int exhausted = 0;
    for (uint64_t attempt = 0; attempt <= QUOTA_BYTES / sizeof(page); ++attempt) {
        ssize_t written = write(descriptors[attempt % 5], page, sizeof(page));
        if (written < 0) {
            Require(errno == ENOSPC);
            exhausted = 1;
            break;
        }
        Require(written > 0 && written <= (ssize_t)sizeof(page));
        total += (uint64_t)written;
    }
    for (int i = 0; i < 5; ++i) close(descriptors[i]);
    Require(exhausted && total <= QUOTA_BYTES);
    Require(printf("QUOTA bytes %" PRIu64 " ENOSPC\n", total) > 0);
}

static void InodeLimit(void) {
    char path[96];
    int exhausted = 0;
    unsigned int count = 0;
    for (unsigned int i = 0; i <= 1024; ++i) {
        Require(snprintf(path, sizeof(path), "%s/inode-%04u", aliases[i % 5], i) > 0);
        int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (descriptor < 0) {
            Require(errno == ENOSPC);
            exhausted = 1;
            break;
        }
        close(descriptor);
        count++;
    }
    Require(exhausted && count <= 1024);
    Require(printf("QUOTA inodes %u ENOSPC\n", count) > 0);
}

int main(int argc, char **argv) {
    Require(argc == 2 && strcmp(argv[1], "/request.bin") == 0);
    Require(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1);
    for (int descriptor = 3; descriptor < 256; ++descriptor) {
        errno = 0;
        Require(fcntl(descriptor, F_GETFD) == -1 && errno == EBADF);
    }
    int input = open("/request.bin", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    Require(input >= 0);
    unsigned char request[65];
    Require(read(input, request, sizeof(request)) == 64);
    close(input);
    Require(memcmp(request, "1337ZIP1", 8) == 0 && request[8] <= 4 && request[9] == 0 &&
        request[10] == 0 && request[11] == 0);
    uint16_t sink_port = U16(request + 12), private_port = U16(request + 14);
    Require(sink_port >= 1024 && private_port >= 1024 && sink_port != private_port);
    sigset_t prior_mask;
    if (request[8] <= 2) {
        sigset_t release_mask;
        Require(sigemptyset(&release_mask) == 0 && sigaddset(&release_mask, SIGUSR1) == 0);
        Require(sigprocmask(SIG_BLOCK, &release_mask, &prior_mask) == 0);
        Require(sigdelset(&prior_mask, SIGUSR1) == 0);
        struct sigaction release_action;
        memset(&release_action, 0, sizeof(release_action));
        release_action.sa_handler = ReleaseCompletion;
        Require(sigemptyset(&release_action.sa_mask) == 0);
        Require(sigaction(SIGUSR1, &release_action, NULL) == 0);
    }
    WriteOriginal("/work/setup.bin", setup_bytes, sizeof(setup_bytes) - 1, 0);
    Ready(request);
    if (request[8] == 4) {
        Require(write(1, "ACK_WITHOUT_REPORT\n", 19) == 19);
        for (;;) pause();
    }
    Lockdown();
    int private_listener = Network(sink_port, private_port);
    WriteOriginal("/work/report/result.bin", report_bytes, sizeof(report_bytes) - 1, 1);
    if (request[8] == 1) ByteLimit();
    if (request[8] == 2) InodeLimit();
    if (request[8] == 3) {
        int detached_ready[2];
        Require(pipe2(detached_ready, O_CLOEXEC) == 0);
        pid_t child = fork();
        Require(child >= 0);
        if (child == 0) {
            close(detached_ready[0]);
            Require(setsid() >= 0);
            Require(write(detached_ready[1], "D", 1) == 1);
            close(detached_ready[1]);
            for (;;) pause();
        }
        close(detached_ready[1]);
        char detached;
        Require(read(detached_ready[0], &detached, 1) == 1 && detached == 'D');
        Require(read(detached_ready[0], &detached, 1) == 0);
        close(detached_ready[0]);
        Require(printf("OWNED_CHILD %jd\n", (intmax_t)child) > 0 && fflush(stdout) == 0);
        for (;;) pause();
    }
    Require(printf("WORK_COMPLETE\n") > 0 && fflush(stdout) == 0);
    while (!completion_released) {
        Require(sigsuspend(&prior_mask) == -1 && errno == EINTR);
    }
    close(private_listener);
    return 0;
}
