#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <grp.h>

static char child_stack[1024*1024];

struct info_s {
    pid_t parent;
    /* Parent NameSpace User ID */
    uid_t pns_uid;
    /* Parent NameSpace Effective User ID */
    uid_t pns_euid;
    gid_t pns_gid;
    gid_t pns_egid;
    const char *hostname;
};

static int
setupIdMaps(struct info_s *info)
{
    char buf[100];
    int fd;
    sprintf(buf, "/proc/%u/uid_map", getpid());
    fd = open(buf, O_WRONLY);
    if (fd < 0) {
        perror(buf);
        return fd;
    }
    sprintf(buf, "0 %i 1\n", info->pns_euid);
    ssize_t s = write(fd, buf, strlen(buf));
    if (s != strlen(buf)) {
        perror("c: write uid");
        close(fd);
        return -2;
    }
    close(fd);

    /* TODO: Newer (3.19 I think) kernels require user programs to write
     * setgroups to false before setting the gid_map. Older kernels don't
     * have this file, and also allow the program to call setgroups to drop
     * groups before writing the group map, which turns out to be a
     * security problem. Unfortunately, in all kernels to date
     * (2016-01-15), you can only map a single group to your GID, and
     * cannot map anything to your supplemental GIDs (unless you are
     * priveleged outside of your namespace). This means that, unless you
     * run an older kernel AND drop your groups, you end up in your
     * namespace with a bunch of supplemental groups that all have the same
     * ID number (equal to the overflow gid number).
     *
     * The TODO here is primarily that we only work on the older kernels
     * with the below commented out, or only the newer ones (probably) with
     * it in. We ought to work on both (try setgroups, ignore failure).
     * Either way we shouldn't drop groups unless we are privileged outside
     * the namespace, or also ignore that error.
     */
    sprintf(buf, "/proc/%u/setgroups", getpid());
    fd = open(buf, O_WRONLY);
    if (fd < 0) {
        //perror(buf);
        //return fd;
    } else {
        write(fd, "deny\n", 5);
        close(fd);
    }

    sprintf(buf, "/proc/%u/gid_map", getpid());
    fd = open(buf, O_WRONLY);
    if (fd < 0) {
        perror(buf);
        return fd;
    }
    sprintf(buf, "5 %i 1\n", info->pns_egid);
    s = write(fd, buf, strlen(buf));
    if (s != strlen(buf)) {
        perror("c: write gid");
        close(fd);
        return -2;
    }
    close(fd);
    return 0;
}

static int
mount_fs()
{
    /* Since we did NEWNS, we have our own mount space too, so we'll mount
     * proc from our namespace so that 'ps' works correctly */
    mount("my-root", "/tmp", "tmpfs", MS_NOEXEC | MS_NOSUID | MS_NODEV, "");
    mkdir("/tmp/proc", 0777);
    mkdir("/tmp/dev", 0777);
    mkdir("/tmp/bin", 0777);
    mkdir("/tmp/usr", 0777);
    mkdir("/tmp/sbin", 0777);
    mkdir("/tmp/lib", 0777);
    mkdir("/tmp/lib64", 0777);
    mkdir("/tmp/root", 0777);
    mkdir("/tmp/etc", 0777);
    /* This doesn't work if host's dev is directly devtmpfs for some reason */
    if (0 != mount("/dev", "/tmp/dev", NULL, MS_BIND | MS_RDONLY, NULL)) {
        perror("c: bind mount /dev");
        fprintf(stderr, "c: Perhaps try \"sudo mount --bind /dev /dev\" first?\n");
        return 1;
    }
    mount("/bin", "/tmp/bin", NULL, MS_BIND | MS_RDONLY, NULL);
    mount("/sbin", "/tmp/sbin", NULL, MS_BIND | MS_RDONLY, NULL);
    mount("/usr", "/tmp/usr", NULL, MS_BIND | MS_RDONLY, NULL);
    mount("/lib", "/tmp/lib", NULL, MS_BIND | MS_RDONLY, NULL);
    mount("/lib64", "/tmp/lib64", NULL, MS_BIND | MS_RDONLY, NULL);
    mount("roothome", "/tmp/root", NULL, MS_BIND | MS_RDONLY, NULL);
    mount("etc", "/tmp/etc", NULL, MS_BIND | MS_RDONLY, NULL);
    chroot("/tmp");
    chdir("/");
    mount("proc", "/proc", "proc", 0, "");
    return 0;
}

static int
child_fn(void *arg)
{
    struct info_s *info = arg;
    printf("c: configure\n");
    /* Force our new shell to have a custom home directory */
    setenv("HOME", "/root", 1);
    setenv("PS1", "\\[\\e[33m\\]\\u\\[\\e[36m\\]@\\[\\e[31m\\]\\h\\[\\e[0m\\] \\w # ", 1);
    if (mount_fs() != 0) {
        return 1;
    }
    sethostname(info->hostname, strlen(info->hostname));
    /* Setup a user id mapping */
    printf("c: You are %i (acting as %i)\n", getuid(), geteuid());
    if (setupIdMaps(info)) {
        printf("c: Error setting user id mapping\n");
        return 1;
    }
    printf("c: You are %i (acting as %i)\n", getuid(), geteuid());
    /* Remove all supplementary groups */
    //setgroups(0, NULL);
#if 0 /* can't drop privilege if single mapping exists. We are always exactly the single ID we put into the uid_map file. */
    if (setuid(5)) {
        perror("setuid");
    }
#endif
    /* And exec a shell */
    printf("c: Starting shell\n");
    execl("/bin/bash", "/bin/bash", "--norc", "--noprofile", NULL);
    printf("c: Failed to exec\n");
    return 0;
}

int
main(int argc, char *argv[])
{
    struct info_s info;
    printf("p: You are %i (acting as %i)\n", getuid(), geteuid());
    info.pns_uid = getuid();
    info.pns_euid = geteuid();
    info.pns_gid = getgid();
    info.pns_egid = getegid();
    if (argc > 1) {
        info.hostname = argv[1];
    } else {
        info.hostname = "pidtest";
    }
    printf("p: Cloning\n");
    pid_t child = clone(child_fn, child_stack+1024*1024, CLONE_NEWPID | SIGCHLD | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWUSER | CLONE_NEWUTS, &info);
    if (child == -1) {
        printf("Failed to clone.\n");
        return 1;
    }
    printf("p: waiting on child %ld\n", (long)child);
    int status;
    waitpid(child, &status, 0);
    if (WIFEXITED(status)) {
        printf("p: child exited with status %i\n", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        printf("p: child terminated with signal %i\n", WTERMSIG(status));
    } else {
        printf("p: something happened wrong\n");
    }
    return 0;
}
