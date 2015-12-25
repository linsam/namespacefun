#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <unistd.h>

static char child_stack[1024*1024];

static int child_fn() {
    printf("Child: configure\n");
    /* Force our new shell to have a custom home directory */
    setenv("HOME", "/home/john/projs/namespacefun/roothome/", 1);
    setenv("PS1", "root # ", 1);
    /* Since we did NEWNS, we have our own mount space too, so we'll mount
     * proc from our namespace so that 'ps' works correctly */
    //system("mount -t proc proc /proc");
    mount("proc", "/proc", "proc", 0, "");
    /* And exec a shell */
    printf("Child: Starting shell\n");
    execl("/bin/bash", "/bin/bash", "--norc", "--noprofile", NULL);
    printf("Failed to exec\n");
    return 0;
}
int main() {
    printf("Cloning\n");
    pid_t child = clone(child_fn, child_stack+1024*1024, CLONE_NEWPID | SIGCHLD | CLONE_NEWNS | CLONE_NEWNET, NULL);
    if (child == -1) {
        printf("Failed to clone.\n");
        return 1;
    }
    printf("Parent, waiting on child %ld\n", (long)child);
    int status;
    waitpid(child, &status, 0);
    if (WIFEXITED(status)) {
        printf("Parent: child exited with status %i\n", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        printf("Parent: child terminated with signal %i\n", WTERMSIG(status));
    } else {
        printf("Parent: something happened wrong\n");
    }
    return 0;
}
