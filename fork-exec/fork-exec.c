#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

void child() {
    printf("Hello from Child Process (pid %d)!\n", getpid());
    execl("./hi", "hi", (char *)NULL);
//    sleep(1);
    printf("Child Process (pid %d) exiting.\n", getpid());
}

void parent(pid_t child_pid) {
    printf("Hello from Parent Process (parent pid %d, child pid %d)!\n", 
        getpid(), child_pid);
    waitpid(child_pid, NULL, 0); // Wait for child to finish
    printf("Parent Process (pid %d) exiting.\n", getpid());
}

int main(int argc, char *argv[]) {
    (void) argc;
    (void) argv;

    int status = fork();
    if (status < 0) { 
        // Fork failed
        return 1;
    }
    if (status == 0) {
        // Child process
        child();
    } else {
        // Parent process
        parent(status);
    }
    return 0;
}