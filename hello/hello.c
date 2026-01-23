#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int main() {
    int status = fork();
    if (status < 0) {
        // Fork failed
        return 1;
    }
    if (status == 0) {
        // Child process
        const char *child_message = "Hello from Child Process!\n";
        write(STDOUT_FILENO, child_message, 27);
    } else {
        // Parent process
        const char *parent_message = "Hello from Parent Process!\n";
        write(STDOUT_FILENO, parent_message, 28);
    }
    return 0;
}