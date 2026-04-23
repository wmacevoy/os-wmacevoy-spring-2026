#include <stdio.h>
#include <unistd.h>

void greet() {
    printf("Hi from hi.c (pid %d)!\n",
         getpid());
}

int main() {
    greet();
    return 0;
}
