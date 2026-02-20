#include <pthread.h>
#include <time.h>        // clock_gettime, timespec
#include <errno.h>       // ETIMEDOUT, EBUSY, etc.
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>      // sleep

struct info {
    int data;
    int result;
};

void* thread_func(void* void_info) {
    struct info* info = (struct info*)void_info;
    long arg = info->data;
    printf("Hello from thread %d!\n", arg);
    info->result = arg * 2;
    return void_info;
}

int main() {
    const int num_threads = 5;
    pthread_t threads[num_threads];
    struct info infos[num_threads];

    for (int i = 0; i < num_threads; i++) {
        infos[i].data = i;
        if (pthread_create(&threads[i], NULL, thread_func, &infos[i]) != 0) {
            perror("Failed to create thread");
            exit(EXIT_FAILURE);
        }
    }

    for (int i = 0; i < num_threads; i++) {
        void* thread_result;
        if (pthread_join(threads[i], &thread_result) != 0) {
            perror("Failed to join thread");
            exit(EXIT_FAILURE);
        }
        struct info* info = (struct info*)thread_result;
        printf("Thread %d returned result %d\n", info->data, info->result);
    }

    return 0;
}