#include <pthread.h>
#include <time.h>        // clock_gettime, timespec
#include <errno.h>       // ETIMEDOUT, EBUSY, etc.
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>


static struct timespec timespec_add_ms(struct timespec t, long ms) {
    t.tv_sec  += ms / 1000;
    t.tv_nsec += (ms % 1000) * 1000000L;
    if (t.tv_nsec >= 1000000000L) { t.tv_sec++; t.tv_nsec -= 1000000000L; }
    return t;
}

static struct timespec deadline_from_now(long ms) {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);          // timed APIs often use REALTIME
    return timespec_add_ms(now, ms);
}

struct oven {
    int temperature;
    pthread_mutex_t mutex;
};

struct cookie_sheet {
    int cookies;
    pthread_mutex_t mutex;
};

struct oven oven = { .temperature = 0, .mutex = PTHREAD_MUTEX_INITIALIZER };
struct cookie_sheet cookie_sheet = { .cookies = 0, .mutex = PTHREAD_MUTEX_INITIALIZER };

void *cook_alice(void *arg) {
    bool cooked = false;
    while (!cooked) {
        struct timespec deadline = deadline_from_now(5000);
        bool my_oven = false;
        bool my_cookie_sheet = false;
        if (pthread_mutex_timedlock(&oven.mutex, &deadline) == 0) {
            my_oven = true; 
            if (pthread_mutex_timedlock(&cookie_sheet.mutex, &deadline) == 0) {
                my_cookie_sheet = true;
                printf("Alice is cooking cookies...\n");
                cookie_sheet.cookies = 12;
                oven.temperature = 350;
                sleep(4);
                cooked = true;
            }
        }
        if (my_cookie_sheet) pthread_mutex_unlock(&cookie_sheet.mutex);
        if (my_oven) pthread_mutex_unlock(&oven.mutex);
        if (!cooked) {
            printf("Alice failed to cook, retrying...\n");
            sleep(rand() % 6 + 1); // Sleep 1-6 seconds before retrying
        }
    }
}

void *cook_deadlock_bob(void *arg) {
    pthread_mutex_lock(&cookie_sheet.mutex);
    // Simulate taking cookies off the sheet    
    sleep(1);
    pthread_mutex_lock(&oven.mutex);
    // Simulate putting cookies on the sheet
    cookie_sheet.cookies = 8;
    oven.temperature = 400;
    sleep(12);
    pthread_mutex_unlock(&oven.mutex);
    pthread_mutex_unlock(&cookie_sheet.mutex);
    return NULL;
}

void *cook_bob(void *arg) {
    bool cooked = false;
    while (!cooked) {
        struct timespec deadline = deadline_from_now(5000);
        bool my_oven = false;
        bool my_cookie_sheet = false;
        if (pthread_mutex_timedlock(&oven.mutex, &deadline) == 0) {
            my_oven = true; 
            if (pthread_mutex_timedlock(&cookie_sheet.mutex, &deadline) == 0) {
                my_cookie_sheet = true;
                printf("Bob is cooking cookies...\n");
                cookie_sheet.cookies = 8;
                oven.temperature = 400;
                sleep(8);
                cooked = true;
            }
        }
        if (my_cookie_sheet) pthread_mutex_unlock(&cookie_sheet.mutex);
        if (my_oven) pthread_mutex_unlock(&oven.mutex);
        if (!cooked) {
            printf("Bob failed to cook, retrying...\n");
            sleep(rand() % 6 + 1); // Sleep 1-6 seconds before retrying
        }
    }
}

int main() {
 
    pthread_t alice_thread, bob_thread;
    pthread_create(&alice_thread, NULL, cook_alice, NULL);
    pthread_create(&bob_thread, NULL, cook_bob, NULL);
    printf("Alice and Bob are cooking cookies...\n");
    pthread_join(alice_thread, NULL);
    pthread_join(bob_thread, NULL);
    return 0;
}

