#include <thread>
#include <mutex>
#include <time.h>        // clock_gettime, timespec
#include <functional>


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

class Finally {
    private: std::function<void()> _func;
    public: Finally(std::function<void()> func) : _func(func) {}
    public: ~Finally() { _func(); }
};

class Guarded {
    private: pthread_t _owner = 0;
    private: pthread_mutex_t _mutex = PTHREAD_MUTEX_INITIALIZER;
    public: bool own() const { return _owner == pthread_self(); }
    public: bool reserve(struct timespec deadline) {
        if (pthread_mutex_timedlock(&_mutex, &deadline) == 0) {
            _owner = pthread_self();
            return true;
        }
        return false;
    }
    public: bool reserve() {
        if (pthread_mutex_lock(&_mutex) == 0) {
            _owner = pthread_self();
            return true;
        }
        return false;
    }
    public: void release() {
        if (own()) {
            _owner = 0;
            pthread_mutex_unlock(&_mutex);
        }
    }
    protected: void guard() const {
        if (!own()) {
            throw std::runtime_error("Must reserve before accessing guarded resource");
        }
    }
};

class GuardedOven : public Guarded {
    private: int _temperature = 0;
    public: int temperature() const {
        guard();
        return _temperature;
    }
    public: void temperature(int temp) {
        guard();
        _temperature = temp; 
    }
};

class GuardedCookieSheet : public Guarded {
    private: int _cookies = 0;
    public: int cookies() const {
        guard();
        return _cookies;
    }
    public: void cookies(int cookies) {         
        guard();
        _cookies = cookies; 
    }
};


GuardedOven oven;
GuardedCookieSheet cookieSheet;

void alice() {
    for(;;) {
        Finally release([&](){ oven.release(); cookieSheet.release(); });
        struct timespec deadline = deadline_from_now(5000);
        if (!oven.reserve(deadline) || !cookieSheet.reserve(deadline)) {
            printf("Alice failed to reserve oven, retrying...\n");
            sleep(rand() % 6 + 1); // Sleep 1-6 seconds before retrying
            continue;
        }
        printf("Alice is cooking cookies...\n");
        cookieSheet.cookies(12);
        oven.temperature(350);
        sleep(4);
        break;
    }
}

void bob() {
    for(;;) {
        Finally release([&](){ oven.release(); cookieSheet.release(); });
        struct timespec deadline = deadline_from_now(5000);
        if (!oven.reserve(deadline) || !cookieSheet.reserve(deadline)) {
            printf("Bob failed to reserve oven, retrying...\n");
            sleep(rand() % 6 + 1); // Sleep 1-6 seconds before retrying
            continue;
        }
        printf("Bob is cooking cookies...\n");
        cookieSheet.cookies(8);
        oven.temperature(400);
        sleep(6);
        break;
    }
}

int main() {
    std::thread alice_thread(alice);
    std::thread bob_thread(bob);
    printf("Alice and Bob are cooking cookies...\n");
    alice_thread.join();
    bob_thread.join();
    return 0;
}

