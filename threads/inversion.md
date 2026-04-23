firetruck, cars, and hurst

Priority Inversion....

1. The firetruck needs a single-lane road.
2. The hurst is on the road.
3. The regular cars keep prempting the hurst.

This can competely lock out the firetruck - regular cars postpone the hurst from exiting the single lane road (maybe forever). 

Priority Inversion
1. Some high priorituy process needs a shared resource.
2. some low priority process currently owns the lock for that resource.
3. Medium priority processes keep interrupting the low priority process so it can't complete its critical section.

Fix it?

OS can give priority creep to stale threads (low priority threads that are in the ready state, but have not been in the run state for a while). So all threads run at least a little, so the hurst (middle priority thread) makes progress.

Since the OS/Kernel knows which threads are involved, it can temporarily assign a higher priority to the middle priority thread: max of all threads waiting for that resource. This is called prioirty inheretance.

As a developor on and OS that does not have priority interetance, always use the highest priority of every thread that might use that resource.

hurst() {
   set_priority(firetruck_priority);
   obtain(single_lane_mutex)
   drive_down_the_lane();
   release(single_lane_mutex);
   set_priority(hurst_prioritry);


}


condition variables help set barriers for things that need to be true for futher action

queue<jobs> work_queue;
mutex work_queue_mutex;
condition empty_queue;
condition full_queue;

producer() {
    obtain(work_queue_mutex);
    if (work_queue.size() >= high_water_mark) {
        condition_signal(full_queue);
        condtion_wait(work_queue_mutex, full_queue);
    }

    release(work_queue_mutex)
}

consumer() {
    obtain(work_queue_mutex);
    job = work_queue.pop_front();
    if (work_queue.size() < high_water_mark) {
        condition_signal(full_queue);
    }
    release(work_queue_mutex)
    job.do();
}
}