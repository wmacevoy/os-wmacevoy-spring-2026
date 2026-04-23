# Memory

Memory is not simple infrastructure. It is a key part of what makes modern systems perform.

core - where compute happens, getting closer to the core is faster.

levels of cache registers, l1, l2, l3, physcial ram each is slower than the previous "ring" of data. Rougly x5 at each level, but x20 for RAM.

performance: nice not to abuse the cache.

1. Use less. vector is better than map, scattered objects are hard to keep in cache compared to adjacent data.
2. Think about adjacency - use sequental data as appropriate.
3. Code is also data in the cache. So keeping jumps smaller is better.
   Ex: draw() as a virtual method. Invoking draw on lots of different kinds of Widgets could be scattered.  So sorting widgets by type fixes this.
4. Profiling will tell you a lot.

black hat:

    cache attack - preload the cache so that the target appliction, when run, a cache miss tells you something about what is running.

    thermal attack - use the memory system enough to create a bit error.

    wear attack - read/write enough to burn out flash memory so that the system is unusable.

white hat:
    cache attack: clear cache between context switch. this is expensive, but correct. so only for critical systems.
    developer: process isolation.  

    thermal attack: ECC Ram. Error Correcting Code Ram: can detect any 2 bit error, correct any 1 bit error. Essential for servers.