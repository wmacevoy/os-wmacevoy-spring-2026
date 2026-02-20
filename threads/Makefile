all : thread-hello deadlock_c deadlock_cpp

thread-hello : thread-hello.c
	gcc -o thread-hello thread-hello.c -lpthread

deadlock_c : deadlock.c
	gcc -o deadlock_c deadlock.c -lpthread

deadlock_cpp : deadlock.cpp
	g++ -std=c++20 -o deadlock_cpp deadlock.cpp -lpthread

clean :
	rm -f thread-hello deadlock_c deadlock_cpp