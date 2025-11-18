
default: client server threads

threads: threads.c
	gcc -o threads threads.c -lssl -lcrypto -pthread

client: client.c
	gcc -Wall -Werror -O3 -o $@ $^ -lssl -lcrypto


clean:
	rm -f server client threads
