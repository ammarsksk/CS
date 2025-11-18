// threads_tls.c
// TLS-enabled threaded server adapted from your threads.c
// Compile: gcc threads_tls.c -o threads_tls -pthread -lssl -lcrypto

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_PORT  5432
#define MAX_PENDING  5
#define MAX_LINE     256
#define MAX_CLIENTS  10

int client_socks[MAX_CLIENTS];   // store client sockets (for non-TLS fallback info)
SSL *client_ssl[MAX_CLIENTS];    // store SSL pointers for each client
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void init_openssl()
{
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
	EVP_cleanup();
}

SSL_CTX *create_context()
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = TLS_server_method(); // supports TLS 1.2 + 1.3
	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	return ctx;
}

void configure_context(SSL_CTX *ctx, const char *pemfile)
{
	// Load server certificate and private key (PEM file containing cert+key)
	if (SSL_CTX_use_certificate_file(ctx, pemfile, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, pemfile, SSL_FILETYPE_PEM) <= 0 ) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	// Optional: verify private key
	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr, "Private key does not match the certificate public key\n");
		exit(EXIT_FAILURE);
	}

	// Set options: disable SSLv2/3, allow TLS1.2/1.3
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	// You can further configure ciphers here if desired.
}

void cleanup_client_slot(int idx)
{
	if (client_ssl[idx]) {
		SSL_shutdown(client_ssl[idx]); // polite TLS close
		SSL_free(client_ssl[idx]);
		client_ssl[idx] = NULL;
	}
	if (client_socks[idx] != -1) {
		close(client_socks[idx]);
		client_socks[idx] = -1;
	}
}

void *client_handler(void *arg)
{
	int idx = *(int *)arg; // index into client arrays
	SSL *ssl = client_ssl[idx];
	char buf[MAX_LINE];

	while (1) {
		int bytes = SSL_read(ssl, buf, sizeof(buf)-1);
		if (bytes <= 0) {
			int err = SSL_get_error(ssl, bytes);
			if (bytes == 0 || err == SSL_ERROR_ZERO_RETURN) {
				printf("client (slot %d) disconnected (TLS shutdown).\n", idx);
			} else {
				fprintf(stderr, "SSL_read error for client slot %d: %d\n", idx, err);
				ERR_print_errors_fp(stderr);
			}
			// cleanup
			pthread_mutex_lock(&lock);
			cleanup_client_slot(idx);
			pthread_mutex_unlock(&lock);
			break;
		} else {
			buf[bytes] = '\0';
			printf("Client (slot %d) says: %s\n", idx, buf);
		}
	}
	return NULL;
}

void event_loop(int s, SSL_CTX *ctx)
{
	fd_set readfds;
	struct timeval tv;
	int max_fd;
	int activity;
	char buf[MAX_LINE];

	for (int i = 0; i < MAX_CLIENTS; i++) {
		client_socks[i] = -1;
		client_ssl[i] = NULL;
	}

	srand(time(NULL));

	while (1) {
		FD_ZERO(&readfds);
		FD_SET(STDIN_FILENO, &readfds);
		FD_SET(s, &readfds);
		max_fd = (s > STDIN_FILENO) ? s : STDIN_FILENO;

		tv.tv_sec = 30;
		tv.tv_usec = 0;

		activity = select(max_fd + 1, &readfds, NULL, NULL, &tv);

		if (activity < 0) {
			perror("select");
			break;
		} else if (activity == 0) {
			// no activity
			continue;
		}

		// New incoming connection (TCP)
		if (FD_ISSET(s, &readfds)) {
			struct sockaddr_in client_addr;
			socklen_t addr_len = sizeof(client_addr);
			int new_s = accept(s, (struct sockaddr *)&client_addr, &addr_len);
			if (new_s < 0) {
				perror("accept failed");
			} else {
				pthread_mutex_lock(&lock);
				int slot = -1;
				for (int i = 0; i < MAX_CLIENTS; i++) {
					if (client_socks[i] == -1) {
						slot = i;
						client_socks[i] = new_s;
						break;
					}
				}
				if (slot == -1) {
					printf("Too many clients, rejecting connection.\n");
					close(new_s);
				} else {
					// Create SSL and perform TLS handshake
					SSL *ssl = SSL_new(ctx);
					if (!ssl) {
						fprintf(stderr, "SSL_new failed\n");
						close(new_s);
						client_socks[slot] = -1;
					} else {
						SSL_set_fd(ssl, new_s);
						int ret = SSL_accept(ssl);
						if (ret <= 0) {
							fprintf(stderr, "SSL_accept failed\n");
							ERR_print_errors_fp(stderr);
							SSL_free(ssl);
							close(new_s);
							client_socks[slot] = -1;
						} else {
							client_ssl[slot] = ssl;
							printf("New TLS client connected (slot %d, fd %d).\n", slot, new_s);
							pthread_t tid;
							// pass the slot index to thread; copy to heap-safe storage
							int *pidx = malloc(sizeof(int));
							*pidx = slot;
							pthread_create(&tid, NULL, client_handler, pidx);
							pthread_detach(tid);
						}
					}
				}
				pthread_mutex_unlock(&lock);
			}
		}

		// stdin input -> send to random active client using SSL_write
		if (FD_ISSET(STDIN_FILENO, &readfds)) {
			if (fgets(buf, sizeof(buf), stdin) != NULL) {
				buf[MAX_LINE-1] = '\0';
				int active_slots[MAX_CLIENTS], count = 0;
				pthread_mutex_lock(&lock);
				for (int i = 0; i < MAX_CLIENTS; i++) {
					if (client_socks[i] != -1 && client_ssl[i] != NULL)
						active_slots[count++] = i;
				}
				pthread_mutex_unlock(&lock);
				if (count > 0) {
					int chosen = active_slots[rand() % count];
					SSL *ssl = NULL;
					pthread_mutex_lock(&lock);
					ssl = client_ssl[chosen];
					pthread_mutex_unlock(&lock);
					if (ssl) {
						int w = SSL_write(ssl, buf, strlen(buf));
						if (w <= 0) {
							fprintf(stderr, "SSL_write error when sending to slot %d\n", chosen);
							ERR_print_errors_fp(stderr);
							pthread_mutex_lock(&lock);
							cleanup_client_slot(chosen);
							pthread_mutex_unlock(&lock);
						}
					}
				} else {
					printf("No TLS clients to send to.\n");
				}
			}
		}
	}

	// cleanup
	for (int i = 0; i < MAX_CLIENTS; i++) {
		pthread_mutex_lock(&lock);
		cleanup_client_slot(i);
		pthread_mutex_unlock(&lock);
	}
	close(s);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <server-pem-file>\n", argv[0]);
		return 1;
	}

	const char *pemfile = argv[1];

	init_openssl();
	SSL_CTX *ctx = create_context();
	configure_context(ctx, pemfile);

	struct sockaddr_in sin;
	int s;

	bzero((char *)&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(SERVER_PORT);

	if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket failed");
		exit(1);
	}
	if ((bind(s, (struct sockaddr *)&sin, sizeof(sin))) < 0) {
		perror("bind failed");
		exit(1);
	}
	if (listen(s, MAX_PENDING) < 0) {
		perror("listen failed");
		exit(1);
	}
	event_loop(s, ctx);

	SSL_CTX_free(ctx);
	cleanup_openssl();
	return 0;
}
