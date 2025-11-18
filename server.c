#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>
#include <time.h>
// 1. Include OpenSSL Headers
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_PORT  5432
#define MAX_PENDING  5
#define MAX_LINE     256
#define MAX_CLIENTS  10

// 2. Helper to setup OpenSSL Context
SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method(); // Create new server-method instance
    ctx = SSL_CTX_new(method);    // Create context
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

// 3. Helper to load certificates
void configure_context(SSL_CTX *ctx) {
    // We will generate these two files (cert.pem and key.pem) later using a command
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void event_loop(int s, SSL_CTX *ctx)
{
    fd_set readfds;
    struct timeval tv;
    int client_socks[MAX_CLIENTS]; 
    SSL *client_ssls[MAX_CLIENTS]; // 4. Parallel array to store SSL structures
    int max_fd;
    int activity;
    char buf[MAX_LINE];

    // initialize
    for (int i = 0; i < MAX_CLIENTS; i++) {
        client_socks[i] = -1;
        client_ssls[i] = NULL; // Initialize SSL pointers to NULL
    }

    srand(time(NULL));

    while(1) {
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(s, &readfds);
        max_fd = (s > STDIN_FILENO) ? s : STDIN_FILENO;

        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (client_socks[i] != -1) {
                FD_SET(client_socks[i], &readfds);
                if (client_socks[i] > max_fd)
                    max_fd = client_socks[i];
            }
        }

        tv.tv_sec = 30;
        tv.tv_usec = 0;

        activity = select(max_fd + 1, &readfds, NULL, NULL, &tv);

        if (activity < 0) {
            perror("select");
            break;
        } else if (activity == 0) {
            printf("No activity for 30 secs. Server running...\n");
            continue;
        }

        // New incoming connection
        if (FD_ISSET(s, &readfds)) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int new_s = accept(s, (struct sockaddr *)&client_addr, &addr_len);
            
            if (new_s < 0) {
                perror("accept failed");
            } else {
                // 5. Wrap the new socket in SSL
                SSL *new_ssl = SSL_new(ctx);
                SSL_set_fd(new_ssl, new_s);

                // Perform the TLS handshake (Simplified: Blocking)
                if (SSL_accept(new_ssl) <= 0) {
                    ERR_print_errors_fp(stderr);
                    close(new_s);
                    SSL_free(new_ssl);
                } else {
                    int added = 0;
                    for (int i = 0; i < MAX_CLIENTS; i++) {
                        if (client_socks[i] == -1) {
                            client_socks[i] = new_s;
                            client_ssls[i] = new_ssl; // Store the SSL struct
                            printf("New client (%d) connected securely.\n", new_s);
                            added = 1;
                            break;
                        }
                    }
                    if (!added) {
                        printf("Too many clients.\n");
                        SSL_shutdown(new_ssl);
                        SSL_free(new_ssl);
                        close(new_s);
                    }
                }
            }
        }

        // Check client sockets
        for (int i = 0; i < MAX_CLIENTS; i++) {
            int cs = client_socks[i];
            if (cs != -1 && FD_ISSET(cs, &readfds)) {
                // 6. Use SSL_read instead of recv
                // Note: We use client_ssls[i], NOT the socket 'cs' directly
                int bytes = SSL_read(client_ssls[i], buf, sizeof(buf) - 1); 
                
                if (bytes <= 0) {
                    int err = SSL_get_error(client_ssls[i], bytes);
                    if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL) {
                        printf("client %d disconnected.\n", cs);
                        SSL_shutdown(client_ssls[i]);
                        SSL_free(client_ssls[i]); // Free SSL memory
                        close(cs);
                        client_socks[i] = -1;
                        client_ssls[i] = NULL;
                    }
                } else {
                    buf[bytes] = '\0'; // Null terminate manually based on bytes read
                    printf("Client %d says: %s\n", cs, buf);
                }
            }
        }

        // Stdin input
        if  (FD_ISSET(STDIN_FILENO, &readfds)) {
            if (fgets(buf, sizeof(buf), stdin) != NULL) {
                buf[MAX_LINE-1] = '\0';

                int active_indices[MAX_CLIENTS], count = 0;
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (client_socks[i] != -1)
                        active_indices[count++] = i; // Store INDEX, not socket
                }
                if (count > 0) {
                    int target_idx = active_indices[rand() % count];
                    SSL *target_ssl = client_ssls[target_idx];

                    // 7. Use SSL_write instead of send
                    if (SSL_write(target_ssl, buf, strlen(buf)) <= 0) {
                        perror("SSL_write error");
                        // Cleanup handled in next read loop ideally, or here
                    }
                } else {
                    printf("No clients to send to.\n");
                }
            }
        }
    }

    // Cleanup
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (client_socks[i] != -1) {
            SSL_shutdown(client_ssls[i]);
            SSL_free(client_ssls[i]);
            close(client_socks[i]);
        }
    }
    close(s);
}

int main()
{
    struct sockaddr_in sin;
    int s;
    
    // 8. Setup OpenSSL Global Config
    SSL_CTX *ctx;
    ctx = create_context();
    configure_context(ctx);

    bzero((char *)&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(SERVER_PORT);

    if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(1);
    }
    
    // Allow port reuse to avoid "Address already in use" errors during testing
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if ((bind(s, (struct sockaddr *)&sin, sizeof(sin))) < 0) {
        perror("bind failed");
        exit(1);
    }
    if (listen(s, MAX_PENDING) < 0) {
        perror("listen failed");
        exit(1);
    }
    
    printf("Simple TLS Server listening on port %d...\n", SERVER_PORT);
    event_loop(s, ctx);
    
    SSL_CTX_free(ctx);
    return 0;
}