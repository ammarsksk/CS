// threads.c - Advanced Chat Server
// Features: Broadcast, Private (@id), Server Commands, /list, /myid
// Compile: make -B

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_PORT  5432
#define MAX_PENDING  5
#define MAX_LINE     1024
#define MAX_CLIENTS  10

// Global State
int client_socks[MAX_CLIENTS];   
SSL *client_ssl[MAX_CLIENTS];    
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

// --- OpenSSL Helpers ---
void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx, const char *pemfile) {
    if (SSL_CTX_use_certificate_file(ctx, pemfile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, pemfile, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

// --- Chat Logic Helpers ---

void cleanup_client_slot(int idx) {
    if (client_ssl[idx]) {
        SSL_shutdown(client_ssl[idx]);
        SSL_free(client_ssl[idx]);
        client_ssl[idx] = NULL;
    }
    if (client_socks[idx] != -1) {
        close(client_socks[idx]);
        client_socks[idx] = -1;
    }
}

// Send a message to a specific client ID (Thread Safe)
void send_private_message(int target_idx, char *msg) {
    pthread_mutex_lock(&lock);
    if (target_idx >= 0 && target_idx < MAX_CLIENTS && client_ssl[target_idx] != NULL) {
        SSL_write(client_ssl[target_idx], msg, strlen(msg));
    }
    pthread_mutex_unlock(&lock);
}

// Send to everyone EXCEPT sender (Thread Safe)
void broadcast_message(char *msg, int sender_idx) {
    pthread_mutex_lock(&lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (client_ssl[i] != NULL && i != sender_idx) {
            SSL_write(client_ssl[i], msg, strlen(msg));
        }
    }
    pthread_mutex_unlock(&lock);
}

void send_user_list(int requester_idx) {
    char list_msg[MAX_LINE] = "Active Clients: ";
    char temp[16];
    
    pthread_mutex_lock(&lock);
    for(int i=0; i<MAX_CLIENTS; i++) {
        if (client_ssl[i] != NULL) {
            sprintf(temp, "[%d] ", i);
            strcat(list_msg, temp);
        }
    }
    pthread_mutex_unlock(&lock);
    strcat(list_msg, "\n");
    send_private_message(requester_idx, list_msg);
}

// --- Thread Worker ---

void *client_handler(void *arg) {
    int idx = *(int *)arg;
    free(arg);
    
    SSL *ssl = client_ssl[idx];
    char buf[MAX_LINE];
    char outgoing[MAX_LINE + 50];

    // --- NEW: Send Welcome Message with ID ---
    char welcome[100];
    snprintf(welcome, sizeof(welcome), "Connected securely. You are Client ID: %d\n", idx);
    SSL_write(ssl, welcome, strlen(welcome));
    // -----------------------------------------

    while (1) {
        int bytes = SSL_read(ssl, buf, sizeof(buf)-1);
        if (bytes <= 0) {
            printf("Client %d disconnected.\n", idx);
            pthread_mutex_lock(&lock);
            cleanup_client_slot(idx);
            pthread_mutex_unlock(&lock);
            break;
        } 
        
        buf[bytes] = '\0';
        buf[strcspn(buf, "\n")] = 0; // Trim newline

        // 1. Check for Private Message: "@<id> <msg>"
        if (buf[0] == '@') {
            char *space_ptr = strchr(buf, ' ');
            if (space_ptr) {
                *space_ptr = '\0'; 
                char *target_str = buf + 1; 
                char *msg_content = space_ptr + 1;

                if (strcasecmp(target_str, "server") == 0) {
                    printf("[Private from Client %d]: %s\n", idx, msg_content);
                } 
                else {
                    int target_id = atoi(target_str);
                    snprintf(outgoing, sizeof(outgoing), "[Private from %d]: %s\n", idx, msg_content);
                    send_private_message(target_id, outgoing);
                    printf("[Log] Client %d -> Client %d (Private)\n", idx, target_id);
                }
            } else {
                char *err = "Usage: @<id> <message>\n";
                SSL_write(ssl, err, strlen(err));
            }
        }
        // 2. Command: /list
        else if (strcmp(buf, "/list") == 0) {
            send_user_list(idx);
        }
        // 3. NEW Command: /myid
        else if (strcmp(buf, "/myid") == 0) {
            char id_msg[64];
            snprintf(id_msg, sizeof(id_msg), "Your Client ID is: %d\n", idx);
            SSL_write(ssl, id_msg, strlen(id_msg));
        }
        // 4. Default: Broadcast
        else {
            printf("Client %d says: %s\n", idx, buf);
            snprintf(outgoing, sizeof(outgoing), "Client %d: %s\n", idx, buf);
            broadcast_message(outgoing, idx);
        }
    }
    return NULL;
}

// --- Main Server Loop ---

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <combined-pem-file>\n", argv[0]);
        return 1;
    }

    init_openssl();
    SSL_CTX *ctx = create_context();
    configure_context(ctx, argv[1]);

    int listener;
    struct sockaddr_in sin;
    bzero((char *)&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(SERVER_PORT);

    if ((listener = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed"); exit(1);
    }
    int opt = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (bind(listener, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("bind failed"); exit(1);
    }
    if (listen(listener, MAX_PENDING) < 0) {
        perror("listen failed"); exit(1);
    }

    for (int i = 0; i < MAX_CLIENTS; i++) {
        client_socks[i] = -1;
        client_ssl[i] = NULL;
    }

    printf("Server running on port %d.\n", SERVER_PORT);
    printf("COMMANDS: /list, /myid, @<id> <msg>, <broadcast>\n");

    fd_set readfds;
    int max_fd;
    char input_buf[MAX_LINE];

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(listener, &readfds);      
        FD_SET(STDIN_FILENO, &readfds);  
        max_fd = listener > STDIN_FILENO ? listener : STDIN_FILENO;

        if (select(max_fd + 1, &readfds, NULL, NULL, NULL) < 0) {
            perror("select error");
            continue;
        }

        // Handle New Connections
        if (FD_ISSET(listener, &readfds)) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int new_s = accept(listener, (struct sockaddr *)&client_addr, &addr_len);

            if (new_s >= 0) {
                pthread_mutex_lock(&lock);
                int slot = -1;
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (client_socks[i] == -1) {
                        slot = i;
                        client_socks[i] = new_s;
                        break;
                    }
                }
                pthread_mutex_unlock(&lock);

                if (slot == -1) {
                    printf("Server full.\n");
                    close(new_s);
                } else {
                    SSL *ssl = SSL_new(ctx);
                    SSL_set_fd(ssl, new_s);
                    if (SSL_accept(ssl) <= 0) {
                        ERR_print_errors_fp(stderr);
                        close(new_s);
                    } else {
                        pthread_mutex_lock(&lock);
                        client_ssl[slot] = ssl;
                        pthread_mutex_unlock(&lock);
                        
                        printf("New Client connected at slot %d\n", slot);
                        
                        pthread_t tid;
                        int *pidx = malloc(sizeof(int));
                        *pidx = slot;
                        pthread_create(&tid, NULL, client_handler, pidx);
                        pthread_detach(tid);
                    }
                }
            }
        }

        // Handle Server Admin Input
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            if (fgets(input_buf, sizeof(input_buf), stdin)) {
                input_buf[strcspn(input_buf, "\n")] = 0; 
                
                if (input_buf[0] == '@') {
                    char *space = strchr(input_buf, ' ');
                    if (space) {
                        *space = '\0';
                        int target_id = atoi(input_buf + 1);
                        char *msg = space + 1;
                        char server_msg[MAX_LINE];
                        snprintf(server_msg, sizeof(server_msg), "[Admin Private]: %s\n", msg);
                        send_private_message(target_id, server_msg);
                        printf("Sent private message to Client %d.\n", target_id);
                    }
                } else {
                    char server_broadcast[MAX_LINE];
                    snprintf(server_broadcast, sizeof(server_broadcast), "[Admin Broadcast]: %s\n", input_buf);
                    broadcast_message(server_broadcast, -1); 
                }
            }
        }
    }

    close(listener);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}