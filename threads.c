// threads.c - Blind Secret Name Network
// Features: No Global List, Blind Requests, Strict Privacy
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
#define MAX_PENDING  5      // <--- This was missing!
#define MAX_LINE     1024
#define MAX_CLIENTS  10

// --- Relationship States ---
#define REL_NONE      0
#define REL_REQ_SENT  1
#define REL_REQ_RCVD  2
#define REL_FRIENDS   3

typedef struct {
    int id;
    int socket;
    SSL *ssl;
    char name[32];
    int active; // 0 = empty, 1 = active
} Client;

// Global State
Client clients[MAX_CLIENTS];
int friends[MAX_CLIENTS][MAX_CLIENTS]; // Matrix: [UserA][UserB] = Status
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

// --- Logic Helpers ---

void send_msg(int idx, char *msg) {
    if (clients[idx].active && clients[idx].ssl) {
        SSL_write(clients[idx].ssl, msg, strlen(msg));
    }
}

int find_user_by_name(char *name) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && strcmp(clients[i].name, name) == 0) {
            return i;
        }
    }
    return -1;
}

void cleanup_client(int idx) {
    if (clients[idx].active) {
        for(int i=0; i<MAX_CLIENTS; i++) {
            friends[idx][i] = REL_NONE;
            friends[i][idx] = REL_NONE;
        }
        if (clients[idx].ssl) {
            SSL_shutdown(clients[idx].ssl);
            SSL_free(clients[idx].ssl);
        }
        close(clients[idx].socket);
        clients[idx].active = 0;
        memset(clients[idx].name, 0, 32);
    }
}

// --- Thread Worker ---

void *client_handler(void *arg) {
    int idx = *(int *)arg;
    free(arg);
    
    SSL *ssl = clients[idx].ssl;
    char buf[MAX_LINE];
    char out[MAX_LINE];

    // 1. Registration
    char *ask_name = "Enter your SECRET NAME to join the network: ";
    SSL_write(ssl, ask_name, strlen(ask_name));

    int bytes = SSL_read(ssl, buf, sizeof(buf)-1);
    if (bytes <= 0) { cleanup_client(idx); return NULL; }
    
    buf[bytes] = '\0';
    buf[strcspn(buf, "\n")] = 0; 
    
    pthread_mutex_lock(&lock);
    if (find_user_by_name(buf) != -1) {
        char *taken = "Name taken. Bye.\n";
        SSL_write(ssl, taken, strlen(taken));
        cleanup_client(idx);
        pthread_mutex_unlock(&lock);
        return NULL;
    }
    strncpy(clients[idx].name, buf, 31);
    pthread_mutex_unlock(&lock);

    sprintf(out, "Welcome, %s. Network is BLIND. Use /chat [name] to request a connection.\n", clients[idx].name);
    SSL_write(ssl, out, strlen(out));
    printf("User registered: %s (Slot %d)\n", clients[idx].name, idx);

    // 2. Main Loop
    while (1) {
        bytes = SSL_read(ssl, buf, sizeof(buf)-1);
        if (bytes <= 0) {
            printf("User %s disconnected.\n", clients[idx].name);
            pthread_mutex_lock(&lock);
            cleanup_client(idx);
            pthread_mutex_unlock(&lock);
            break;
        } 
        
        buf[bytes] = '\0';
        buf[strcspn(buf, "\n")] = 0;

        pthread_mutex_lock(&lock);

        // --- COMMAND: /list (ONLY Accepted Friends) ---
        if (strcmp(buf, "/list") == 0) {
            char list[MAX_LINE] = "Your Private Contacts: ";
            int found = 0;
            for (int i=0; i<MAX_CLIENTS; i++) {
                if (friends[idx][i] == REL_FRIENDS) {
                    strcat(list, clients[i].name);
                    strcat(list, " ");
                    found = 1;
                }
            }
            if (!found) strcat(list, "(None. Use /chat [name] to add someone)");
            strcat(list, "\n");
            send_msg(idx, list);
        }

        // --- COMMAND: /chat [name] (Blind Request) ---
        else if (strncmp(buf, "/chat ", 6) == 0) {
            char *target_name = buf + 6;
            int t_idx = find_user_by_name(target_name);

            if (t_idx == -1) {
                send_msg(idx, "User not found or not online.\n");
            } else if (t_idx == idx) {
                send_msg(idx, "You cannot chat with yourself.\n");
            } else if (friends[idx][t_idx] == REL_FRIENDS) {
                send_msg(idx, "Already friends!\n");
            } else if (friends[idx][t_idx] == REL_REQ_SENT) {
                send_msg(idx, "Request already pending.\n");
            } else {
                friends[idx][t_idx] = REL_REQ_SENT;
                friends[t_idx][idx] = REL_REQ_RCVD;
                
                send_msg(idx, "Request sent. Waiting for them to accept.\n");
                sprintf(out, "New Chat Request from '%s'. Type '/accept %s' to connect.\n", clients[idx].name, clients[idx].name);
                send_msg(t_idx, out);
            }
        }

        // --- COMMAND: /accept [name] ---
        else if (strncmp(buf, "/accept ", 8) == 0) {
            char *target_name = buf + 8;
            int t_idx = find_user_by_name(target_name);

            if (t_idx != -1 && friends[idx][t_idx] == REL_REQ_RCVD) {
                friends[idx][t_idx] = REL_FRIENDS;
                friends[t_idx][idx] = REL_FRIENDS;
                
                send_msg(idx, "Connected! You can now private message.\n");
                sprintf(out, "%s accepted your request. You can now private message.\n", clients[idx].name);
                send_msg(t_idx, out);
            } else {
                send_msg(idx, "No pending request from that user.\n");
            }
        }

        // --- PRIVATE MESSAGING: @name msg ---
        else if (buf[0] == '@') {
            char *space = strchr(buf, ' ');
            if (space) {
                *space = '\0';
                char *target_name = buf + 1;
                char *msg_content = space + 1;
                int t_idx = find_user_by_name(target_name);

                if (t_idx != -1) {
                    if (friends[idx][t_idx] == REL_FRIENDS) {
                        sprintf(out, "[%s]: %s\n", clients[idx].name, msg_content);
                        send_msg(t_idx, out);
                        send_msg(idx, "Sent.\n");
                    } else {
                        send_msg(idx, "Error: You are not connected with this user.\n");
                    }
                } else {
                    send_msg(idx, "User not found.\n");
                }
            }
        }
        else {
            send_msg(idx, "Unknown command. Use /chat [name], /accept [name], /list, or @name [msg].\n");
        }

        pthread_mutex_unlock(&lock);
    }
    return NULL;
}

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

    if ((listener = socket(PF_INET, SOCK_STREAM, 0)) < 0) { perror("socket"); exit(1); }
    int opt = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (bind(listener, (struct sockaddr *)&sin, sizeof(sin)) < 0) { perror("bind"); exit(1); }
    if (listen(listener, MAX_PENDING) < 0) { perror("listen"); exit(1); }

    // Init Globals
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].active = 0;
        for (int j = 0; j < MAX_CLIENTS; j++) friends[i][j] = REL_NONE;
    }

    printf("Blind Private Network running on port %d.\n", SERVER_PORT);
    printf("Admin restricted to /list.\n");

    fd_set readfds;
    int max_fd;
    char input_buf[MAX_LINE];

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(listener, &readfds);      
        FD_SET(STDIN_FILENO, &readfds);  
        max_fd = listener > STDIN_FILENO ? listener : STDIN_FILENO;

        if (select(max_fd + 1, &readfds, NULL, NULL, NULL) < 0) continue;

        if (FD_ISSET(listener, &readfds)) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int new_s = accept(listener, (struct sockaddr *)&client_addr, &addr_len);

            if (new_s >= 0) {
                pthread_mutex_lock(&lock);
                int slot = -1;
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (!clients[i].active) {
                        slot = i;
                        clients[i].socket = new_s;
                        clients[i].active = 1; 
                        break;
                    }
                }
                pthread_mutex_unlock(&lock);

                if (slot == -1) {
                    close(new_s);
                } else {
                    SSL *ssl = SSL_new(ctx);
                    SSL_set_fd(ssl, new_s);
                    if (SSL_accept(ssl) <= 0) {
                        ERR_print_errors_fp(stderr);
                        close(new_s);
                        clients[slot].active = 0;
                    } else {
                        clients[slot].ssl = ssl;
                        pthread_t tid;
                        int *pidx = malloc(sizeof(int));
                        *pidx = slot;
                        pthread_create(&tid, NULL, client_handler, pidx);
                        pthread_detach(tid);
                    }
                }
            }
        }

        // Admin (Restricted to /list)
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            if (fgets(input_buf, sizeof(input_buf), stdin)) {
                input_buf[strcspn(input_buf, "\n")] = 0;
                if (strcmp(input_buf, "/list") == 0) {
                    printf("Active Clients: ");
                    pthread_mutex_lock(&lock);
                    for(int i=0; i<MAX_CLIENTS; i++) {
                        if (clients[i].active) printf("[%s] ", clients[i].name);
                    }
                    pthread_mutex_unlock(&lock);
                    printf("\n");
                } else {
                    printf("Admin restricted to /list only.\n");
                }
            }
        }
    }

    close(listener);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}