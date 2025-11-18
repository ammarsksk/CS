// Source: https://book.systemsapproach.org/foundation/software.html

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#define SERVER_PORT 5432
#define MAX_LINE 256

// --- CHANGED FUNCTION START ---
SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* * ENABLING STRICT VERIFICATION 
     * 1. SSL_VERIFY_PEER: Tells client to fail if server cert is invalid.
     * 2. SSL_CTX_load_verify_locations: Loads "cert.pem" as the "Trusted CA".
     * In a real browser, this loads hundreds of Root CAs (Verisign, etc).
     * Here, we trust only our specific server certificate.
     */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    if (SSL_CTX_load_verify_locations(ctx, "cert.pem", NULL) != 1) {
        fprintf(stderr, "Error loading trust store (cert.pem).\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}
// --- CHANGED FUNCTION END ---

int main(int argc, char * argv[])
{
  struct hostent *hp;
  struct sockaddr_in sin;
  char *host;
  char buf[MAX_LINE];
  int s;
  int len, max_fd = STDIN_FILENO;
    fd_set readfds;
    struct timeval tv;
    int activity;
    
    // Initialize Context with VERIFICATION enabled
    SSL_CTX *ctx = create_context();
    SSL *ssl = NULL; 

  if (argc==2) {
    host = argv[1];
  }
  else {
        host = "localhost";
  }

  hp = gethostbyname(host);
  if (!hp) {
    fprintf(stderr, "simplex-talk: unknown host: %s\n", host);
    exit(1);
  }

  bzero((char *)&sin, sizeof(sin));
  sin.sin_family = AF_INET;
  bcopy(hp->h_addr, (char *)&sin.sin_addr, hp->h_length);
  sin.sin_port = htons(SERVER_PORT);

  if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket");
    exit(1);
  }
  
  if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) < 0)
  {
    perror("connect");
    close(s);
    exit(1);
  }
    
    ssl = SSL_new(ctx); 
    SSL_set_fd(ssl, s);
    
    // Enable hostname verification (Important for strict security!)
    // This ensures the cert isn't just valid, but is valid for "localhost" specifically.
    SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (!SSL_set1_host(ssl, "localhost")) {
        fprintf(stderr, "Failed to set hostname verification\n");
        goto cleanup;
    }

    // If verification fails, SSL_connect will return < 0 here
    if (SSL_connect(ssl) <= 0) {
        printf("Handshake failed. Server certificate invalid or not trusted.\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    printf("Connected securely to %s using %s\n", host, SSL_get_cipher(ssl));
    // Print the Subject of the certificate we just verified
    X509 *cert = SSL_get_peer_certificate(ssl);
    if(cert) { 
        char *line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Verified Server Subject: %s\n", line);
        free(line);
        X509_free(cert);
    }

    max_fd = (s > max_fd) ? s : max_fd;

    while(1) {
        FD_ZERO(&readfds);
        FD_SET(s, &readfds);
        FD_SET(STDIN_FILENO, &readfds);

        tv.tv_sec = 30;
        tv.tv_usec = 0;

        activity = select(max_fd + 1, &readfds, NULL, NULL, &tv);

        if (activity < 0) {
            perror("select");
            break;
        } else if (activity == 0) {
            printf("No activity for 30 secs.\n");
            continue;
        }

        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            if (fgets(buf, sizeof(buf), stdin) != NULL) {
            buf[MAX_LINE-1] = '\0';
            len = strlen(buf);
            if (SSL_write(ssl, buf, len) <= 0) {
                    perror("SSL write failed");
                    break;
                }
            }
        }

        if (FD_ISSET(s, &readfds)) {
            int bytes = SSL_read(ssl, buf, sizeof(buf) - 1);
            if (bytes <= 0) {
                printf("server disconnected.\n");
                break;
            }
            buf[bytes] = '\0';
            printf("%s\n", buf);
        }
    }
    
cleanup:
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    close(s);
    SSL_CTX_free(ctx);
    return 0;
}