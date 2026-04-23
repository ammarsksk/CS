# BLIND - Private Chat Network

BLIND is a secure, multi-threaded private chat network implemented in C. It uses SSL/TLS for end-to-end encrypted communication and pthreads to handle multiple concurrent clients.

## Features

- **End-to-End Encryption**: All traffic between client and server is encrypted using TLS 1.3 via OpenSSL.
- **Multi-threaded Architecture**: The server uses a thread-per-client model for high concurrency.
- **Relationship-Based Chat**: Users must send and accept chat requests before they can exchange private messages.
- **Secret Identities**: Users register with a "secret name" upon connection.
- **Admin Control**: Local server administrator can monitor active connections.

---

## Project Structure

- `threads.c`: The core server implementation. Handles socket management, SSL handshaking, and the command protocol.
- `client.c`: A secure client that connects to the BLIND network, verifies server certificates, and handles user interactions.
- `Makefile`: Build script for the project.
- `cert.pem`: Public certificate (used by both server and client for verification).
- `key.pem`: Private key for the server.
- `combined.pem`: Concatenated certificate and private key for server-side SSL context.

---

## Getting Started

### Prerequisites

- GCC compiler
- OpenSSL development libraries (`libssl-dev` on Ubuntu/Debian)
- POSIX threads support

### Build

Run the following command to compile both the client and the server:

```bash
make
```

### Running the Server

Start the server by providing the combined PEM file:

```bash
./threads combined.pem
```
The server will start listening on port `5432`.

### Running the Client

Connect to a running server (defaults to localhost):

```bash
./client [hostname]
```

---

## In-Chat Commands

Once connected and registered with a secret name, use the following commands:

| Command | Action |
| :--- | :--- |
| `/list` | List all your connected friends. |
| `/chat [name]` | Send a connection request to another user. |
| `/accept [name]` | Accept a pending connection request from a user. |
| `@name [msg]` | Send a private message to a connected friend. |

### Admin Commands (Server STDIN)
- `/list`: Lists all currently active users in the network.

---

## Security Model

1. **TLS Handshake**: The client verifies the server's certificate against `cert.pem` and ensures the hostname matches (defaulting to `localhost`).
2. **Data Integrity**: All messages are passed through `SSL_write` and `SSL_read`, ensuring they cannot be intercepted or tampered with in transit.
3. **Privacy**: Users can only message those they have explicitly accepted as contacts.
