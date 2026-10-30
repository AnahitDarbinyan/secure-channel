#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 5000

int main(void)
{
    int sock;
    struct sockaddr_in server_addr;

    char message[] = "Hello from Device1!";
    char buffer[1024] = {0};

    sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock < 0) {
        perror("Socket creation failed");
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1",
                  &server_addr.sin_addr) <= 0) {
        printf("Invalid server address.\n");
        close(sock);
        return 1;
    }

    printf("Device1 connecting to Device2...\n");

    if (connect(sock, (struct sockaddr *)&server_addr,
                sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return 1;
    }

    printf("Connected to Device2!\n");

    send(sock, message, strlen(message), 0);

    printf("Message sent: %s\n", message);

    int bytes_received = recv(sock, buffer,
                              sizeof(buffer) - 1, 0);

    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        printf("Response from Device2: %s\n", buffer);
    }

    close(sock);

    return 0;
}
