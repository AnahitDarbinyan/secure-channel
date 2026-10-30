#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 5000

int main(void)
{
    int server_fd;
    int client_fd;

    struct sockaddr_in server_addr;

    char buffer[1024] = {0};
    char response[] = "Hello Device1! Message received by Device2.";

    server_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (server_fd < 0) {
        perror("Socket creation failed");
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr,
             sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 1) < 0) {
        perror("Listen failed");
        close(server_fd);
        return 1;
    }

    printf("Device2 is waiting for Device1 on port %d...\n", PORT);

    client_fd = accept(server_fd, NULL, NULL);

    if (client_fd < 0) {
        perror("Connection failed");
        close(server_fd);
        return 1;
    }

    printf("Device1 connected successfully!\n");

    int bytes_received = recv(client_fd, buffer,
                              sizeof(buffer) - 1, 0);

    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        printf("Message received: %s\n", buffer);

        send(client_fd, response, strlen(response), 0);
        printf("Response sent to Device1.\n");
    }

    close(client_fd);
    close(server_fd);

    return 0;
}
