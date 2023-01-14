#include "api.h"

int main(int argc, char **argv)
{
    int port = atoi(argv[1]);

    int socketRecv = -1;
    int socketSend = -1;
    char buffer[1024] = {'\0'};

    // Create socket
    if ((socketRecv = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
        printf("Error: Cannot create socket : %d", errno);
        return -1;
    }

    if ((socketSend = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
        printf("Error: Cannot create socket : %d", errno);
        return -1;
    }

    // setup Server address structure
    struct sockaddr_in serverAddress;
    memset((char *)&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(port);

    // Bind
    if (bind(socketRecv, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) == -1)
    {
        printf("ERROR: bind() failed with error code : %d", errno);
        return -1;
    }

    memset((char *)&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(port + 1);

    if (bind(socketSend, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) == -1)
    {
        printf("ERROR: bind() failed with error code : %d", errno);
        return -1;
    }

    struct sockaddr_in clientAddress;
    socklen_t clientAddressLen = sizeof(clientAddress);

    memset((char *)&clientAddress, 0, sizeof(clientAddress));

    // the Main Loop
    while (1)
    {
        memset((char *)&clientAddress, 0, sizeof(clientAddress));
        clientAddressLen = sizeof(clientAddress);

        memset(buffer, '\0', sizeof(buffer));

        int recv_len = -1;

        printf("Recving...\n");
        if ((recv_len = recvfrom(socketRecv, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&clientAddress, &clientAddressLen)) == -1)
        {
            printf("ERROR: recvfrom() failed with error code : %d", errno);
        }

        if (recv_len > 0)
        {
            printf("Sending...\n");
            if (sendto(socketSend, buffer, recv_len, 0, (struct sockaddr *)&clientAddress, clientAddressLen) == -1)
            {
                printf("sendto() failed with error code : %d", errno);
            }
        }
    }

    close(socketRecv);
    close(socketSend);

    return 0;
}
