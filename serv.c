#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>

#define PORT 8888

int main(int argc, char *argv[])
{
	int server_fd, new_socket, valread,client_socket[30], max_clients = 30, activity, i,sd, max_sd;
	struct sockaddr_in addr;
	int opt = 1;
	int addrlen = sizeof(addr);
	char buffer[1025] ;

	char *msg = "Server running...";

	fd_set readfds;

	for(i=0;i<max_clients;i++)
	{
		client_socket[i] = 0;
	}

	if((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
	{
		perror("socket failed");
		exit(EXIT_FAILURE);
	}

	if(setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR,(char *) &opt, sizeof(opt)) < 0)
	{
		perror("set socket opt failed");
		exit(EXIT_FAILURE);
	}

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(PORT);

	if(bind(server_fd, (struct sockaddr *) &addr, sizeof(addr))<0)
	{
		perror("bind failed");
		exit(EXIT_FAILURE);
	}

	if(listen(server_fd, 3) < 0)
	{
		perror("listen failed");
		exit(EXIT_FAILURE);
	}

	printf("\n Waiting for connections....\n");

	while(1)
	{
	
		FD_ZERO(&readfds);

		FD_SET(server_fd, &readfds);
		max_sd = server_fd;

		for( i=0; i < max_clients; i++)
		{
			sd = client_socket[i];

			if(sd > 0)
				FD_SET(sd, &readfds);

			if(sd > max_sd)
				max_sd = sd;
		}

		activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);

		if((activity < 0) && (errno != EINTR))
		{
			printf("select error");
		}

		if(FD_ISSET(server_fd, &readfds))
		{
			if((new_socket = accept(server_fd, (struct sockaddr *)&addr,(socklen_t *)&addrlen)) < 0)
			{
				perror("accept error");
				exit(EXIT_FAILURE);
			}		

			printf("New Connection. socket fd is %d , ip is : %s , port : %d\n", new_socket,  inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

			if( send(new_socket, msg , strlen(msg), 0) != strlen(msg))
			{
				perror("send err");
			}

			puts("Welcome message sent successfully");

			for( i=0; i<max_clients;i++)
			{
				if(client_socket[i] == 0)
				{
					client_socket[i] = new_socket;
					printf("Adding to list of socets as %d\n", i);
				}
			}
		}

		for( i=0; i<max_clients; i++)
		{
			sd = client_socket[i];
			
			if(FD_ISSET(sd, &readfds))
			{
				if((valread = read(sd, buffer, 1024)) == 0)
				{
					getpeername(sd, (struct sockaddr*)&addr, (socklen_t *)&addrlen);
					printf("Host disconnected, ip %s, port %d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

					close(sd);
					client_socket[i] = 0;
				}

				else
				{
					buffer[valread] = '\0';
					send(sd, buffer, strlen(buffer), 0);
				}
			}
		}
	}

	return 0;

}
