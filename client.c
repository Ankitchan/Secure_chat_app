//#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define PORT 8080

int main(int argc, const *argv[])
{
	struct sockaddr_in addr;
	int sock = 0, valread;
	struct sockaddr_in serv_addr;
	char *msg = "Hello from client";
	char buffer[1024] = {0};
	if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		//cout<<endl<<" Socket creation err "<<endl;
		printf(" Socket creation err \n");
		return -1;
	}

	memset(&serv_addr, '0', sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);

	if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0)
	{
		//cout<<endl<<"Invalid addr"<<endl;
		printf("Invalid addr");
		return -1;
	}
	
	if(connect(sock, (struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0)
	{
		//cout<<endl<<"Connection Failed"<<endl;
		printf("Connection failed");
		return -1;
	}
	send(sock, msg, strlen(msg), 0);
	//cout<<"Hello msg send"<<endl;
	printf("Hello msg send");
	valread = read(sock, buffer, 1024);
	//cout<<buffer<<endl;
	printf("%s\n",buffer);
	return 0;
}
