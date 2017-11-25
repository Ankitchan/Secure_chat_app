#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8080
#define FAIL -1

int OpenConnection(const char *hostname, int port)
{
	int sd;
	struct hostent *host;
	struct sockaddr_in addr;

	if((host = gethostbyname(hostname)) == NULL)
	{
		perror(hostname);
		abort();
	}
	sd = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = *(long*)(host->h_addr);
	if(connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
	{
		close(sd);
		perror(hostname);
		abort();
	}
	return sd;
}

SSL_CTX* InitCTX(void)
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	method = TLSv1_2_client_method();
	ctx = SSL_CTX_new(method);
	if(ctx == NULL)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}

void ShowCerts(SSL* ssl)
{
	X509 *cert;
	char *line;

	cert = SSL_get_peer_certificate(ssl);
	if(cert != NULL)
	{
		printf("Server certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line );
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line );
		free(line);
		X509_free(cert);
	}
	else
	{
		printf("Info: No client certificates configured.\n");
	}
}

int main(int argc, char *argv[])
{
	/*struct sockaddr_in addr;
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
	printf("%s\n",buffer);*/

	SSL_CTX *ctx;
	int server_fd;
	SSL *ssl;
	char buffer[1024];
	int bytes;
	char *hostname, *portnum;

	if(argc != 3)
	{
		printf("usage %s <hostname> <portnum>\n", argv[0] );
		exit(0);
	}
	SSL_library_init();
	hostname = argv[1];
	portnum = argv[2];

	ctx = InitCTX();
	server_fd = OpenConnection(hostname, atoi(portnum));
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, server_fd);
	if(SSL_connect(ssl) == FAIL)
		ERR_print_errors_fp(stderr);
	else
	{
		bytes = SSL_read(ssl, buffer, sizeof(buffer));
		buffer[bytes] = '\0'; 
		printf("Received: %s\n", buffer);

		char msg[1024];
		printf("Enter message to send(not more than 1024 char)\n");
		scanf("%s",msg);
		
		printf("\n\n Connected with %s encryption\n", SSL_get_cipher(ssl));
		ShowCerts(ssl);
		
		SSL_write(ssl, msg, strlen(msg));
		printf("Sent %s\n", msg);
		
		bytes = SSL_read(ssl, buffer, sizeof(buffer));
		buffer[bytes] = '\0'; 
		printf("Received: %s\n", buffer);
		
		SSL_free(ssl);
	}
	close(server_fd);
	SSL_CTX_free(ctx);
	return 0;
}
