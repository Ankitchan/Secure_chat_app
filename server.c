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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>


#define PORT 8888
#define FAIL -1

int padding = RSA_PKCS1_PADDING;

int OpenListener(int port)
{
	int sd;
	struct sockaddr_in addr;

	sd = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;

	if(bind(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
	{
		perror("can't bind port");
		abort();
	}
	if(listen(sd, 10) != 0)
	{
		perror("can't configure listening port");
		abort();
	}
	return sd;
}

int isRoot()
{
	if(getuid() != 0)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}

SSL_CTX* InitServerCTX(void)
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	method = TLSv1_2_server_method();
	ctx = SSL_CTX_new(method);
	if(ctx == NULL)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;

}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
	if(SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}

	if(SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}

	if(!SSL_CTX_check_private_key(ctx))
	{
		fprintf(stderr, "Private key does not match the public certificates\n" );
		abort();
	}
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
		printf("Subject: %s\n", line);
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);
		X509_free(cert);
	}
	else 
	{
		printf("No certificates.\n");
	}
}

void ServResponse(SSL *ssl, char *msg)
{
	//char buf[1024] = {0};

	int valwrite;

	if(SSL_accept(ssl) == FAIL)
		ERR_print_errors_fp(stderr);
	else
	{
		ShowCerts(ssl);
		// bytes = SSL_read(ssl, buf, sizeof(buf));
		// buf[bytes] = '\0';
		// printf("Client msg: \"%s\"\n", buf);
		// if(bytes > 0)
		// {
		// 	if(strcmp(cpValidMsg, buf) == 0)
		// 	{
		// 		SSL_write(ssl, ServResp, strlen(ServResp));
		// 	}
		// 	else
		// 	{
		// 		SSL_write(ssl, "Invalid Msg", strlen("Invalid Msg"));
		// 	}
		// }
		// else
		if((valwrite = SSL_write(ssl, msg, strlen(msg))) > 0)
		{
			printf("Sent %s\n", msg);
			puts("message sent successfully");	
		}
		else if(valwrite == 0)
		{
			printf("%d\n",SSL_get_error(ssl, valwrite));
			ERR_print_errors_fp(stderr);
			abort();
		}
		else
		{
			printf("Error in sending a message\n");
			ERR_print_errors_fp(stderr);
			abort();
		}
		
	}
	//sd = SSL_get_fd(ssl);
	//SSL_free(ssl);
	//close(sd);
}


RSA * createRSAWithFilename( char * filename,int public)
{
    FILE * fp = fopen(filename,"rb");
 
    if(fp == NULL)
    {
        printf("Unable to open file %s \n",filename);
        return NULL;    
    }
    RSA *rsa= RSA_new() ;
 
    if(public)
    {
        rsa = PEM_read_RSA_PUBKEY(fp, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_RSAPrivateKey(fp, &rsa,NULL, NULL);
    }
 
    return rsa;
}

int public_encrypt(unsigned char * data,int data_len, char * key_file_name, unsigned char *encrypted)
{
    RSA * rsa = createRSAWithFilename(key_file_name,1);
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}

int private_decrypt(unsigned char * enc_data,int data_len, char * key_file_name, unsigned char *decrypted)
{
    RSA * rsa = createRSAWithFilename(key_file_name,0);
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}

int main(int argc, char *argv[])
{
	int server_fd, new_socket, valread,client_socket[30], max_clients = 30, activity, i,sd, max_sd;
	struct sockaddr_in addr;
	//int opt = 1;
	int addrlen = sizeof(addr);
	char *buffer = "";

	char *msg = "Server running...";

	fd_set readfds;

	SSL_CTX *ctx;
	char *portnum;

	if(!isRoot())
	{
		printf("This program must be run as root/sudo user!!");
		abort();
	}

	if(argc != 2)
	{
		printf("Usage %s <portnum>\n",  argv[0]);
	}
	for(i=0;i<max_clients;i++)
	{
		client_socket[i] = 0;
	}

	SSL_library_init();

	portnum = argv[1];
	ctx = InitServerCTX();
	LoadCertificates(ctx, "mycert.pem", "mycert.pem");
	server_fd = OpenListener(atoi(portnum));
	// if((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
	// {
	// 	perror("socket failed");
	// 	exit(EXIT_FAILURE);
	// }

	// if(setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR,(char *) &opt, sizeof(opt)) < 0)
	// {
	// 	perror("set socket opt failed");
	// 	exit(EXIT_FAILURE);
	// }

	// addr.sin_family = AF_INET;
	// addr.sin_addr.s_addr = INADDR_ANY;
	// addr.sin_port = htons(PORT);

	// if(bind(server_fd, (struct sockaddr *) &addr, sizeof(addr))<0)
	// {
	// 	perror("bind failed");
	// 	exit(EXIT_FAILURE);
	// }

	// if(listen(server_fd, 3) < 0)
	// {
	// 	perror("listen failed");
	// 	exit(EXIT_FAILURE);
	// }

	printf("\n Waiting for connections....\n");

	while(1)
	{
		SSL *ssl;
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
			printf("select error\n");
		}
		printf("%d\n", server_fd);

		if(FD_ISSET(server_fd, &readfds))
		{
			printf("Bye\n");
			if((new_socket = accept(server_fd, (struct sockaddr *)&addr,(socklen_t *)&addrlen)) < 0)
			{
				printf("Delta");
				perror("accept error");
				exit(EXIT_FAILURE);
			}		

			printf("New Connection. socket fd is %d , ip is : %s , port : %d\n", new_socket,  inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

			ssl = SSL_new(ctx);
			SSL_set_fd(ssl, new_socket);
			ServResponse(ssl, msg);
			//if( send(new_socket, msg , strlen(msg), 0) != strlen(msg))

			printf("Charlie\n");
			

			for( i=0; i<max_clients;i++)
			{
				if(client_socket[i] == 0)
				{
					printf("%d\n", new_socket);
					client_socket[i] = new_socket;
					printf("Adding to list of sockets as %d\n", i);
				}
			}
		}
		for( i=0; i<max_clients; i++)
		{
			sd = client_socket[i];
			printf("%d\n", sd);

			printf("%d\n", FD_ISSET(sd, &readfds));
			if(FD_ISSET(sd, &readfds) > 0)
			{
				printf("X\n");
				if((valread = SSL_read(ssl, buffer, strlen(buffer))) == 0)
				{
					printf("Z\n");
					getpeername(sd, (struct sockaddr*)&addr, (socklen_t *)&addrlen);
					printf("Host disconnected, ip %s, port %d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

					close(sd);
					client_socket[i] = 0;
				}

				else if(valread > 0)
				{
					printf("A\n");
					buffer[valread] = '\0';
					// If the message is encrypted 

					unsigned char  encrypted[4098]={};
					unsigned char decrypted[4098]={};
					printf("B\n");
					int decrypted_length = private_decrypt((unsigned char *) buffer, (int) strlen(buffer),  "private.pem", decrypted);
					if(decrypted_length == -1)
					{
					    printf("Private decryption failed ");
					    exit(0);
					}
					printf("C\n");
					int encrypted_length= public_encrypt(decrypted,decrypted_length, "public.pem",encrypted); //encrypted contains the re-encrypted message
					if(encrypted_length == -1)
					{
					    printf("Public Encrypt failed ");
					    exit(0);
					}
					printf("D\n");
					//send(sd, encrypted, strlen(encryped), 0);
					printf("Received: %s\n", buffer);

					ServResponse(ssl, (char *)encrypted);
					printf("E\n");
					//ServResponse(ssl, encrypted);			sends encrypted message
				}
			}
		}
		
		sd = SSL_get_fd(ssl);       /* get socket connection */
    	SSL_free(ssl);         /* release SSL state */
    	close(sd);  
	}

	close(server_fd);
	SSL_CTX_free(ctx);
	return 0;

}
