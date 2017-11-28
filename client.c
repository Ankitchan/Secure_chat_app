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
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#define PORT 8080
#define FAIL -1
#define KEY_LENGTH  2048
#define PUB_EXP     3
#define PRINT_KEYS
#define WRITE_TO_FILE

int padding = RSA_PKCS1_PADDING;

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


RSA * createRSAWithFilename(char * filename,int public)
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

void printLastError(char *msg)
{
    char * err = malloc(130);;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n",msg, err);
    free(err);
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
	char resp1[16], resp2[16];

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
		printf("Enter message to send(not more than 214 char)\n");
		scanf("%s",msg);
		// start encryption

		unsigned char  encrypted[4098]={};
		unsigned char decrypted[4098]={};
		
		int encrypted_length= public_encrypt((unsigned char *) msg,strlen(msg),"public.pem",encrypted);
		if(encrypted_length == -1)
		{
		    printLastError("Public Encrypt failed ");
		    exit(0);
		}

		// encryption finished
		// now we have the ciphertext in encrypted

		printf("Would you like to receive the ciphertext? (Y/N)\n");
		scanf("%s", resp1);
		printf("A");
		if(strcmp(resp1, "Y") == 0 || strcmp(resp1, "y") == 0) {
			printf("%s\n", encrypted);
		}

		printf("Would you like to send message to the server? (Y/N)\n");
		scanf("%s", resp2);

		if(strcmp(resp2, "Y") == 0 || strcmp(resp2, "y") == 0) {
			ShowCerts(ssl);
			SSL_write(ssl, encrypted, strlen((char *) encrypted));
			printf("Sent %s\n", encrypted);
		}
		
		
		bytes = SSL_read(ssl, buffer, sizeof(buffer));
		buffer[bytes] = '\0'; 

		printf("Received: %s\n", buffer);

		int decrypted_length = private_decrypt((unsigned char * )buffer, (int) strlen(buffer), "private.pem", decrypted);
		if(decrypted_length == -1)
		{
		    printLastError("Private decryption failed ");
		    exit(0);
		}


		
		
		SSL_free(ssl);
	}
	close(server_fd);
	SSL_CTX_free(ctx);
	return 0;
}
