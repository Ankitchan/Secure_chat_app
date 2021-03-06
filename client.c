#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

#define FAIL    -1

int padding = RSA_PKCS1_PADDING;

int OpenConnection(const char *hostname, int port)
{   
	int sd;
	struct hostent *host;
	struct sockaddr_in addr;
	if ( (host = gethostbyname(hostname)) == NULL )
	{
		perror(hostname);
		abort();
	}
	sd = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = *(long*)(host->h_addr);
	if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
	{
		close(sd);
		perror(hostname);
		abort();
	}
	return sd;
}


SSL_CTX* InitCTX(void)
{   
	SSL_METHOD *method;
	SSL_CTX *ctx;
	OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
	SSL_load_error_strings();   /* Bring in and register error messages */
	method = TLSv1_2_client_method();  /* Create new client-method instance */
	ctx = SSL_CTX_new(method);   /* Create new context */
	if ( ctx == NULL )
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
	cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
	if ( cert != NULL )
	{
		//printf("Server certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		//printf("Subject: %s\n", line);
		free(line);       /* free the malloc'ed string */
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		//printf("Issuer: %s\n", line);
		free(line);       /* free the malloc'ed string */
		X509_free(cert);     /* free the malloc'ed certificate copy */
	}
	else
		printf("Info: No client certificates configured.\n");
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

int public_encrypt(unsigned char * data,int data_len, unsigned char *encrypted)
{
    RSA * rsa = createRSAWithFilename("server_public.pem",1);
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}

int private_decrypt(unsigned char * enc_data,int data_len, unsigned char *decrypted)
{
    RSA * rsa = createRSAWithFilename("client_private.pem",0);
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


int main(int count, char *strings[])
{   
	SSL_CTX *ctx;
	int server;
	SSL *ssl;
	char buffer[2048/8];
	int bytes;
	char resp1[16], resp2[16];
	char *hostname, *portnum;
	unsigned char  encrypted[4098]={};
	unsigned char decrypted[4098]={};
	
	if ( count != 3 )
	{
		printf("usage: %s <hostname> <portnum>\n", strings[0]);
		exit(0);
	}
	SSL_library_init();
	hostname=strings[1];
	portnum=strings[2];
	ctx = InitCTX();
	server = OpenConnection(hostname, atoi(portnum));
	ssl = SSL_new(ctx);      /* create new SSL connection state */
	SSL_set_fd(ssl, server);    /* attach the socket descriptor */
	if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
		ERR_print_errors_fp(stderr);
	else
	{  
		
		
		printf("Enter message to send(not more than 244 char)\n");
		fgets(buffer, 256-1, stdin);

		if(strlen(buffer) > 245)
		{
			printf("Input too large\n");
			exit(0);
		}
		//printf("%d",(int)strlen(buffer));
		// encrypt the plaintext

		int encrypted_length= public_encrypt(buffer,strlen(buffer),encrypted);
		if(encrypted_length == -1)
		{
		    printLastError("Public Encrypt failed ");
		    exit(0);
		}

		// return the ciphertext

		printf("\n\nWould you like to receive the ciphertext? (Y/N)\n");
		scanf("%s", resp1);
		printf("\n\n");
		printf("%s", encrypted);
		if(strcmp(resp1, "Y") == 0 || strcmp(resp1, "y") == 0) {
			for(int i = 0; i < 255; ++i) {
				printf("%d,", (int) *(encrypted + i));
			}
			printf("%d", (int) *(encrypted + 255));
		}

		// send the message to server at user's request

		printf("\n\n\n\nWould you like to send message to the server? (Y/N)\n");
		scanf("%s", resp2);

		if(strcmp(resp2, "Y") == 0 || strcmp(resp2, "y") == 0) {
			
			
			ShowCerts(ssl);
			SSL_write(ssl, encrypted, 256);

			// Receive message from server

			bytes = SSL_read(ssl, buffer, 256);
			buffer[bytes] = '\0'; 

			//printf("%d", (int) *(encrypted + 255));		


			int decrypted_length = private_decrypt(buffer,256,decrypted);
			if(decrypted_length == -1)
			{
			    printLastError("Private Decrypt failed ");
			    exit(0);
			}

			printf("\n\n\n\nReceived from server: \n\n%s\n", decrypted);
		}
		
		SSL_free(ssl);        /* release connection state */
	}
	close(server);         /* close socket */
	SSL_CTX_free(ctx);        /* release context */
	return 0;
}
