#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

#define FAIL    -1

int padding = RSA_PKCS1_PADDING;

// Create the SSL socket and intialize the socket address structure
int OpenListener(int port)
{   
	int sd;
	struct sockaddr_in addr;
	sd = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
	{
		perror("can't bind port");
		abort();
	}
	if ( listen(sd, 10) != 0 )
	{
		perror("Can't configure listening port");
		abort();
	}
	return sd;
}

int isRoot()
{
	if (getuid() != 0)
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
	OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
	SSL_load_error_strings();   /* load all error messages */
	method = TLSv1_2_server_method();  /* create new server-method instance */													// First warning
	ctx = SSL_CTX_new(method);   /* create new context from method */
	if ( ctx == NULL )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}


void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
	/* set the local certificate from CertFile */
	if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* set the private key from KeyFile (may be the same as CertFile) */
	if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* verify private key */
	if ( !SSL_CTX_check_private_key(ctx) )
	{
		fprintf(stderr, "Private key does not match the public certificate\n");
		abort();
	}
}


void ShowCerts(SSL* ssl)
{   
	X509 *cert;
	char *line;
	cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
	if ( cert != NULL )
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
		printf("No certificates.\n");
}


void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{   
	char buffer[1024] = {0};
	int sd, bytes;
							 
	if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
		ERR_print_errors_fp(stderr);
	else
	{
		ShowCerts(ssl);        /* get any certificates */
		bytes = SSL_read(ssl, buffer, sizeof(buffer)); /* get request */
		buffer[bytes] = '\0';
		printf("Client msg: \"%s\"\n", buffer);
		if ( bytes > 0 )
		{
			unsigned char  encrypted[4098]={};
			unsigned char decrypted[4098]={};

			int decrypted_length = private_decrypt(buffer, (int) strlen(buffer),  "private.pem", decrypted);
			if(decrypted_length == -1)
			{
			    printLastError("Private decryption failed\n");
			    exit(0);
			}
			
			printf("Received from client: %s\n", decrypted);			


			printf("Buffer: %s\n", buffer);
			printf("strlen: %d\n", (int) strlen(buffer));
			printf("decrypted: %s\n", decrypted);
			int encrypted_length= public_encrypt(decrypted,decrypted_length, "public.pem",encrypted); //encrypted contains the re-encrypted message
			if(encrypted_length == -1)
			{
			    printf("Public Encrypt failed\n");
			    exit(0);
			}

			SSL_write(ssl, encrypted, strlen(encrypted));
	
		}
		else
		{
			ERR_print_errors_fp(stderr);
		}
	}
	sd = SSL_get_fd(ssl);       /* get socket connection */
	SSL_free(ssl);         /* release SSL state */
	close(sd);          /* close connection */
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

int main(int count, char *Argc[])
{   
	SSL_CTX *ctx;
	int server;
	char *portnum;
	//Only root user have the permsion to run the server
	if(!isRoot())
	{
		printf("This program must be run as root/sudo user!!\n");
		exit(0);
	}
	if ( count != 2 )
	{
		printf("Usage: %s <portnum>\n", Argc[0]);
		exit(0);
	}
	// Initialize the SSL library
	SSL_library_init();
	portnum = Argc[1];
	ctx = InitServerCTX();        /* initialize SSL */
	LoadCertificates(ctx, "mycert.pem", "mycert.pem"); /* load certs */
	server = OpenListener(atoi(portnum));    /* create server socket */
	while (1)
	{   
		struct sockaddr_in addr;
		socklen_t len = sizeof(addr);
		SSL *ssl;
		int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
		printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
		ssl = SSL_new(ctx);              /* get new SSL state with context */
		SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
		Servlet(ssl);         /* service connection */
	}
	close(server);          /* close server socket */
	SSL_CTX_free(ctx);         /* release context */
}