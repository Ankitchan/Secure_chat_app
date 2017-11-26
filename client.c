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
#include <openssl/evp.h>

#define PORT 8080
#define FAIL -1
#define KEY_LENGTH  2048
#define PUB_EXP     3
#define PRINT_KEYS
#define WRITE_TO_FILE

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

//RSA* generate_key() {
//    	fflush(stdout);
//    	RSA *keypair = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);
//   	return keypair;
//}



//void generate_cstring_pem(BIO *pri, BIO* pub; char* pri_key, char* pub_key) {
//	pri = BIO_new(BIO_s_mem());
//    	pub = BIO_new(BIO_s_mem());
	
//	PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
//	PEM_write_bio_RSAPublicKey(pub, keypair);

//	pri_len = BIO_pending(pri);
//	pub_len = BIO_pending(pub);

//	pri_key = malloc(pri_len + 1);
//	pub_key = malloc(pub_len + 1);

//	BIO_read(pri, pri_key, pri_len);
//	BIO_read(pub, pub_key, pub_len);

//	pri_key[pri_len] = '\0';
//	pub_key[pub_len] = '\0';

//}


//int rsa_encrpyt(char* encrypted) {
//    encrypted = malloc(RSA_size(keypair));
//    int encrypt_len;
//    err = malloc(130);
//    if((encrypt_len = RSA_public_encrypt(strlen(msg)+1, (unsigned char*)msg, (unsigned char*)encrypt,
//                                         keypair, RSA_PKCS1_OAEP_PADDING)) == -1) {
//        ERR_load_crypto_strings();
//        ERR_error_string(ERR_get_error(), err);
//        fprintf(stderr, "Error encrypting message: %s\n", err);
//        goto free_stuff;
//    }

//    return encrypt_len
//}


//void deallocate() {
//	RSA_free(keypair);
//	BIO_free_all(pub);
  //  	BIO_free_all(pri);
//    	free(pri_key);
//    	free(pub_key);
//    	free(encrypt);
//    	free(decrypt);
//    	free(err);

//}

int main(int argc, char *argv[])
{
	//BIO *pri;
	//BIO *pub;
	//size_t pri_len;            // Length of private key
    	//size_t pub_len;            // Length of public key
    	//char   *pri_key;           // Private key
    	//char   *pub_key;           // Public key
    	//char   msg[KEY_LENGTH/8];  // Message to encrypt
    	//char   *encrypt = NULL;    // Encrypted message
    	//char   *decrypt = NULL;    // Decrypted message
    	//char   *err;               // Buffer for any error messages

	//RSA *keypair = generate_key()


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

		//if(// want encryption ) {
		//	int i = 0;
		//	for(i = 0; i < msg.size 
		//}
		
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
