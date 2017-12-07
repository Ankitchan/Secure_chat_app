# Secure_chat_app
Steps to run the application
1. Generate SSL/TLS key using

openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout mycert.pem -out mycert.pem

2. Generate client RSA keys

openssl genpkey -algorithm RSA -out client_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in client_private.pem  -out client_public.pem

3. Generate server RSA keys

openssl genpkey -algorithm RSA -out server_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in server_private.pem  -out server_public.pem

4. Compile and run the server side

gcc server.c -o server -L /usr/lib -lssl -lcrypto

sudo ./server <port num>

5. Compile and runthe client side

gcc client.c -o client -L /usr/lib -lssl -lcrypto

./client 127.0.0.1 <port num>

Note: 
1. Ignore any warnings generated
2. Port number should be same for both and client
3. While running client, if the server is on other ip address then the localhost is replaced with the ipaddress of server 
