#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>

#define PORT_NUMBER 55555
#define BUFF_SIZE 2000
struct sockaddr_in peerAddr;

#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }

int setupTCPServer();
void processRequest(SSL* ssl, int sock);
void TLStunSelected(int tunfd, int sockfd, SSL *ssl);
void TLSsocketSelected(int tunfd, int sockfd, SSL *ssl);
SSL* sslINIT();

SSL* sslINIT(){
  SSL_METHOD *meth;
  SSL_CTX* ctx;
  SSL *ssl;
  int err;

  SSL_library_init();
  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();

  meth = (SSL_METHOD *)TLSv1_2_method();
  ctx = SSL_CTX_new(meth);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  // Step 2: Set up the server certificate and private key
  SSL_CTX_use_certificate_file(ctx, "./cert_server/server-cert.pem", SSL_FILETYPE_PEM);
  SSL_CTX_use_PrivateKey_file(ctx, "./cert_server/server-key.pem", SSL_FILETYPE_PEM);
  // Step 3: Create a new SSL structure for a connection
  ssl = SSL_new (ctx);

  return ssl;
}

int setupTCPServer(){
    struct sockaddr_in sa_server;
    int sockfd;

    sockfd= socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(sockfd, "socket");
    memset (&sa_server, '\0', sizeof(sa_server));
    sa_server.sin_family      = AF_INET;
    sa_server.sin_addr.s_addr = INADDR_ANY;
    sa_server.sin_port        = htons (4433);
    int err = bind(sockfd, (struct sockaddr*)&sa_server, sizeof(sa_server));
    CHK_ERR(err, "bind");
    err = listen(sockfd, 5);
    CHK_ERR(err, "listen");
    return sockfd;
}

void processRequest(SSL* ssl, int sock){
    char buf[1024];
    int len = SSL_read (ssl, buf, sizeof(buf) - 1);
    buf[len] = '\0';
    printf("Received: %s\n",buf);

    // Construct and send the HTML page
    char *html =
	"HTTP/1.1 200 OK\r\n"
	"Content-Type: text/html\r\n\r\n"
	"<!DOCTYPE html><html>"
	"<head><title>Hello World</title></head>"
	"<style>body {background-color: black}"
	"h1 {font-size:3cm; text-align: center; color: white;"
	"text-shadow: 0 0 3mm yellow}</style></head>"
	"<body><h1>Hello, world!</h1></body></html>";
    SSL_write(ssl, html, strlen(html));
    SSL_shutdown(ssl);  SSL_free(ssl);
}


void TLStunSelected(int tunfd, int sockfd, SSL *ssl){
    int len;
    char buff[BUFF_SIZE];

    printf("Got a packet from TUN\n");

    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);
    buff[len] = '\0';
    SSL_write(ssl, buff, len);
    //sendto(sockfd, buff, len, 0, (struct sockaddr *) &peerAddr, sizeof(peerAddr));
}

void TLSsocketSelected(int tunfd, int sockfd, SSL *ssl){
    int len;
    char buff[BUFF_SIZE];
    printf("Got a packet from the tunnel\n");

    bzero(buff, BUFF_SIZE);
    //len = recvfrom(sockfd, buff, BUFF_SIZE, 0, NULL, NULL);
    len = SSL_read(ssl, buff, BUFF_SIZE);
    buff[len] = '\0';
    write(tunfd, buff, len);
}
