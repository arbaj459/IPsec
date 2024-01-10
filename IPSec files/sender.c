#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <unistd.h>
#include <arpa/inet.h>
#include <unistd.h>
#define MAX 200
#define PORT 8080
#define SA struct sockaddr

// Function designed for chat between client and server.

void func1(int sockfd,char **argv)
{
	char buff[MAX];
	int n;
	for (;;) {
		bzero(buff, sizeof(buff));
		
		n = 0;
		strcpy(buff,"301 302 length checksum ipv4 20 tyoeOfService 24 flag flagOffcet timeTOLIve 17 198.168.3.4 192.168.10.9 ipheader ");
		strcat(buff,argv[1]);
		strcat(buff," ");
		write(sockfd, buff, sizeof(buff));
		bzero(buff, sizeof(buff));
		read(sockfd, buff, sizeof(buff));
		
		if ((strncmp(buff, "exit", 4)) == 0) {
			printf("sender Exit...\n");
			break;
		}
	}
}
void func(int connfd,int a,char **argv)
{
	char buff[MAX];
	int n;
	// infinite loop for chat
	for (;;) {
		bzero(buff, MAX);

		// read the message from client and copy it in buffer
		read(connfd, buff, sizeof(buff));
		// print buffer which contains the client contents
		
		bzero(buff, MAX);
		n = 0;
		// copy server message in the buffer
		if(a!=1)
		strcpy(buff,"ok");
		else
		strcpy(buff,"1");
		write(connfd, buff, sizeof(buff));
		
		bzero(buff, MAX);

		// read the message from client and copy it in buffer
		read(connfd, buff, sizeof(buff));
		printf("From sender: IP_header UDP_header DATA\n");
		// and send that buffer to client
		
		if (strncmp("exit", buff, 4) == 0) {
			
			break;
		}
		
		
		
		
		
		
		
		bzero(buff, MAX);
		n = 0;
		// copy server message in the buffer
		strcpy(buff,"301 302 length checksum ipv4 20 tyoeOfService 24 flag flagOffcet timeTOLIve 17 198.168.3.4 192.168.10.9 ipheader ");
		strcat(buff,argv[1]);
		strcat(buff," ");
		printf("From sender: IP_header UDP_header DATA\n");
		// and send that buffer to client
		write(connfd, buff, sizeof(buff));
		
		bzero(buff, MAX);
		read(connfd, buff, sizeof(buff));
		// print buffer which contains the client contents
		
		bzero(buff, MAX);

		strcpy(buff,"exit");
		
		// and send that buffer to client
		write(connfd, buff, sizeof(buff));
		


		// if msg contains "Exit" then server exit and chat ended.
		if (strncmp("exit", buff, 4) == 0) {
			printf("sender Exit...\n");
			break;
		}
	}
}

// Driver function
int main(int argc, char **argv)
{

	int a=0;
	printf("want to generate attack please enter 1 else 0\n");
	scanf("%d",&a);
	int sockfd, connfd, len;
	struct sockaddr_in servaddr, cli;

	// socket create and verification
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		printf("socket creation failed...\n");
		exit(0);
	}
	else
		printf("Socket successfully created..\n");
	bzero(&servaddr, sizeof(servaddr));

	// assign IP, PORT
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(PORT);

	// Binding newly created socket to given IP and verification
	if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) {
		printf("socket bind failed...\n");
		exit(0);
	}
	else
		printf("Socket successfully binded..\n");

	// Now server is ready to listen and verification
	if ((listen(sockfd, 5)) != 0) {
		printf("Listen failed...\n");
		exit(0);
	}
	else
		printf("Server listening..\n");
	len = sizeof(cli);

	// Accept the data packet from client and verification
	connfd = accept(sockfd, (SA*)&cli, &len);
	if (connfd < 0) {
		printf("server accept failed...\n");
		exit(0);
	}
	else
		printf("server accept the client...\n");

	// Function for chatting between client and server
	func(connfd,a,argv);

	// After chatting close the socket
	close(sockfd);
if(a==1){
	
	sleep(100);
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    }
    else
        printf(" ");
    bzero(&servaddr, sizeof(servaddr));
   
    
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(8081);
   
    
    if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) {
        printf("connection with the client2 failed...\n");
        exit(0);
    }
    else
        printf(" ");
   
    
    func1(sockfd,argv);
   
    
    close(sockfd);
    }
}
