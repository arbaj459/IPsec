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
char header[50],file[50],protocol[50],s_ip_address[50],d_ip_address[50],sport[50],dport[50],version[50];
// Function designed for chat between client and server.
void func(int connfd)
{
	char buff[MAX];
	int n;
	// infinite loop for chat
	for (;;) {
		bzero(buff, MAX);

		// read the message from client and copy it in buffer
		read(connfd, buff, sizeof(buff));
		// print buffer which contains the client contents
		
		
		
		int i=0,j=0;
		while(buff[i]!=' ')
        {
        sport[j++]=buff[i++];
        }
        sport[j]='\0';
        i++;
        j=0;
        
         while(buff[i]!=' ')
        {
        dport[j++]=buff[i++];
        }
        dport[j]='\0';
        i++;
        j=0;
        
        while(buff[i]!=' ') //length
        {
        i++;
        }
        
        
        i++;
        
        
        while(buff[i]!=' ') //checksum
        {
        i++;
        }
        i++;
        
        j=0;
        
        
        
          
        while(buff[i]!=' ') //version
        {
        version[j++]=buff[i++];
        }
        version[j]='\0';
        i++;
        
        j=0;
        
        while(buff[i]!=' ') //hl
        {
        i++;
        }
        i++;
        while(buff[i]!=' ') //type of service
        {
        i++;
        }
        i++;
          
          while(buff[i]!=' ') //identification 
        {
        i++;
        }
        i++;
        while(buff[i]!=' ') //flag
        {
        i++;
        }
        i++;
        
        while(buff[i]!=' ') //flga offset
        {
        i++;
        }
        i++;
        
        while(buff[i]!=' ') //timetolive
        {
        i++;
        }
        i++;
        j=0;
        while(buff[i]!=' ') //protocol
        {
        protocol[j++]=buff[i++];
        }
        protocol[j]='\0';
        i++;
        j=0;
        while(buff[i]!=' ')
        {
        s_ip_address[j++]=buff[i++];
        }
        s_ip_address[j]='\0';
        i++;
        j=0;
        
        
        
        
        
        
        
        while(buff[i]!=' ')
        {
        d_ip_address[j++]=buff[i++];
        }
        d_ip_address[j]='\0';
        
        
        i++;
        j=0;
        while(buff[i]!=' ')
        {
        
        header[j++]=buff[i++];
        }
        header[j]='\0';
        i++;
        j=0;
        while(buff[i]!=' ')
        {
        
        file[j++]=buff[i++];
        
        }
        file[j]='\0';
        
		// copy server message in the buffer
		
		// and send that buffer to client
		
		bzero(buff, MAX);
		strcpy(buff,"exit");
		write(connfd, buff, sizeof(buff));

		// if msg contains "Exit" then server exit and chat ended.
		if (strncmp("exit", buff, 4) == 0) {
			printf("Attacker Exit...\n");
			break;
		}
	}
}

// Driver function
int main()
{
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
	servaddr.sin_port = htons(8081);

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
		printf("Attacker listening..\n");
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
	func(connfd);
	
	printf("Information attacker have after capturing packet\n");
	printf("UDP and IP and data all received by attacker\n");
	printf("source port=%s\ndestination port=%s \nsourse ip=%s \ndestination ip=%s \nand many more",sport,dport,s_ip_address,d_ip_address);

	// After chatting close the socket
	close(sockfd);
}

