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

char header[50],file[50],esp_protocol[50],s_ip_address[50],d_ip_address[50],version[50],spi[50],seq[50],ivh[50],esp_port[50],id[50];
char auth[50],ip[50],ip_address[50],protocol[50],port[50];
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
		printf("From Gatway1: IP-header ESP-header payload \n");
		
		int i=0;
		int j=0;
		
		
		
	while(buff[i]!=' ')
        {
        ip_address[j++]=buff[i++];
        }
        ip_address[j]='\0';
        i++;
        j=0;
	while(buff[i]!=' ')
        {
        protocol[j++]=buff[i++];
        }
        protocol[j]='\0';
        i++;
        j=0;	
	while(buff[i]!=' ')
        {
        port[j++]=buff[i++];
        }
        port[j]='\0';
        i++;
        j=0;
        
/*******************************************************************************************************************************************/

        
        
        
          
        while(buff[i]!=' ') 
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
         j=0; 
          while(buff[i]!=' ') //identification 
        {
        id[j++]=buff[i++];
        }
        id[j]='\0';
        j=0;
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
        esp_protocol[j++]=buff[i++];
        
        }
        esp_protocol[j]='\0';
        i++;
        j=0;
        while(buff[i]!=' ')
        {
        s_ip_address[j++]=buff[i++];
        
        }
        s_ip_address[j]='\0';
        i++;
        j=0;
        
       
        
        
       
        while(buff[i]!=' ') //dip
        {
        d_ip_address[j++]=buff[i++];
     
        }
        d_ip_address[j]='\0';
       
       
       i++;
        j=0;
        
       
        while(buff[i]!=' ')  //spi 
        {
        spi[j++]=buff[i++];
     
        }
       spi[j]='\0';
       
       i++;
        j=0;
        
       
        while(buff[i]!=' ') //seq
        {
     seq[j++]=buff[i++];
     
        }
       seq[j]='\0';


 	i++;
        j=0;
        
       
        while(buff[i]!=' ') //iv
        {
     ivh[j++]=buff[i++];
     
        }
       ivh[j]='\0';

	
/****************************************************************************************************************************************/        
	i++;
	j=0;
        
        while(buff[i]!=' ')
        {
        
        ip[j++]=buff[i++];
        }
        ip[j]='\0';
        i++;
        j=0;
        while(buff[i]!=' ')
        {
        
        file[j++]=buff[i++];
        
        }
        file[j]='\0';
        i++;
        j=0;
        while(buff[i]!=' ')
        {
        
        auth[j++]=buff[i++];
        
        }
        auth[j]='\0';
        
		
		
		
		bzero(buff, MAX);
		n = 0;
		// copy server message in the buffer
		strcpy(buff,"exit");

		// and send that buffer to client
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
		printf(" ");

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
		printf(" ");
		
		
	
	// Function for chatting between client and server
	func(connfd);
	printf("Information accesable to attacker is\n");
	printf("attacker received IP header ESP header and ecrypted payload\n");
	printf("source IP=%s \ndestination IP =%s \nsequence number=%s\nIV=%s\nIdentification number=%s\nversion=%s \nprotocol field=%s\n ",s_ip_address,d_ip_address,seq,ivh,id,version,esp_protocol);
	printf("all ip header and esp header field accesable original ip header and data is not accesable also ip address printed are router address not host\n");


	// After chatting close the socket
	close(sockfd);
}

