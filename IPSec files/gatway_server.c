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
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#define BUFF_SIZE 4096
#define MAX 200
#define PORT 8080
#define SA struct sockaddr
/***************************************************symmetric encryption********************************************/
#define AES_256_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define AES_128_KEY_SIZE 24

#define DES_128_KEY_SIZE 24
#define DES_128_BLOCK_SIZE 8

#define BUFSIZE 1024  
//char header[50],file[50],port[50],protocol[50],ip_address[50];
char header[50],file[50],protocol[50],s_ip_address[50],d_ip_address[50],sport[50],dport[50],version[50];
//This fuction used to display if some error ocuurin program
/**********************************************************************client1_gatway_1 communication********************************/
void funcA(int sockfd)
{
	char buff[MAX];
	int n;
	for (;;) {
		bzero(buff, sizeof(buff));
		strcpy(buff,s_ip_address);
		strcat(buff," ");
		
		strcat(buff,protocol);
		strcat(buff," ");
		strcat(buff,sport);
		strcat(buff," ");
		strcat(buff,"ipv4 20 tyoeOfService 24 flag flagOffcet timeTOLIve 50");
		strcat(buff," ");
		strcat(buff,"192.168.7.8");
		strcat(buff," ");
		strcat(buff,"192.168.9.10");
		
		strcat(buff," ");
		strcat(buff,"SPI 1234 0123456789ABCDEF encrypt_ipheader encrypted_file ESP_auth ESP_trail");
		write(sockfd, buff, sizeof(buff));
		bzero(buff, sizeof(buff));
		read(sockfd, buff, sizeof(buff));
		printf("From Gatway1 :IP-header ESP-header Payloadn\n");
		if ((strncmp(buff, "exit", 4)) == 0) {
			printf("Gatway1 Exit...\n");
			break;
		}
	}
}

int func1(int sockfd)
{
    char buff[MAX];
    int n;
    for (;;) {
        bzero(buff, sizeof(buff));
        
        strcpy(buff,"start");
        
       write(sockfd, buff, sizeof(buff));
       
        bzero(buff, sizeof(buff));
        read(sockfd, buff, sizeof(buff));
        
        
        if((strcmp(buff,"1")==0))
        {
        bzero(buff, sizeof(buff));
        strcpy(buff,"exit");
        }
        else
        {
        bzero(buff, sizeof(buff));
        strcpy(buff,"ok");
        
        }
        write(sockfd, buff, sizeof(buff));
        
        
        
        
        
        
         if ((strncmp(buff, "exit", 4)) == 0) {
			printf("Gatway1 Exit...\n");
			return 1;
			break;
		}
		
	bzero(buff, sizeof(buff));
        read(sockfd, buff, sizeof(buff));
        
       
        
        FILE* fp2 = fopen("ipheader", "wb");
      if (fp2 == NULL)
      {
            printf("Ipheader file does not exist...");
            exit(0);
      }
        
        
        fwrite(buff, sizeof(unsigned char), 123, fp2);
        fclose(fp2);
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
        
        bzero(buff, sizeof(buff));
        printf("Enter the string : ");
        strcpy(buff,"okk");
        
        
       write(sockfd, buff, sizeof(buff));
       
       
       bzero(buff, sizeof(buff));
        read(sockfd, buff, sizeof(buff));
        
        printf("\npacket received from sender\n");
       
        if ((strncmp(buff, "exit", 4)) == 0) {
            printf("Communication between sender and gatway complete...\n");
            printf("Starting communication between gatway1 and gatway2\n");
            break;
        }
    }
    return 0;
}
   

/**************************************************************************************************************************************/

void handleErrors()
{
printf("Wrong encryption or decryption progress\n");
}	






//This function will perform encryption and decryption both according to specify algorithm 
void file_encrypt_decrypt(const EVP_CIPHER *cipher_type,unsigned char* key,unsigned char *iv, FILE *ifp,FILE *ofp,int v){
    
    unsigned char in_buf[BUFSIZE], out_buf[BUFSIZE +64];

    int num_bytes_read, out_len;
    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();
    if(ctx == NULL){
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        
    }

    
    if(!EVP_CipherInit_ex(ctx, cipher_type, NULL, NULL, NULL, v)){ //Initalize algorithm which we are using for encrypt or decrypt
        fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        handleErrors();
        
    }
    
    if(cipher_type==EVP_des_ede3()){
    OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == DES_128_KEY_SIZE);
    
}
    
    
 
	if(cipher_type==EVP_aes_256_cbc())
	{  								//check key lenght is correct or not
    		OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == AES_256_KEY_SIZE);
    		OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == AES_BLOCK_SIZE);
	}
	if(cipher_type==EVP_aes_192_ccm())
	{
    		OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == AES_128_KEY_SIZE);
    		OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == AES_BLOCK_SIZE);
	}
    
    if(!EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, v))
    { 									//set the key and iv
        fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        handleErrors();
        EVP_CIPHER_CTX_cleanup(ctx);
        
    }

    while(1)
    {
        
        num_bytes_read = fread(in_buf, sizeof(unsigned char), BUFSIZE, ifp); //reading file according to specify block size
        if (ferror(ifp))
        {
            fprintf(stderr, "ERROR: fread error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
            
        }
        if(!EVP_CipherUpdate(ctx, out_buf, &out_len, in_buf, num_bytes_read))
        { 									//performing encryption and decryption accordingly
            fprintf(stderr, "ERROR: EVP_CipherUpdate failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
            handleErrors();
            EVP_CIPHER_CTX_cleanup(ctx);
            
        }
        fwrite(out_buf, sizeof(unsigned char), out_len, ofp);
        if (ferror(ofp)) 
        {
            fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
            
        }
        if (num_bytes_read < BUFSIZE) {
            /* Reached End of file */
            break;
        }
        }
        if(!EVP_CipherFinal_ex(ctx, out_buf, &out_len))
        {									 //performing last block encryption or decryption
        fprintf(stderr, "ERROR: EVP_CipherFinal_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        handleErrors();
        EVP_CIPHER_CTX_cleanup(ctx);
        
        }
    fwrite(out_buf, sizeof(unsigned char), out_len, ofp);
    if (ferror(ofp))
     {
        fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
        EVP_CIPHER_CTX_cleanup(ctx);
        
    }
    EVP_CIPHER_CTX_cleanup(ctx);
        
        
}
    



/********************************************verify certificate*************************************/

int verify(FILE *fp4,FILE *fp5)
 {
  


char line[100],nl[100];


      
 while (fgets(line, sizeof(line), fp4))
      {
            continue;
            
      }
while (fgets(nl, sizeof(nl), fp5))
      {
            continue;
            
      }
      
      
fclose(fp4);
 fclose(fp5);
 for(int i=0;i<64;i++)
 {
 if(line[i]!=nl[i])
 {
 printf("verification_fail\n");
 return 0;
 }
 
 }
 printf("verification sussessfull\n");
 return 1;
 
 }
/****************************************************************************************************/

/***********************************************************************public private encrypt ***********************/
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
 









 
int padding = RSA_PKCS1_PADDING;
 
RSA * createRSA(unsigned char * key,int public)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return 0;
    }
    if(public)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
    if(rsa == NULL)
    {
        printf( "Failed to create RSA");
    }
 
    return rsa;
}
 //public private key encrypt decrypt functions
int public_encrypt(char * key, FILE *ifp,FILE *ofp)
{
	unsigned char in_buf[7680], out_buf[7680];
    RSA * rsa = createRSAWithFilename(key,1);
    while(1)
    { 
       int num_bytes_read = fread(in_buf, sizeof(unsigned char), 4096, ifp);
       
       
       if (num_bytes_read<1)
       break;
    if (ferror(ifp))
        {
            fprintf(stderr, "ERROR: fread error: ");
            
            
        }
    
    int result = RSA_public_encrypt(num_bytes_read,in_buf,out_buf,rsa,padding);
    fwrite(out_buf, sizeof(unsigned char), result, ofp);
        if (ferror(ofp)) 
        {
            fprintf(stderr, "ERROR: fwrite error: ");
            
            
        }
    
    }
    return 0;
    
}
int private_decrypt(char * key, FILE *ifp,FILE *ofp)
{

	unsigned char in_buf[7680], out_buf[7680];
    RSA * rsa = createRSAWithFilename(key,0);
    while(1)
    {
        
        int num_bytes_read = fread(in_buf, sizeof(unsigned char), 7680, ifp);
        
        
        if (num_bytes_read ==0)
         break;
        
        
        if (ferror(ifp))
        {
            fprintf(stderr, "ERROR: fread error: ");
            
            
        }
    
    
    
    int  result = RSA_private_decrypt(num_bytes_read,in_buf,out_buf,rsa,padding);
    fwrite(out_buf, sizeof(unsigned char), result, ofp);
    
        if (ferror(ofp)) 
        {
            fprintf(stderr, "ERROR: fwrite error: ");
            
            
        }
    }
    
    return 0;
    
}
 
 int private_encrypt(unsigned char * key, FILE *ifp,FILE *ofp)
{
	unsigned char in_buf[4096], out_buf[4096];
    RSA * rsa = createRSAWithFilename("pr.pem",0);
    while(1)
    {
        
        int num_bytes_read = fread(in_buf, sizeof(unsigned char), 4096, ifp); //reading file according to specify block size
        
        
        if (num_bytes_read ==0)
         break;
        
        
        if (ferror(ifp))
        {
            fprintf(stderr, "ERROR: fread error: ");
            
            
        }
    
    
    
    int  result = RSA_private_encrypt(num_bytes_read,in_buf,out_buf,rsa,padding);
    
    
    fwrite(out_buf, sizeof(unsigned char), result, ofp);
    
        if (ferror(ofp)) 
        {
            fprintf(stderr, "ERROR: fwrite error: ");
            
            
        }
    }
    
    
    
    
    return 0;
}
int public_decrypt(char * key, FILE *ifp,FILE *ofp)
{
	unsigned char in_buf[4096], out_buf[4096];
    RSA * rsa = createRSAWithFilename(key,1);
    
    while(1)
    { 
       int num_bytes_read = fread(in_buf, sizeof(unsigned char), 4096, ifp);
       
       
       if (num_bytes_read<1)
       break;
    if (ferror(ifp))
        {
            fprintf(stderr, "ERROR: fread error: ");
            
            
        }
    
    int result = RSA_public_decrypt(num_bytes_read,in_buf,out_buf,rsa,padding);
    fwrite(out_buf, sizeof(unsigned char), result, ofp);
        if (ferror(ofp)) 
        {
            fprintf(stderr, "ERROR: fwrite error: ");
            
            
        }
    
    }
    
    return 0;
}

 
void printLastError(char *msg)
{
    char * err = malloc(130);;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n",msg, err);
    free(err);
}



/************************************************************************public private end *************************/

int sha(FILE *fp,FILE *fd)
{



size_t          i, n;                       
    				    
    char            buff[BUFF_SIZE];            
    unsigned int    md_len;                     
    EVP_MD_CTX      *mdctx;                     
    unsigned char   md_value[EVP_MAX_MD_SIZE];  
  

    

    mdctx = EVP_MD_CTX_new();   
    const EVP_MD *EVP_md5();    

    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);  

    while ((n = fread(buff, 1, sizeof(buff), fp)))  
    {
            EVP_DigestUpdate(mdctx, buff, n);  
    }

    EVP_DigestFinal_ex(mdctx, md_value, &md_len);   


    for (i = 0; i < md_len; i++)    
    {
    	fprintf(fd,"%02x", md_value[i]);
    
                
    }
    
fclose(fp);
fclose(fd);
    return 0;       


}


// Function designed for chat between client and server.
int func(int connfd,char **argv)
{
	char buff[MAX];
	int n;
	// infinite loop for chat
	for (;;) {
		
		char cookie[50];
		bzero(buff, MAX);
		printf("Authentication is performing between gatway1 and gatway2 using cookis and RSA certificate\n");
		// read the message from client and copy it in buffer
		read(connfd, buff, sizeof(buff));
		// print buffer which contains the client contents
		printf("From Gatway2 received cookie\n");
		strcpy(cookie,buff);
		
		
		bzero(buff, MAX);
		n = 0;
		// copy server message in the buffer
		strcpy(buff,"EEEEAAAABF888875");
		printf("FROM Gatway1 sent cookie\n");
		// and send that buffer to client
		write(connfd, buff, sizeof(buff));
	/*************************************************************certificate exchange**********************/
		bzero(buff, MAX);

		// read the message from client and copy it in buffer
		read(connfd, buff, sizeof(buff));
		// print buffer which contains the client contents
		printf("From Gatway2: Certificate rceived");
		int i=0,j=0;
		char certi[50],sign[50];
        	while(buff[i]!=' ')
        	{
        	certi[j++]=buff[i++];
        	}
        	certi[j]='\0';
        	i++;
        	j=0;
        	while(buff[i]>=97 && buff[i]<=128 || buff[i]==46 || buff[i]==95 || buff[i]>=65 && buff[i]<=91 || buff[i]>=47 && buff[i]<=58)
       	 {
        
        	sign[j++]=buff[i++];
        	}
        	sign[j]='\0';
        	 
        FILE *fp1 = fopen(sign, "rb");
      if (fp1 == NULL)
     {
            printf("file does not exist..%s",sign);
            return 0;
      }
      
     
      FILE *fp2 = fopen("signature", "wb");
      if (fp2 == NULL)
      {
            printf(" signatute file does not exist...");
            return 0;
      }
      
      public_decrypt("c_pu.pem",fp1,fp2);
        
	fclose(fp1);
	fclose(fp2);
	
	fp1 = fopen(certi, "rb");
	if (fp1 == NULL)
     {
            printf("file does not exist..%s",certi);
            return 0;
      }
      
     
      fp2 = fopen("unhashed", "wb");
      if (fp2 == NULL)
      {
            printf(" signatute file does not exist...");
            return 0;
      }
      sha(fp1,fp2);
      
		fp1 = fopen("signature", "rb");
	if (fp1 == NULL)
     {
            printf("signature file does not exist..");
            return 0;
      }
      
     
      fp2 = fopen("unhashed", "rb");
      if (fp2 == NULL)
      {
            printf(" unhashed file does not exist...");
            return 0;
      }
      
      int x=verify(fp1,fp2);
      if(x==0)
      return 0;
      
      
	bzero(buff, MAX);
		n = 0;
		// copy server message in the buffer
		strcpy(buff,"pu.pem gatwaySignature");
		printf("FROM Gatway1:CERTIFICATE sent to gatway2\n");
		// and send that buffer to client
		write(connfd, buff, sizeof(buff));
	
	/*******************************************************************************************************/
	
	
	
	
	
	
	
		bzero(buff, MAX);

		// read the message from client and copy it in buffer
		read(connfd, buff, sizeof(buff));
		// print buffer which contains the client contents
		printf("performing Deffie hellman parameter exchange using RSA certificate encryption\n");
		printf("public parameter received from gatway2\n");
		
		
		i=0;
		j=0;
		char param[50];
        	while(buff[i]!=' ')
        	{
        	param[j++]=buff[i++];
        	}
        	param[j]='\0';
		fp1 = fopen(param, "rb");
		if (fp1 == NULL)
    	 {
            printf("file does not exist..%s",param);
            return 0;
      	}
      
     
      fp2 = fopen("dhp.pem", "wb");
      if (fp2 == NULL)
      {
            printf(" signatute file does not exist...");
            return 0;
      }
		
	private_decrypt("pr.pem",fp1,fp2);
        
	fclose(fp1);
	fclose(fp2);
		
		
		
		printf("parameter stored in dhp.pem file\n");
		bzero(buff, MAX);
		n = 0;
		// copy server message in the buffer
		strcpy(buff,"ok");

		// and send that buffer to client
		write(connfd, buff, sizeof(buff));
	printf("public key parameter of gatway1 sent to gatway2\n");

		bzero(buff, MAX);

		// read the message from client and copy it in buffer
		read(connfd, buff, sizeof(buff));
		// print buffer which contains the client contents
		
	printf("public parameter of gatway2 received\n");
		i=0;
		j=0;
		char pub[50];
        	while(buff[i]!=' ')
        	{
        	pub[j++]=buff[i++];
        	}
        	param[j]='\0';
		fp1 = fopen(pub, "rb");
		if (fp1 == NULL)
    	 {
            printf("file does not exist..%s",param);
            return 0;
      	}
      
     
      fp2 = fopen("dhpub2.pem", "wb");
      if (fp2 == NULL)
      {
            printf(" signatute file does not exist...");
            return 0;
      }
		
	private_decrypt("pr.pem",fp1,fp2);
        
	fclose(fp1);
	fclose(fp2);
		
		
		
		
		printf("public key stored  in dhpub2.pem file\n");
		
		
		
		bzero(buff, MAX);
		n = 0;
		// copy server message in the buffer
		
		fp1 = fopen("dhpub1.pem", "rb");
      if (fp1 == NULL)
     {
            printf("dhpub2 file does not exist..");
            return 0; 
      }
      
     
      fp2 = fopen("public", "wb");
      if (fp2 == NULL)
      {
            printf(" signatute file does not exist...");
            return 0;
      }
      
      public_encrypt("pu1.pem",fp1,fp2);
        
	fclose(fp1);
	fclose(fp2);
	strcpy(buff,"public ");
		printf("encrypted_public key shared\n");
		
		
		
		strcpy(buff,"public ");

		// and send that buffer to client
		write(connfd, buff, sizeof(buff));
		
		
		
		FILE *fp = fopen("secret1.bin", "rb");
  
    		if (fp == NULL)
   	 {
    	printf("failed to open file ");
	    return 0;
    	}
    	
    	FILE *fq = fopen("symmetric_key_gatway_1", "wb");
  
    		if (fq == NULL)
   	 {
    	printf("failed to open file ");
	    return 0;
    	}
    	
    	sha(fp,fq);
		printf("secreat key generated\n");
		printf("key exchange performed successfully\n");
		printf("traffic selector done!!\n");
		printf("Transfering packet to gatway2\n");
		
/*********************************************************************encrypting files***********************************************/		
		unsigned char key[AES_256_KEY_SIZE];
		char line[256];
		fq = fopen("symmetric_key_gatway_1", "rb");
  
    		if (fq == NULL)
   	 {
    	printf("failed to open file ");
	    return 0;
    	}
	fread(key, sizeof(unsigned char), 32, fq);
		//printf("%s",key);
		
		fclose(fq);
		//return 0;
		//strcpy(key,"0123456789ABCDEF888888888888888");
		int c,a;
		FILE *fi, *fe, *fd;
		fi = fopen(header, "rb"); //input file
		
		if (fi == NULL)
   	 {
    	printf("header failed to open file ");
	    return 0;
    	}

		unsigned char *iv = (unsigned char *)"0123456789ABCDEF";
		const EVP_CIPHER *cipher_type;
		cipher_type=EVP_aes_256_cbc();
		fe = fopen("encrypt_ipheader", "wb"); 
		file_encrypt_decrypt(cipher_type,key,iv,fi,fe,1);
		fclose(fi);
		fclose(fe);
		
		
		fi = fopen(file, "rb"); //input file
		
		if (fi == NULL)
   	 {
    	printf("file failed to open file ");
	    return 0;
    	}

		
		fe = fopen("encrypted_file", "wb"); 
		file_encrypt_decrypt(cipher_type,key,iv,fi,fe,1);
		fclose(fi);
		fclose(fe);
		
		fi = fopen(file, "rb"); //input file
		
		if (fi == NULL)
   	 {
    	printf("failed to open file ");
	    return 0;
    	}
    	
    	fe = fopen("hash", "wb"); //input file
		
		if (fe == NULL)
   	 {
    	printf("failed to open file ");
	    return 0;
    	}
		sha(fi,fe);
		
		fi = fopen("hash", "rb"); //input file
		
		if (fi == NULL)
   	 {
    	printf("failed to open file ");
	    return 0;
    	}

		
		fe = fopen("ESP_auth", "wb"); 
		file_encrypt_decrypt(cipher_type,key,iv,fi,fe,1);
		fclose(fi);
		fclose(fe);
		
		
		if (strncmp("1", argv[1], 4) == 0)
		strcpy(buff,"exit");
		else
		strcpy(buff,"ok");
		write(connfd, buff, sizeof(buff));
		
		
		
	//	bzero(buff, MAX);

		// read the message from client and copy it in buffer
	//	read(connfd, buff, sizeof(buff));
		
		
		if (strncmp("exit", buff, 4) == 0) {
           	 printf(" ");
           	 return 1;
            	break;
            	}
            	
            	
            	bzero(buff, MAX);

		// read the message from client and copy it in buffer
		read(connfd, buff, sizeof(buff));
		
/*****************************************************************************************************************************************/	
		strcpy(buff,s_ip_address);
		strcat(buff," ");
		
		strcat(buff,protocol);
		strcat(buff," ");
		strcat(buff,sport);
		strcat(buff," ");
		strcat(buff,"ipv4 20 tyoeOfService 24 flag flagOffcet timeTOLIve 50");
		strcat(buff," ");
		strcat(buff,"192.168.7.8");
		strcat(buff," ");
		strcat(buff,"192.168.9.10");
		
		strcat(buff," ");
		strcat(buff,"SPI 1234 0123456789ABCDEF encrypt_ipheader encrypted_file ESP_auth ESP_trail");

		// and send that buffer to client
		write(connfd, buff, sizeof(buff));
		printf("\nTo Gatway2  :IP-header ESP-Header packet ESP_auth ESP_trail");
		return 0;
		
		
		
		// if msg contains "Exit" then server exit and chat ended.
		if (strncmp("exit", buff, 4) == 0) {
			printf("Server Exit...\n");
			break;
		}
	}
	return 0;
}

// Driver function
int main(int argc, char **argv)
{
/***********************************************client*************************************/

int sockfd, connfd;
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
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(PORT);
   
    // connect the client socket to server socket
    if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) {
        printf("connection with the server failed...\n");
        exit(0);
    }
    else
        printf("connected to the server..\n");
   
    // function for chat
    int x=func1(sockfd);
   
    // close the socket
    close(sockfd);
    
    if(x==1)
    return 0;




/*******************************************************************server***********************/


	sleep(100);
	int   len;
	

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
	int z=func(connfd,argv);
	
	close(sockfd);

	
	
	if(z==1)
	{
	
	sleep(100);
	 sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully created..\n");
    bzero(&servaddr, sizeof(servaddr));
   
    
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(8081);
   
    
    if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) {
        printf("connection with the client2 failed...\n");
        exit(0);
    }
    else
        printf("connected to client2..\n");
   
    
    funcA(sockfd);
   
    
    close(sockfd);	
	
	}
	
	
}

