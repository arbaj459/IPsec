#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include<string.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
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
/**************************************************************Symmetric encryption*********************************/

#define AES_256_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define AES_128_KEY_SIZE 24

#define DES_128_KEY_SIZE 24
#define DES_128_BLOCK_SIZE 8

#define BUFSIZE 1024  
char header[50],file[50],esp_protocol[50],s_ip_address[50],d_ip_address[50],version[50],spi[50],seq[50],ivh[50],esp_port[50];
char auth[50],ip[50],ip_address[50],protocol[50],port[50];
//This fuction used to display if some error ocuurin program


/*************************************************gatway_2 and receiver*****************/

void func1(int sockfd)
{
    char buff[MAX];
    int n;
    for (;;) {
    
    printf("Performing communication Gatway2 and receiver\n");
        bzero(buff, sizeof(buff));
        
        FILE* fp2 = fopen("decrypt_ipheader", "rb");
      if (fp2 == NULL)
      {
            printf("decryptyIpheader file does not exist...");
            exit(0);
      }
        
        fread(buff, sizeof(unsigned char), 123, fp2);
        
        fclose(fp2);
        
        strcat(buff," ");
        strcat(buff,"decrypted_file");
        write(sockfd, buff, sizeof(buff));
        printf(" Gatway2:IP header packet\n");
        bzero(buff, sizeof(buff));
        read(sockfd, buff, sizeof(buff));
        
        
        
        bzero(buff, sizeof(buff));
        
        strcpy(buff,"exit");
        write(sockfd, buff, sizeof(buff));
        if ((strncmp(buff, "exit", 4)) == 0) {
            printf("Gatway2 Exit...\n");
            break;
        }
    }
}
/**************************************************************************************/

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
    



/**********************************************************verify certificate*******************************************/

int verify(FILE *fp4,FILE *fp5)
 {
  


char line[100],nl[100];


      if (fp5 == NULL)
      {
            printf("unhashed_final file does not exist...");
            return 0;
      }
 
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

/***********************************************************************************************************************
/*****************************************************************************************public private encrypt decrypt****/


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
        
        int num_bytes_read = fread(in_buf, sizeof(unsigned char), 4096, ifp);
        
        
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



/******************************************************************************public private end**************************/

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

int func(int sockfd)
{
	char buff[MAX];
	
	int n;
	for (;;) {
	
	
	/****************************cookie**************/
	//bzero(buff, sizeof(buff));
	bzero(buff, MAX);
		
		
		strcpy(buff,"FABCDE12ABB897EA");
		printf("FROM Gatway1 sent :COOkie\n");
		write(sockfd, buff, sizeof(buff));
		
		//bzero(buff, sizeof(buff));
		bzero(buff, MAX);
		
		read(sockfd, buff, sizeof(buff));
		printf("From Gatway1 received cookie\n");
	
	/***********************************************************exchanging certificats*******************************************************/
		//bzero(buff, sizeof(buff));
		bzero(buff, MAX);
		
		
		strcpy(buff,"pu1.pem gatway2Signature");
		printf("FROM Gatway2 sent CERTIFICATE %s\n",buff);
		write(sockfd, buff, sizeof(buff));
		
		
		//bzero(buff, sizeof(buff));
		
		bzero(buff, MAX);
		read(sockfd, buff, sizeof(buff));
		printf("From gatway1 received certificate\n");
		
		int i=0,j=0;
		char certi[50],sign[50];
        	while(buff[i]!=' ')
        	{
        	certi[j++]=buff[i++];
        	}
        	certi[j]='\0';
        	i++;
        	j=0;
        	while(buff[i]>=97 && buff[i]<=128 || buff[i]==46 || buff[i]==95 || buff[i]>=65 && buff[i]<=91)
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
      
      
	/***************************************************************************************************************************************/
	
	
		bzero(buff, sizeof(buff));
		printf("Sharing DH parameters using RSA certificate\n");
		
		fp1 = fopen("dhp.pem", "rb");
      if (fp1 == NULL)
     {
            printf("file does not exist..%s",sign);
            return 0;
      }
      
     
      fp2 = fopen("parameter", "wb");
      if (fp2 == NULL)
      {
            printf(" signatute file does not exist...");
            return 0;
      }
      
      public_encrypt("pu.pem",fp1,fp2);
        
	fclose(fp1);
	fclose(fp2);
		
		
		
		
		
		
		
		strcpy(buff,"parameter FABCDE12ABB897EA");
		printf("Gatway2:encrypted_parameter \n");
		write(sockfd, buff, sizeof(buff));
		bzero(buff, sizeof(buff));
		read(sockfd, buff, sizeof(buff));
		printf("From Gatway1 : received parammeter\n");
		
		
		bzero(buff, sizeof(buff));
		
		
		
		
		fp1 = fopen("dhpub2.pem", "rb");
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
      
      public_encrypt("pu.pem",fp1,fp2);
        
	fclose(fp1);
	fclose(fp2);
	strcpy(buff,"public ");
		printf("Gatway2:encrypted_public key shared\n");
		write(sockfd, buff, sizeof(buff));
		
		
		
		bzero(buff, sizeof(buff));
		read(sockfd, buff, sizeof(buff));
		printf("Gatway1:encrypted_public key received\n");
		
		i=0;
		j=0;
		char pub[50];
        	while(buff[i]!=' ')
        	{
        	pub[j++]=buff[i++];
        	}
        	pub[j]='\0';
		fp1 = fopen(pub, "rb");
		if (fp1 == NULL)
    	 {
            printf("file does not exist..%s",pub);
            return 0;
      	}
      
     
      fp2 = fopen("dhpub1.pem", "wb");
      if (fp2 == NULL)
      {
            printf(" signatute file does not exist...");
            return 0;
      }
		
	private_decrypt("pr1.pem",fp1,fp2);
        
	fclose(fp1);
	fclose(fp2);
		
		
		
		
		
		
		
		
		printf("public key stored in dhpub1.pem\n");
		
		FILE *fp = fopen("secret2.bin", "rb");
  
    		if (fp == NULL)
   	 {
    	printf("failed to open file ");
	    return 0;
    	}
    	
    	FILE *fq = fopen("symmetric_key_gatway_2", "wb");
  
    		if (fq == NULL)
   	 {
    	printf("failed to open file ");
	    return 0;
    	}
    	
    	sha(fp,fq);
		
		printf("secreat key generated\n");
		printf("key exchange performed successfully\n");
		
		printf("traffic selector done!!\n");
		
		printf("Received packet from Gatway1\n");
		
		
		
		bzero(buff, sizeof(buff));
		read(sockfd, buff, sizeof(buff));
		
		
		

		//bzero(buff, sizeof(buff));
	//	strcpy(buff,"exit");
		
	//	write(sockfd, buff, sizeof(buff));
		
		
		if (strncmp("exit", buff, 4) == 0)
		{
		
		return 1;
		
		break;
		
		
		}
		
		
		bzero(buff, sizeof(buff));
		strcpy(buff,"ok");
		
		write(sockfd, buff, sizeof(buff));
		
		bzero(buff, sizeof(buff));
		read(sockfd, buff, sizeof(buff));
		
		i=0;
		j=0;
		
		
		
	while(buff[i]!=' ')//sIP
        {
        ip_address[j++]=buff[i++];
        }
        ip_address[j]='\0';
        i++;
        j=0;
	while(buff[i]!=' ') //protocol
        {
        protocol[j++]=buff[i++];
        }
        protocol[j]='\0';
        i++;
        j=0;	
	while(buff[i]!=' ')//sport
        {
        port[j++]=buff[i++];
        }
        port[j]='\0';
        i++;
        j=0;
        
/*******************************************************************************************************************************************/

        
        
        
          
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
        esp_protocol[j++]=buff[i++];
        
        }
        esp_protocol[j]='\0';
        i++;
        j=0;
        while(buff[i]!=' ') //sIP
        {
        s_ip_address[j++]=buff[i++];
        
        }
        s_ip_address[j]='\0';
        i++;
        j=0;
        
       
        
        
       
        while(buff[i]!=' ') //DIP
        {
        d_ip_address[j++]=buff[i++];
     
        }
        d_ip_address[j]='\0';
       
       
       i++;
        j=0;
        
        while(buff[i]!=' ') //spi
        {
        spi[j++]=buff[i++];
     
        }
        spi[j]='\0';
       
       
       i++;
        j=0;
        
       
        while(buff[i]!=' ')  //sequence 
        {
        seq[j++]=buff[i++];
     
        }
       seq[j]='\0';
       
       i++;
        j=0;
        
       
        while(buff[i]!=' ') //IV
        {
     ivh[j++]=buff[i++];
     
        }
       ivh[j]='\0';



	
/****************************************************************************************************************************************/        
	i++;
	j=0;
        
        while(buff[i]!=' ')//IP
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
        
  
 printf("\nchecking SPD rules for packet processing\n");      
        
 /**************************SPD entities check***************************************************/
 
 if((strcmp(protocol,"17")==0) || (strcmp(protocol,"TCP")==0) || (strcmp(protocol,"ICMP")==0))
 printf("\n%s packet allowed\n",protocol);
 
 else
 {
 printf("\n %s This packet is not allowed Drop packet\n",protocol);
 return 1;
 }
 
 int m=0;
 i=0;
 while(port[i]!='\0')
 {
 m=m*10+port[i]-'0';
 i++;
 }
 printf("port=%d",m);
 if(m>500)
 {
 printf("\npacket of this %d port not allowed to enter Drop packet\n",m);
 return 1;
 }
 else
 {
 
 printf("\npacket of this %d port allowed to enter\n",m);
 }
 
 
 if(strstr(ip_address,"192.168."))
 {
 printf("\n%s packet of this ip allowed\n",ip_address);
 }
 else
 {
 
 printf("\npacket of this %s IP not allowed Drop packet\n",ip_address);
 return 1;
 }
 
 
 
 
        
        
		
/**********************************************************decrypting files *************************************************************/
		unsigned char key[AES_256_KEY_SIZE];
		char line[256];
		fq = fopen("symmetric_key_gatway_2", "rb");
  
    		if (fq == NULL)
   	 {
    	printf("failed to open file of key ");
	    return 0;
    	}
		fread(key, sizeof(unsigned char), 32, fq);
		//printf("%s",key);
		
		fclose(fq);
		//return 0;
		//strcpy(key,"0123456789ABCDEF888888888888888");
		int c,a;
		FILE *fi, *fe, *fd;
		
		fi = fopen(ip, "rb"); //input file
		
		if (fi == NULL)
   	 {
    	printf("failed to open file  header ");
	    return 0;
    	}

		unsigned char *iv = (unsigned char *)"0123456789ABCDEF";
		const EVP_CIPHER *cipher_type;
		cipher_type=EVP_aes_256_cbc();
		fe = fopen("decrypt_ipheader", "wb"); 
		file_encrypt_decrypt(cipher_type,key,iv,fi,fe,0);
		fclose(fi);
		fclose(fe);
		
		
	fi = fopen(file, "rb"); //input file
		
		if (fi == NULL)
   	 {
    	printf("failed to open file ");
	    return 0;
    	}

		
		fe = fopen("decrypted_file", "wb"); 
		file_encrypt_decrypt(cipher_type,key,iv,fi,fe,0);
		fclose(fi);
		fclose(fe);
		
		
		fi = fopen(auth, "rb"); //input file
		
		if (fi == NULL)
   	 {
    	printf("auth failed to open file ");
	    return 0;
    	}

		
		fe = fopen("unhashed", "wb"); 
		file_encrypt_decrypt(cipher_type,key,iv,fi,fe,0);
		fclose(fi);
		fclose(fe);
		
		
		fi = fopen("decrypted_file", "rb"); //input file
		
		if (fi == NULL)
   	 {
    	printf("file failed to open file ");
	    return 0;
    	}
fe = fopen("unhashed2", "wb"); //input file
		
		if (fe == NULL)
   	 {
    	printf("unhahsed2 failed to open file ");
	    return 0;
    	}
    	
    	
    	sha(fi,fe);
    	
    	fi = fopen("unhashed2", "rb"); //input file
		
		if (fi == NULL)
   	 {
    	printf("unhashed2 failed to open file ");
	    return 0;
    	}

fe = fopen("unhashed", "rb"); //input file
		
		if (fe == NULL)
   	 {
    	printf("unhashed failed to open file ");
	    return 0;
    	}

	verify(fi,fe);
		
/*********************************************************************************************************************************/		
		
		
		
		return 0;
		
		
		if ((strncmp(buff, "exit", 4)) == 0) {
			printf("Client Exit...\n");
			break;
		}
	}

return 0;}

int main()
{
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
	int z=func(sockfd);
	
	close(sockfd);
	if(z==1)
	return 0;
	sleep(100);
	
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

	func1(sockfd);

	// close the socket
	close(sockfd);
}

