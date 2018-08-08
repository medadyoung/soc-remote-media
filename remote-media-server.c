/***  TCP Server tcpserver.c 
 *
 * 利用 socket 介面設計網路應用程式
 * 程式啟動後等待 client 端連線，連線後印出對方之 IP 位址
 * 並顯示對方所傳遞之訊息，並回送給 Client 端。
 *
 */
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/errno.h>
#include <strings.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include "config.h"

#define MAXDATA   512

#if HAVE_GNUTLS
#include <gnutls/x509.h>
#include <gnutls/gnutls.h>

#include <assert.h>

#define KEYFILE "/etc/remote-media/privatekey.pem"
#define CERTFILE "/etc/remote-media/cert.pem"

#define CHECK(x) assert((x)>=0)

#endif

#define SERV_PORT 8080

#define IDVENDOR            "/sys/kernel/config/usb_gadget/mass_storage/idVendor"
#define IDPRODUCT           "/sys/kernel/config/usb_gadget/mass_storage/idProduct"
//#define BCDDEVICE           "/sys/kernel/config/usb_gadget/mass_storage/bcdDevice"
//#define BCDUSB              "/sys/kernel/config/usb_gadget/mass_storage/bcdUSB"
//#define BMAXPACKERSIZE0     "/sys/kernel/config/usb_gadget/mass_storage/bMaxPacketSize0"
#define SERIALNUMBER        "/sys/kernel/config/usb_gadget/mass_storage/strings/0x409/serialnumber"
#define MANUFACTURER        "/sys/kernel/config/usb_gadget/mass_storage/strings/0x409/manufacturer"
#define PRODUCT             "/sys/kernel/config/usb_gadget/mass_storage/strings/0x409/product"
#define MAXPOWER            "/sys/kernel/config/usb_gadget/mass_storage/configs/c.1/MaxPower"
#define LUN0                "/sys/kernel/config/usb_gadget/mass_storage/functions/mass_storage.0/lun.0/file"
#define CONFIGURATION       "/sys/kernel/config/usb_gadget/mass_storage/configs/c.1/strings/0x409/configuration"

#define USB0                "/sys/kernel/config/usb_gadget/mass_storage/functions/mass_storage.0"
#define CONF0               "/sys/kernel/config/usb_gadget/mass_storage/configs/c.1/mass_storage.0"

#define UDC                 "/sys/kernel/config/usb_gadget/mass_storage/UDC"

#define USB_DEV_NAME        "f0838000.udc"

struct gmass_storage_init_desc {
	char *path;
	const void *ptr;
	int size;
};

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define DESC(_path, _p, _s)		\
	{							\
		.path	=	(_path),	\
		.ptr	=	(_p),		\
		.size	=	(_s),		\
	}

static struct gmass_storage_init_desc _gmass_storage_init_desc[] = {
	//DESC(LUN0, "\/dev\/nbd1", 12),
	DESC(IDVENDOR, "0x0525", 8),//
	DESC(IDPRODUCT, "0xa4a5", 8),//
	//DESC(BCDDEVICE, "0x7200", 8),
	//DESC(BCDUSB, "0x0200", 8),
	//DESC(BMAXPACKERSIZE0, "0x08", 4),
	DESC(SERIALNUMBER, "0123456789", 10),//
	DESC(MANUFACTURER, "Nuvoton", 10),//
	DESC(PRODUCT, "Mass Storage Gadget", 20),
	DESC(MAXPOWER, "0x01", 4),
	DESC(CONFIGURATION, "Conf 1", 8),
};

int usb_gadget_write(char *path, const void *ptr, size_t size){
	FILE *pFile;
	pFile = fopen(path,"w");
	if (pFile == NULL) {
		printf("fopen fail:%d[%s](%s) \n",errno,strerror(errno),path);
		return -1;
	}else if(size>0){
		fwrite(ptr, size, 1, pFile);
	}else{
		printf("clear %s\n",path);
	}
	fclose(pFile);
	return 0;
}

int g_mass_storage_init(){
	int i = 0;
	int nr_set = ARRAY_SIZE(_gmass_storage_init_desc);
	struct gmass_storage_init_desc  *desc  = _gmass_storage_init_desc;

	for(i = 0; i < nr_set; i++) {
		usb_gadget_write(desc->path, desc->ptr, desc->size);
		desc++;
	}

	symlink(USB0, CONF0);

	return 0;
}

#define MAXNAME 1024
#define BUF_SIZE 256
char *clientip={"255.255.255.255"};
extern int errno;

int auth_account(char *ID,char *PW){
	printf("ID:[%s] PW:[%s]\n",ID,PW);
	return 1;
}

int serve_client_tls(gnutls_session_t session){
	int state =0 ;
	int id_pw_counter=0;
	char ID[1024]={0};
	char PW[1024]={0};
	for (;;) {
		char buf[BUF_SIZE]={0};
		char cmd[BUF_SIZE]={0};
		int nbytes;
		printf("waiting for DATA from client(%s)...\n",clientip);
		nbytes = gnutls_record_recv(session, buf, BUF_SIZE);

		if (nbytes == 0) {
			printf("\n- Peer has closed the GnuTLS connection\n");
			return 0;
		} else if (nbytes < 0 && gnutls_error_is_fatal(nbytes) == 0) {
			fprintf(stderr, "*** Warning: %s\n", gnutls_strerror(nbytes));
		} else if (nbytes < 0) {
			fprintf(stderr, "\n*** Received corrupted data(%d). Closing the connection.\n\n", nbytes);
			return -1;
		} else if (nbytes > 0) {
			printf("Server Got %d bytes [%s] from [%s]\n",nbytes, buf, clientip);
		}
		switch(state){
			case 0:
				if(id_pw_counter==0)
					strncpy(ID,buf,nbytes);
				else if(id_pw_counter==1){
					strncpy(PW,buf,nbytes);
					state=1;
#ifdef LDAP_AUTH
                    if (auth_pam_ldap(ID, PW, clientip) == 0)
#else
                    if (auth_account(ID,PW)==1)
#endif
                    {
						strcpy(buf,"authentication_pass");
						buf[strlen("authentication_pass")]='\0';
						printf("Authentication Return: %s(%d)\n",buf,strlen("authentication_pass"));
						if (gnutls_record_send(session, buf, strlen("authentication_pass")) < 0) {
							perror ("write to client error");
							return -1;
						}
					}else{
						state=0;
						if (gnutls_record_send(session, buf, strlen("authentication_fail")) < 0) {
							perror ("write to client error");
							return -1;
						}
						return -1;
					}
				}

				if(id_pw_counter > 1){
					id_pw_counter=0;
					state=0;
				}else{
					id_pw_counter++;
				}

			break;
			case 1:
				printf("state 1\n");
				if (strcmp(buf, "ENABLENBDCLIENT")==0){
					state=2;//Need to get port # from client
					/* return to client */
					if (gnutls_record_send(session, buf, nbytes) < 0) {
						perror ("write to client error");
						return -1;
					}
				}else if (strcmp(buf, "ENABLENBDCLIENTX")==0){
					state=3;//Need to get port # from client
					/* return to client */
					if (gnutls_record_send(session, buf, nbytes) < 0) {
						perror ("write to client error");
						return -1;
					}
				}else if (strcmp(buf, "DISABLENBDCLIENT")==0){
					state =1;
					usb_gadget_write(LUN0,NULL,0);
					if(system("echo \"\" > /sys/kernel/config/usb_gadget/mass_storage/functions/mass_storage.0/lun.0/file")==-1){
						perror ("Clear lun.0/file fail");
					}
					if(system("nbd-client -d /dev/nbd1")==-1){
						perror ("nbd-client -d /dev/nbd1 fail");
						if (gnutls_record_send(session, "STOP NBD CLient Fail", strlen("STOP NBD CLient Fail")) < 0) {
							perror ("write to client error");
							return -1;
						}
					}else{
						if (gnutls_record_send(session, "STOP NBD CLient Success", strlen("STOP NBD CLient Success")) < 0) {
							perror ("write to client error");
							return -1;
						}
					}
				}else if(strcmp(buf, "INITMASSSTORAGE")==0){
					state =1;
					if(system("mkdir -p /sys/kernel/config/usb_gadget/mass_storage")==-1)
						perror ("mkdir -p /sys/kernel/config/usb_gadget/mass_storage error");
					if(system("mkdir -p /sys/kernel/config/usb_gadget/mass_storage/configs/c.1")==-1)
						perror ("mkdir -p /sys/kernel/config/usb_gadget/mass_storage/configs/c.1 error");
					if(system("mkdir -p /sys/kernel/config/usb_gadget/mass_storage/functions/mass_storage.0")==-1)
						perror ("mkdir -p /sys/kernel/config/usb_gadget/mass_storage/functions/mass_storage.0 error");
					if(system("mkdir -p /sys/kernel/config/usb_gadget/mass_storage/strings/0x409")==-1)
						perror ("mkdir -p /sys/kernel/config/usb_gadget/mass_storage/strings/0x409 error");
					if(system("mkdir -p /sys/kernel/config/usb_gadget/mass_storage/configs/c.1/strings/0x409")==-1)
						perror ("mkdir -p /sys/kernel/config/usb_gadget/mass_storage/configs/c.1/strings/0x409 error");
					g_mass_storage_init();
					/* return to client */
					if (gnutls_record_send(session, buf, nbytes) < 0) {
						perror ("write to client error");
						return -1;
					}
				}else if (strcmp(buf, "ENABLEUSB")==0){
					state =1;
					usb_gadget_write(LUN0,"\/dev\/nbd1",9);
					usb_gadget_write(UDC, USB_DEV_NAME, 16);
					/* return to client */
					if (gnutls_record_send(session, buf, nbytes) < 0) {
						perror ("write to client error");
						return -1;
					}
				}else if (strcmp(buf, "DISABLEUSB")==0){
					state =1;

					if(system("echo \"\" > /sys/kernel/config/usb_gadget/mass_storage/UDC")==-1){
						perror ("Clear usb_gadget/mass_storage/UDC fail");

						if (gnutls_record_send(session, "STOP MassStorage Fail", strlen("STOP MassStorage Fail")) < 0) {
							perror ("write to client error");
							return -1;
						}
					}else{
						printf("Clear %s successfully\n",UDC);
						if (gnutls_record_send(session, "STOP MassStorage Success", strlen("STOP MassStorage Success")) < 0) {
							perror ("write to client error");
							return -1;
						}
					}
					printf("Clear UDC done\n");
				}else if (strcmp(buf, "CLOSECONNECTION")==0){
					state =1;
					/* return to client */
					if (gnutls_record_send(session, buf, nbytes) < 0) {
						perror ("write to client error");
						return -1;
					}
					//CHECK(gnutls_bye(session, GNUTLS_SHUT_WR));
					return 0;
				}
			break;
			case 2://Need to get NBD server port # from remote media client
				printf("state 2\n");//NO TLS
				state =1;
				snprintf(cmd, sizeof(cmd), "nbd-client %s %s /dev/nbd1 -b 512 -N poleg-nbd", clientip,buf);//-x
				printf("CMD:%s\n",cmd);
				if(system(cmd)==-1){
					perror ("Launch nbd-client error");
					if (gnutls_record_send(session, "NBD Client Fail", strlen("NBD Client Fail")) < 0) {
						perror ("write to client error");
						return -1;
					}
				}else{
					if (gnutls_record_send(session, "NBD Client Success", strlen("NBD Client Success")) < 0) {
						perror ("write to client error");
						return -1;
					}
				}
			break;
			case 3://Need to get NBD server port # from remote media client
				printf("state 3: get NBD Server port:%s\n",buf);
				state =1;
				//option -x is to enable TLS
				snprintf(cmd, sizeof(cmd), "nbd-client %s %s /dev/nbd1 -x -b 512 -N poleg-nbd", clientip,buf);//-x
				printf("CMD:%s\n",cmd);
				if(system(cmd)==-1){
					perror ("Launch nbd-client error");
					if (gnutls_record_send(session, "NBD Client Fail", strlen("NBD Client Fail")) < 0) {
						perror ("write to client error");
						return -1;
					}
				}else{
					if (gnutls_record_send(session, "NBD Client Success", strlen("NBD Client Success")) < 0) {
						perror ("write to client error");
						return -1;
					}
				}
			break;
			default:
				printf("unknow state\n");
				state=1;
			break;
		}
	}//continue to read data from client

	return 1;
}

int serve_client(int recfd){
	int state =0 ;
	while(1){
		char buf[BUF_SIZE]={0};
		char cmd[BUF_SIZE]={0};
		int nbytes;
		printf("waiting for DATA from client(%d)...\n",recfd);
		if ((nbytes = read(recfd, buf, BUF_SIZE)) <= 0) {
			if(usb_gadget_write(UDC,NULL,0)==-1){
				perror ("Clear UDC fail--1");
			}else{
				printf("Make sure UDC is disable when read function return <= 0\n");
			}
			printf("Clear UDC done\n");
			perror("read of data error nbytes !");
			return -1;
		}

		printf("Server Got %d bytes [%s] from [%s]\n",nbytes, buf,clientip);
		switch(state){
			case 0:
				printf("state 0\n");
				if (strcmp(buf, "ENABLENBDCLIENT")==0){
					state=1;//Need to get port # from client
					/* return to client */
					if (write(recfd, buf, nbytes) == -1) {
						perror ("write to client error");
						return -1;
					}
				}else if (strcmp(buf, "ENABLENBDCLIENTX")==0){
					state=2;//Need to get port # from client
					/* return to client */
					if (write(recfd, buf, nbytes) == -1) {
						perror ("write to client error");
						return -1;
					}
				}else if (strcmp(buf, "DISABLENBDCLIENT")==0){
					state =0;
					if(system("echo \"\" > /sys/kernel/config/usb_gadget/mass_storage/functions/mass_storage.0/lun.0/file")==-1)
						perror ("Clear usb_gadget/mass_storage/functions/mass_storage.0/lun.0/file fail");
					if(system("nbd-client -d /dev/nbd1")==-1){
						perror ("nbd-client -d /dev/nbd1 fail");
						if (write(recfd, "STOP NBD CLient Fail", strlen("STOP NBD CLient Fail")) == -1) {
							perror ("write to client error");
							return -1;
						}
					}else{
						if (write(recfd, "STOP NBD CLient Success", strlen("STOP NBD CLient Success")) == -1) {
							perror ("write to client error");
							return -1;
						}
					}
				}else if(strcmp(buf, "INITMASSSTORAGE")==0){
					state =0;
					if(system("mkdir -p /sys/kernel/config/usb_gadget/mass_storage")==-1)
						perror ("mkdir -p /sys/kernel/config/usb_gadget/mass_storage error");
					if(system("mkdir -p /sys/kernel/config/usb_gadget/mass_storage/configs/c.1")==-1)
						perror ("mkdir -p /sys/kernel/config/usb_gadget/mass_storage/configs/c.1 error");
					if(system("mkdir -p /sys/kernel/config/usb_gadget/mass_storage/functions/mass_storage.0")==-1)
						perror ("mkdir -p /sys/kernel/config/usb_gadget/mass_storage/functions/mass_storage.0 error");
					if(system("mkdir -p /sys/kernel/config/usb_gadget/mass_storage/strings/0x409")==-1)
						perror ("mkdir -p /sys/kernel/config/usb_gadget/mass_storage/strings/0x409 error");
					if(system("mkdir -p /sys/kernel/config/usb_gadget/mass_storage/configs/c.1/strings/0x409")==-1)
						perror ("mkdir -p /sys/kernel/config/usb_gadget/mass_storage/configs/c.1/strings/0x409 error");
					g_mass_storage_init();
					/* return to client */
					if (write(recfd, buf, nbytes) == -1) {
						perror ("write to client error");
						return -1;
					}
				}else if (strcmp(buf, "ENABLEUSB")==0){
					state =0;
					usb_gadget_write(LUN0,"\/dev\/nbd1",9);
					usb_gadget_write(UDC, USB_DEV_NAME, 16);
					/* return to client */
					if (write(recfd, buf, nbytes) == -1) {
						perror ("write to client error");
						return -1;
					}
				}else if (strcmp(buf, "DISABLEUSB")==0){
					state =0;
					if(system("echo \"\" > /sys/kernel/config/usb_gadget/mass_storage/UDC")==-1){
						perror ("Clear usb_gadget/mass_storage/UDC fail--3");

						if (write(recfd, "STOP MassStorage Fail", strlen("STOP MassStorage Fail")) == -1) {
							perror ("write to client error");
							return -1;
						}
					}else{
						printf("Clear %s successfully\n",UDC);
						if (write(recfd, "STOP MassStorage Success", strlen("STOP MassStorage Success")) == -1) {
							perror ("write to client error");
							return -1;
						}
					}
					printf("Clear %s done\n",UDC);
				}else if (strcmp(buf, "CLOSECONNECTION")==0){
					state =0;
					/* return to client */
					if (write(recfd, buf, nbytes) == -1) {
						perror ("write to client error");
						return -1;
					}
					close(recfd);
					return 0;
				}
			break;
			case 1://Need to get NBD server port # from remote media client
				printf("state 1\n");//NO TLS
				state =0;
				snprintf(cmd, sizeof(cmd), "nbd-client %s %s /dev/nbd1 -b 512 -N poleg-nbd", clientip,buf);//-x
				printf("CMD:%s\n",cmd);
				if(system(cmd)==-1){
					perror ("Launch nbd-client error");
					if (write(recfd, "NBD Client Fail", strlen("NBD Client Fail")) == -1) {
						perror ("write to client error");
						return -1;
					}
				}else{
					if (write(recfd, "NBD Client Success", strlen("NBD Client Success")) == -1) {
						perror ("write to client error");
						return -1;
					}
				}
			break;
			case 2://Need to get NBD server port # from remote media client
				printf("state 2\n");
				state =0;
				//option -x is to ebanle TLS
				snprintf(cmd, sizeof(cmd), "nbd-client %s %s /dev/nbd1 -b 512 -x -N poleg-nbd", clientip,buf);
				printf("CMD:%s\n",cmd);
				if(system(cmd)==-1){
					perror ("Launch nbd-client error");
					if (write(recfd, "NBD Client Fail", strlen("NBD Client Fail")) == -1) {
						perror ("write to client error");
						return -1;
					}
				}else{
					if (write(recfd, "NBD Client Success", strlen("NBD Client Success")) == -1) {
						perror ("write to client error");
						return -1;
					}
				}
			break;
			default:
				printf("unknow state\n");
				state=0;
			break;
		}
	}//continue to read data from client

	return 0;
}

void main(int argc, char *argv[])
{
	int i;
	int socket_fd;      /* file description into transport */
	int recfd;     /* file descriptor to accept        */
	int length;     /* length of address structure      */
	int nbytes;     /* the number of read **/
	struct sockaddr_in myaddr; /* address of this service */
	struct sockaddr_in client_addr; /* address of client    */
	unsigned short port = SERV_PORT;
	char type[MAXDATA]={0}; /* read data form file */
	char data[MAXDATA]={0}; /* read data form file */
	int ndata=0;
	int fdesc;     /* file description */
	FILE *pf;

#if HAVE_GNUTLS
	int ret;
	gnutls_certificate_credentials_t x509_cred;
	gnutls_priority_t priority_cache;
	gnutls_session_t session;
#endif

	printf("Set max_sectors_kb & read_ahead_kb to 1024 for nbd1\n");
	if(system("echo 1024 > /sys/block/nbd1/queue/max_sectors_kb")==-1){
		perror ("Set max_sectors_kb to 1024 fail");
	}
	if(system("echo 1024 > /sys/block/nbd1/queue/read_ahead_kb")==-1){
		perror ("Set read_ahead_kb to 1024 fail");
	}

#if 0
	for(i=0;i<argc;i++)
		printf("%d:%s\n",i,argv[i]);
#endif

#if HAVE_GNUTLS
	pf=fopen("/etc/remote-media/rms.cfg","r");
	if( pf ==NULL ){
		perror("open /etc/remote-media/rms.cfg file error!");
		return;
	}

	while(ndata=fscanf(pf , "%s" , type)!=EOF){
		if(strcmp(type,"PrivateKeyPassphrase:")==0){
			fscanf(pf , "%s" , data);
			break;
		}else{
			printf("We only support PrivateKeyPassphrase: at this moment\n");
			return;
		}
	}

	fclose(pf);

	/*TLS*/
	/* for backwards compatibility with gnutls < 3.3.0 */
	CHECK(gnutls_global_init());

	CHECK(gnutls_certificate_allocate_credentials(&x509_cred));

	//CHECK(gnutls_certificate_set_x509_trust_file(x509_cred, CAFILE,
	//                                             GNUTLS_X509_FMT_PEM));

	//CHECK(gnutls_certificate_set_x509_crl_file(x509_cred, CRLFILE,
	//                                           GNUTLS_X509_FMT_PEM));

	/* The following code sets the certificate key pair as well as, 
	 * an OCSP response which corresponds to it. It is possible
	 * to set multiple key-pairs and multiple OCSP status responses
	 * (the latter since 3.5.6). See the manual pages of the individual
	 * functions for more information.
	 */
	//CHECK(gnutls_certificate_set_x509_key_file(x509_cred, CERTFILE, KEYFILE, GNUTLS_X509_FMT_PEM));
	CHECK(gnutls_certificate_set_x509_key_file2(x509_cred, CERTFILE, KEYFILE, GNUTLS_X509_FMT_PEM, data, 0));

	//CHECK(gnutls_certificate_set_ocsp_status_request_file(x509_cred,
	//                                                      OCSP_STATUS_FILE,
	//                                                      0));

	/* One could use specific priority strings such as "PERFORMANCE:%SERVER_PRECEDENCE"
	 * especially if they are read from a configuration file; otherwise, it
	 * is recommended to use the defaults as shown here. */
	CHECK(gnutls_priority_init(&priority_cache, NULL, NULL));

#if GNUTLS_VERSION_NUMBER >= 0x030506
        /* only available since GnuTLS 3.5.6, on previous versions see
         * gnutls_certificate_set_dh_params(). */
        gnutls_certificate_set_known_dh_params(x509_cred, GNUTLS_SEC_PARAM_MEDIUM);
#endif

#endif
	/*
	*      Get a socket into TCP/IP
	*/
	if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) <0) {
		perror ("socket failed");
		return;
	}
	/*
	*    Set up our address
	*/
	bzero ((char *)&myaddr, sizeof(myaddr));
	myaddr.sin_family = AF_INET;
	myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	if(argc==2)
		port = atoi(argv[1]);
	printf("RMS Port:%d\n",port);
	myaddr.sin_port = htons(port);

	/*
	*     Bind to the address to which the service will be offered
	*/
	if (bind(socket_fd, (struct sockaddr *)&myaddr, sizeof(myaddr)) <0) {
		perror ("bind failed");
		return;
	}

	/* 
	* Set up the socket for listening, with a queue length of 5
	*/
	if (listen(socket_fd, 20) <0) {
		perror ("listen failed");
		return;
	}
	/*
	* Loop continuously, waiting for connection requests
	* and performing the service
	*/
	length = sizeof(client_addr);

	/*signal(SIGCHLD, SIG_IGN)會讓system() 回傳 No child processes ，
	 *但是其實是有呼叫成功，所以只能在father process用waitpid();
	 *或是嘗試不要用system()，直接用fork()和exec()
	 */
	//signal(SIGCHLD, SIG_IGN);		//for linux to prevent child process to become a zombie
	while (1) {
#if HAVE_GNUTLS
		CHECK(gnutls_init(&session, GNUTLS_SERVER));
		CHECK(gnutls_priority_set(session, priority_cache));
		CHECK(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred));

		/* We don't request any certificate from the client.
		 * If we did we would need to verify it. One way of
		 * doing that is shown in the "Verifying a certificate"
		 * example.
		 */
		gnutls_certificate_server_set_request(session, GNUTLS_CERT_IGNORE);
		gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
#endif
		printf("waiting for NEW Client coming...\n");
		if ((recfd = accept(socket_fd, 
			(struct sockaddr *)&client_addr, &length)) <0) {
			perror ("could not accept call");
			return;
		}

		pid_t pid = fork();
		if (pid < 0){
			printf("error in fork!");
			close(recfd);
			return;
		}else if (pid == 0){
			//printf("I am the child process, my process id is %d[pid:%d]\n",getpid(),pid);

			printf("Create socket #%d form %s : %d\n", recfd, 
			inet_ntoa(client_addr.sin_addr), htons(client_addr.sin_port)); 
			clientip=(char *)inet_ntoa(client_addr.sin_addr);
#if HAVE_GNUTLS
			gnutls_transport_set_int(session, recfd);

			do {
				ret = gnutls_handshake(session);
			}while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
			if (ret < 0) {
				close(recfd);
				gnutls_deinit(session);
				fprintf(stderr,
					"*** Handshake has failed (%s)\n\n",
					gnutls_strerror(ret));
					return;
			}
			printf("- Handshake was completed\n");

			int ret = serve_client_tls(session);
			if(ret==-1)
				printf("serve_client_tls end with some error\n");

			/* do not wait for the peer to close the connection.*/
			CHECK(gnutls_bye(session, GNUTLS_SHUT_WR));

			close(recfd);
			gnutls_deinit(session);
			printf("Closing original connection with client\n");

			if(system("echo \"\" > /sys/kernel/config/usb_gadget/mass_storage/UDC")==-1){//here has some issue
				perror ("echo \"\" to UDC fail--1");
			}else{
				printf("Make sure UDC is disable when returning from serve_client_tls()\n");
			}
			printf("echo \"\" to UDC done\n");
			return;
#else
			int ret = serve_client(recfd);
			if(ret==-1)
				printf("serve_client end with some error\n");
			close(recfd);
			printf("Closing original connection with client\n");
			return;
#endif
		}else{
			close(recfd);
			waitpid(pid,NULL,0);//需要waitpid 否則child process會變成zombie
		}

	}
}
