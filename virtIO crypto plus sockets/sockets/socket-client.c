
/*
 * socket-client.c
 * Simple TCP/IP communication using sockets
 *
 * Neofytou Alexandros
 * Adamis Dimitrios
 */

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "cryptodev.h"

#include "socket-common.h"
#define KEY_SIZE        16
#define BLOCK_SIZE      16
/* Insist until all of the data has been read */

ssize_t insist_read(int fd, void *buf, size_t cnt)
{
        ssize_t ret;
        size_t orig_cnt = cnt;

        while (cnt > 0) {
                ret = read(fd, buf, cnt);
                if (ret == 0) {
                        printf("Server went away. Exiting...\n");
                        return 0;
                }
                if (ret < 0) {
                        perror("read from server failed");
                        return ret;
                }
                buf += ret;
                cnt -= ret;
        }

        return orig_cnt;
}

/* Insist until all of the data has been written */
ssize_t insist_write(int fd, const void *buf, size_t cnt)
{
        ssize_t ret;
        size_t orig_cnt = cnt;

        while (cnt > 0) {
                ret = write(fd, buf, cnt);
                if (ret < 0)
                        return ret;
                buf += ret;
                cnt -= ret;
        }

        return orig_cnt;
}

int main(int argc, char *argv[])
{
        int fd,sd, port;
        char buf[256],temp[256];
        char *hostname;
        fd_set readfd;
        struct hostent *hp;
        struct sockaddr_in sa;
        struct session_op sess;
        struct crypt_op cryp;



        //desmefsh xwrou mnhmh gia ta 2 struct
        memset(&sess, 0, sizeof(sess));
        memset(&cryp, 0, sizeof(cryp));


        if (argc != 3) {
                printf("Usage: %s [hostname] [port]\n", argv[0]);
                exit(1);
        }
        hostname = argv[1];
        port = atoi(argv[2]); /* Needs better error checking */

        /* Create TCP/IP socket, used as main chat channel */
        if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
                perror("socket");
                exit(1);
        }
        printf("Created TCP socket\n");

        /* Look up remote hostname on DNS */
        if (!(hp = gethostbyname(hostname))) {
                perror("DNS lookup failed");
                exit(1);
        }

        /* Connect to remote TCP port */
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        memcpy(&sa.sin_addr.s_addr, hp->h_addr, sizeof(struct in_addr));
        printf("Connecting to remote host... ");
        if (connect(sd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
                perror("connect");
                exit(1);
        }
        printf("Connected.\n");

        fd = open("/dev/cryptodev0", O_RDWR);
        if (fd < 0) {
                perror("open(/dev/crypto)");
                return 1;
        }





        /*
         * Get crypto session for AES128
         */
        sess.cipher = CRYPTO_AES_CBC;
        sess.keylen = KEY_SIZE;
        sess.key = (unsigned char*)KEY;

        if (ioctl(fd, CIOCGSESSION, &sess)) {
                perror("ioctl(CIOCGSESSION)");
                return 1;
        }



        cryp.ses = sess.ses;
        cryp.iv = (unsigned char*)IV;
        //cryp.src = (unsigned char*)buf;
        //cryp.dst = (unsigned char*)temp;
        cryp.len = sizeof(buf); //length of source data


        FD_ZERO(&readfd);   //clears the set
        int max=0,array[2],n=0,i,ret;
        array[0]=sd;
        array[1]=0;



        /* Read answer and write it to standard output */
        for (;;) {



                for (i=0; i<2; i++){   //edw orizw to prwto orisma tis select (max ari8mos fd +1)
                        FD_SET(array[i],&readfd);
                        if (array[i]>max){
                                max=array[i];
                                }
                        }


                //select


                ret=select(max+1,&readfd,NULL,NULL,NULL); //to teleftaio orisma NULL gia na mhn blockarei h select kai na perimenei mexri na ginei kapoio I/O
                if (ret==-1){
                        perror("select error");
                        }



                else {
                        for (i=0;i<2;i++){
                                //printf("IFSSET SERVER i:%d\n",i);


                                if (FD_ISSET(array[i],&readfd)){
                                        if(i==0) // gyrise kapoio I/O apo ton sd
                                        {
                                                memset(temp, 0, sizeof(temp));
                                                n= insist_read(sd, buf, 256);

                                                if (n <= 0) {
                                                                perror("read");
                                                                exit(1);
                                                                }

                                                cryp.src = (unsigned char*)buf;
                                                cryp.dst = (unsigned char*)temp;
                                                cryp.op = COP_DECRYPT;
                                                if (ioctl(fd, CIOCCRYPT, &cryp)) {
                                                        perror("ioctl(CIOCCRYPT)");
                                                        return 1;
                                                        }


                                                printf("The Server Says: %s\n",temp);
                                                //printf("The mPARMPOUYTSALA Says: %s\n",buf);





                                                        }

                                        else
                                        {               //egrapsa kati sto stdin

                                                        //initialize bufers


                                                        memset(temp, 0, sizeof(temp));
                                                        memset(buf, 0, sizeof(buf));
                                                        //printf("I As a Client: ");


                                                        n=insist_read(0, buf, 256);
                                                        buf[sizeof(buf) - 1] = '\0';


                                                        //oti diavasa paei ton buffer

                                                        if (n <= 0) {
                                                                perror("read");
                                                                exit(1);
                                                                }



                                                        cryp.src = (unsigned char*)buf;
                                                        cryp.dst = (unsigned char*)temp;
                                                        cryp.op = COP_ENCRYPT;

                                                        if (ioctl(fd, CIOCCRYPT, &cryp)) {
                                                                perror("ioctl(CIOCCRYPT)");
                                                                return 1;
                                                        }



                                                        //write to cliend sd



                                                        if (insist_write(sd, temp, 256) != 256) {
                                                                printf("write to remote peer failed\n");
                                                                break;
                                                                }





                                                        }





                                                        }
                                                }
                                        }




                                }

        if (ioctl(fd, CIOCFSESSION, &sess.ses)) {
                perror("ioctl(CIOCFSESSION)");
                return 1;
        }
        if (close(fd) < 0) {
                perror("close(fd)");
                return 1;
        }







        return 0;
}
