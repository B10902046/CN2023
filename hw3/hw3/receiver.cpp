#include <iostream>
#include <cstdio>
#include <ctime>
#include <cstdlib>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstring>

#include <zlib.h>

#include "def.h"

#include <openssl/evp.h>
#include <string>
#include <sstream>
#include <iomanip>

using namespace std;

// to hex string
string hexDigest(const void *buf, int len) {
    const unsigned char *cbuf = static_cast<const unsigned char *>(buf);
    ostringstream hx{};

    for (int i = 0; i != len; ++i)
        hx << hex << setfill('0') << setw(2) << (unsigned int)cbuf[i];

    return hx.str();
}


typedef struct {
	int len;
	char buff[MAX_SEG_SIZE];
} bufftype;

void setIP(char *dst, char *src){
    if(strcmp(src, "0.0.0.0") == 0 || strcmp(src, "local") == 0 || strcmp(src, "localhost") == 0){
        sscanf("127.0.0.1", "%s", dst);
    }
    else{
        sscanf(src, "%s", dst);
    }
    return;
}


// ./receiver <recv_ip> <recv_port> <agent_ip> <agent_port> <dst_filepath>
int main(int argc, char *argv[]) {
    // parse arguments
    if (argc != 6) {
        cerr << "Usage: " << argv[0] << " <recv_ip> <recv_port> <agent_ip> <agent_port> <dst_filepath>" << endl;
        exit(1);
    }

    int recv_port, agent_port;
    char recv_ip[50], agent_ip[50];

    // read argument
    setIP(recv_ip, argv[1]);
    sscanf(argv[2], "%d", &recv_port);

    setIP(agent_ip, argv[3]);
    sscanf(argv[4], "%d", &agent_port);

    char *filepath = argv[5];

    // make socket related stuff
    int sock_fd = socket(PF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in recv_addr;
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_port = htons(agent_port);
    recv_addr.sin_addr.s_addr = inet_addr(agent_ip);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(recv_port);
    addr.sin_addr.s_addr = inet_addr(recv_ip);
    memset(addr.sin_zero, '\0', sizeof(addr.sin_zero));    
    bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr));

    //*********************************************************
    // start 
    bufftype buffer[MAX_SEG_BUF_SIZE];
    int used_buffer[256] = {0}; 
    int acked = 0;
    int finish = 0;
    int current_num = 0;
    FILE *fp;
    if ((fp = fopen(filepath, "wb")) == NULL) {
    	perror("Error creating tmp file");
    	exit(0);
    }
    socklen_t recv_addr_sz;
    segment recv_sgmt{};
    segment sgmt{};
    // for sha init
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_MD_CTX *sha256 = EVP_MD_CTX_new();
    EVP_DigestInit_ex(sha256, EVP_sha256(), NULL);
    int n_bytes = 0;

    while(1) {
        if (recvfrom(sock_fd, &recv_sgmt, sizeof(recv_sgmt), 0, (struct sockaddr *)&recv_addr, &recv_addr_sz) > 0) {
            //fin
            if (recv_sgmt.head.fin == 1) {
                printf("recv\tfin\n");
                printf("send\tfinack\n");
                printf("flush\n");
                for (int i = 0; i < current_num; i++) {
                    fwrite(buffer[i].buff, 1, buffer[i].len, fp);
                    used_buffer[i] = 0; 
                }
                for (int i = 0; i < current_num; i++) {
                    n_bytes += buffer[i].len;
                    for (int s_i = 0; s_i != buffer[i].len; ++s_i) {
                        // update the object given a buffer and length
                        // (here we add just one character per update)
                        EVP_DigestUpdate(sha256, buffer[i].buff + s_i, 1);

                        // calculating hash
                        // (we need to make a copy of `sha256` for EVP_DigestFinal_ex to use,
                        // otherwise `sha256` will be broken)
                        EVP_MD_CTX *tmp_sha256 = EVP_MD_CTX_new();
                        EVP_MD_CTX_copy_ex(tmp_sha256, sha256);
                        EVP_DigestFinal_ex(tmp_sha256, hash, &hash_len);
                        EVP_MD_CTX_free(tmp_sha256);
                    }
                }
                printf("sha256\t%d\t%s\n", n_bytes, hexDigest(hash, hash_len).c_str()); 
                printf("finsha\t%s\n", hexDigest(hash, hash_len).c_str());
                recv_sgmt.head.ack = 1;
                sendto(sock_fd, &recv_sgmt, sizeof(recv_sgmt), 0, (struct sockaddr *)&recv_addr, sizeof(sockaddr));
                break;
            }
            //drop
            if (recv_sgmt.head.checksum != crc32(0L, (const Bytef *)recv_sgmt.data, recv_sgmt.head.length)) {
                // checksum
                sgmt.head.ack = 1;
                sgmt.head.ackNumber = acked;
                sgmt.head.sackNumber = acked;
                sendto(sock_fd, &sgmt, sizeof(sgmt), 0, (struct sockaddr *)&recv_addr, sizeof(sockaddr));
                printf("drop\tdata\t#%d\t(corrupted)\n", recv_sgmt.head.seqNumber);
                printf("send\tack\t#%d,\tsack\t#%d\n", sgmt.head.ackNumber, sgmt.head.sackNumber);
            }else if (recv_sgmt.head.seqNumber > MAX_SEG_BUF_SIZE * (finish + 1) || recv_sgmt.head.seqNumber <= MAX_SEG_BUF_SIZE * finish) {
                // out of buffer
                sgmt.head.ack = 1;
                sgmt.head.ackNumber = acked;
                sgmt.head.sackNumber = acked;
                sendto(sock_fd, &sgmt, sizeof(sgmt), 0, (struct sockaddr *)&recv_addr, sizeof(sockaddr));
                printf("drop\tdata\t#%d\t(buffer overflow)\n", recv_sgmt.head.seqNumber); 
                printf("send\tack\t#%d,\tsack\t#%d\n", sgmt.head.ackNumber, sgmt.head.sackNumber);
            }
            else {
                // put in buffer
                for (int i = 0; i < recv_sgmt.head.length; i++)
                    buffer[(recv_sgmt.head.seqNumber - 1)%256].buff[i] = recv_sgmt.data[i];
                buffer[(recv_sgmt.head.seqNumber - 1)%256].len = recv_sgmt.head.length;
                if (used_buffer[(recv_sgmt.head.seqNumber - 1)%256] == 0) {
                    current_num++;
                    used_buffer[(recv_sgmt.head.seqNumber - 1)%256] = 1;
                }
                if (recv_sgmt.head.seqNumber == acked + 1) {
                    // in order
                    printf("recv\tdata\t#%d\t(in order)\n", recv_sgmt.head.seqNumber);
                }else {
                    // out of order
                    printf("recv\tdata\t#%d\t(out of order, sack-ed)\n", recv_sgmt.head.seqNumber); 
                }
                // find acked
                for (int i = acked % 256; i < 256; i++) {
                    if (used_buffer[i] == 1) {
                        acked++;
                    }else {
                        break;
                    }
                }
                // send back
                sgmt.head.ack = 1;
                sgmt.head.ackNumber = acked;
                sgmt.head.sackNumber = recv_sgmt.head.seqNumber;
                sendto(sock_fd, &sgmt, sizeof(sgmt), 0, (struct sockaddr *)&recv_addr, sizeof(sockaddr));
                printf("send\tack\t#%d,\tsack\t#%d\n", sgmt.head.ackNumber, sgmt.head.sackNumber);
                // flush
                if (current_num == 256) {
                    printf("flush\n");
                    for (int i = 0; i < 256; i++) {
                        fwrite(buffer[i].buff, 1, buffer[i].len, fp);
                        used_buffer[i] = 0; 
                    }
                    current_num = 0;
                    finish++;
                    // print sha
                    for (int i = 0; i < 256; i++) {
                        n_bytes += buffer[i].len;
                        for (int s_i = 0; s_i != buffer[i].len; ++s_i) {
                            // update the object given a buffer and length
                            // (here we add just one character per update)
                            EVP_DigestUpdate(sha256, buffer[i].buff + s_i, 1);

                            // calculating hash
                            // (we need to make a copy of `sha256` for EVP_DigestFinal_ex to use,
                            // otherwise `sha256` will be broken)
                            EVP_MD_CTX *tmp_sha256 = EVP_MD_CTX_new();
                            EVP_MD_CTX_copy_ex(tmp_sha256, sha256);
                            EVP_DigestFinal_ex(tmp_sha256, hash, &hash_len);
                            EVP_MD_CTX_free(tmp_sha256);
                        }
                    }
                    printf("sha256\t%d\t%s\n", n_bytes, hexDigest(hash, hash_len).c_str()); 
                }
            }
        }
    }

    exit(0);
    // // receive a segment! (do the logging on your own)
    // socklen_t recv_addr_sz;
    // segment recv_sgmt{};
    // recvfrom(sock_fd, &recv_sgmt, sizeof(recv_sgmt), 0, (struct sockaddr *)&recv_addr, &recv_addr_sz);

    // cerr << "get data: " << string(recv_sgmt.data, recv_sgmt.head.length) << endl;

    // // send a segment!
    // segment sgmt{};
    // sgmt.head.ack = 1;
    // sgmt.head.ackNumber = recv_sgmt.head.seqNumber;
    // sgmt.head.sackNumber = recv_sgmt.head.seqNumber;

    // sendto(sock_fd, &sgmt, sizeof(sgmt), 0, (struct sockaddr *)&recv_addr, sizeof(sockaddr));
}