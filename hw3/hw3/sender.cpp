#include <iostream>
#include <fstream>
#include <cstdio>
#include <ctime>
#include <cstdlib>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstring>
#include <chrono>
#include <zlib.h>
#include <algorithm>
#include "def.h"

using namespace std;

void setIP(char *dst, char *src){
    if(strcmp(src, "0.0.0.0") == 0 || strcmp(src, "local") == 0 || strcmp(src, "localhost") == 0){
        sscanf("127.0.0.1", "%s", dst);
    }
    else{
        sscanf(src, "%s", dst);
    }
    return;
}


// ./sender <send_ip> <send_port> <agent_ip> <agent_port> <src_filepath>
int main(int argc, char *argv[]) {
    // parse arguments
    if (argc != 6) {
        cerr << "Usage: " << argv[0] << " <send_ip> <send_port> <agent_ip> <agent_port> <src_filepath>" << endl;
        exit(1);
    }

    int send_port, agent_port;
    char send_ip[50], agent_ip[50];

    // read argument
    setIP(send_ip, argv[1]);
    sscanf(argv[2], "%d", &send_port);

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
    addr.sin_port = htons(send_port);
    addr.sin_addr.s_addr = inet_addr(send_ip);
    memset(addr.sin_zero, '\0', sizeof(addr.sin_zero));    
    bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr));
    

    char buffer[MAX_SEG_SIZE]; 
    //Things for the select
    fd_set readfds, master;
    struct timeval timeout;

    FD_ZERO(&master);
    FD_ZERO(&readfds);

    FD_SET(sock_fd, &master);  
    int fdmax = sock_fd;  

    char fname[256];
    strcpy(fname, argv[5]);
    if (strcmp(fname, "/dev/stdin") == 0) {
        std::string filename = "input";
        std::ofstream outputFile(filename);
        std::string line;
        while (std::getline(std::cin, line)) {
            outputFile << line << std::endl;
        }
        outputFile.close();
        strcpy(fname, filename.c_str());
    }

    //open file
    FILE *fp;
    if ((fp = fopen(fname, "rb")) == NULL) {
        exit(0);
    }

    // check for acked
    int seg_state[100000] = {0};

    // init
    int last_select = 0;    // for resend
    double cwnd = 1.0;
    int threshold = 16;    
    int dup_ack = 0;
    int stateslow = 1;
    int acked = 0;         // for cumulative ack
    int sacked = 0; 
    segment send_seg, recv_seg;
    unsigned int result;
    int last = -1;
    int tmp;
    int check;
    socklen_t recv_addr_sz;
    int last_send = 0;

    // find filesize
    if (fseek(fp, 0, SEEK_END) != 0) {
        fprintf(stderr, "Error seeking to the end of the file.\n");
        return 1;
    }
    long fileSize = ftell(fp);
    last = (fileSize - 1) / MAX_SEG_SIZE + 1;


    fseek(fp, 0, SEEK_SET);
    if ((result = fread(send_seg.data, 1, MAX_SEG_SIZE, fp)) < 0) {
        perror("Error reading data");
        exit(0);
    }
    
    send_seg.head.length = result;
    send_seg.head.seqNumber = 1;
    send_seg.head.checksum = crc32(0L, (const Bytef *)send_seg.data, result);
    if ((tmp = sendto(sock_fd, &send_seg, sizeof(send_seg), 0, (struct sockaddr *)&recv_addr, sizeof(recv_addr))) < 0) {
        perror("Error sending package");
        exit(0);
    }
    printf("send\tdata\t#%d,\twinSize = %d\n", 1, int(cwnd));
    seg_state[1] = 1;
    last_send = 1;        
    
    
    auto start_time = std::chrono::steady_clock::now();

    while (1) {
        FD_ZERO(&master);
        FD_ZERO(&readfds);

        FD_SET(sock_fd, &master);  
        int fdmax = sock_fd;
        // set timer 
        readfds = master;
        //Wait for all of the data, to choose if timeout or packet loss
        
        auto end_time = std::chrono::steady_clock::now();
        std::chrono::duration<double> duration = (end_time - start_time);
        auto remain_time = double(1) - duration.count();
        if (remain_time < 0)
            remain_time = 0;
        timeout.tv_sec = int(remain_time);
        timeout.tv_usec = int((remain_time - int(remain_time))*1000000);
        check = select(fdmax + 1, &readfds, NULL, NULL, &timeout);
        if (check == -1) {
            perror("Select error ");
            exit(0);
        }
        //time out 
        if (check == 0) {
            // set state
            stateslow = 1;
            threshold = (1 > int(cwnd/2)) ? 1 : int(cwnd/2);
            cwnd = 1;
            dup_ack = 0;
            printf("time\tout,\tthreshold = %d,\twinSize = %d\n", threshold, int(cwnd));
            // send missing
            fseek(fp, (acked)*MAX_SEG_SIZE, SEEK_SET);
            if ((result = fread(send_seg.data, 1, MAX_SEG_SIZE, fp)) < 0) {
                perror("Error reading data");
                exit(0);
            }
            send_seg.head.length = result;
            send_seg.head.seqNumber = acked + 1;
            send_seg.head.checksum = crc32(0L, (const Bytef *)send_seg.data, result);
            if ((tmp = sendto(sock_fd, &send_seg, sizeof(send_seg), 0, (struct sockaddr *)&recv_addr, sizeof(recv_addr))) < 0) {
                perror("Error sending package");
                exit(0);
            }
            printf("resnd\tdata\t#%d,\twinSize = %d\n", acked + 1, int(cwnd));
            last_send = acked + 1;
            start_time = std::chrono::steady_clock::now();
        }else {
            // recv
            if (recvfrom(sock_fd, &recv_seg, sizeof(recv_seg), 0, (struct sockaddr *)&recv_addr, &recv_addr_sz) < 0) {
                perror("Error receiving package");
                exit(0);
            }
            if (recv_seg.head.ack == 1) {
                printf("recv\tack\t#%d,\tsack\t#%d\n", recv_seg.head.ackNumber, recv_seg.head.sackNumber);
                seg_state[recv_seg.head.sackNumber] = 2;
                sacked = recv_seg.head.sackNumber;
                if (recv_seg.head.ackNumber > acked) {
                    int prev_window = (int)cwnd;
                    // new ack
                    dup_ack = 0;
                    if (stateslow) {
                        cwnd += 1;
                    }else {
                        cwnd += double(1) / int(cwnd);
                    }
                    for (int i = acked + 1; i <= recv_seg.head.ackNumber; i++) {
                        seg_state[i] = 2;
                    }
                    acked = recv_seg.head.ackNumber;
                    /******************     send new    ***************/
                    int window_size = (int)cwnd - prev_window + 1;
                    int base = last_send + 1; 
                    // send segment
                    while (window_size > 0) {
                        // send new 
                        if (seg_state[base] == 0 || seg_state[base] == 1) {
                            // read file content
                            fseek(fp, (base-1)*MAX_SEG_SIZE, SEEK_SET);
                            if ((result = fread(send_seg.data, 1, MAX_SEG_SIZE, fp)) < 0) {
                                perror("Error reading data");
                                exit(0);
                            }
                            if (result == 0) {
                                last = base-1;
                                break;                    
                            }
                            send_seg.head.length = result;
                            send_seg.head.seqNumber = base;
                            send_seg.head.checksum = crc32(0L, (const Bytef *)send_seg.data, result);
                            if ((tmp = sendto(sock_fd, &send_seg, sizeof(send_seg), 0, (struct sockaddr *)&recv_addr, sizeof(recv_addr))) < 0) {
                                perror("Error sending package");
                                exit(0);
                            }
                            if (seg_state[base] == 0)
                                printf("send\tdata\t#%d,\twinSize = %d\n", base, int(cwnd));
                            else if (seg_state[base] == 1)
                                printf("resnd\tdata\t#%d,\twinSize = %d\n", base, int(cwnd));
                            seg_state[base] = 1;
                            window_size--;
                            last_send = base;
                        }
                        base++;
                    }
                    start_time = std::chrono::steady_clock::now();
                }else {
                    // dup ack
                    dup_ack += 1;
                    /**************  send   new     *****************/
                    if (recv_seg.head.ackNumber != recv_seg.head.sackNumber) {
                        int window_size = 1;
                        int base = last_send + 1; 
                        // send segment
                        while (window_size > 0) {
                            // send new 
                            if (seg_state[base] == 0 || seg_state[base] == 1) {
                                // read file content
                                fseek(fp, (base-1)*MAX_SEG_SIZE, SEEK_SET);
                                if ((result = fread(send_seg.data, 1, MAX_SEG_SIZE, fp)) < 0) {
                                    perror("Error reading data");
                                    exit(0);
                                }
                                if (result == 0) {
                                    last = base-1;
                                    break;                    
                                }
                                send_seg.head.length = result;
                                send_seg.head.seqNumber = base;
                                send_seg.head.checksum = crc32(0L, (const Bytef *)send_seg.data, result);
                                if ((tmp = sendto(sock_fd, &send_seg, sizeof(send_seg), 0, (struct sockaddr *)&recv_addr, sizeof(recv_addr))) < 0) {
                                    perror("Error sending package");
                                    exit(0);
                                }
                                if (seg_state[base] == 0)
                                    printf("send\tdata\t#%d,\twinSize = %d\n", base, int(cwnd));
                                else if (seg_state[base] == 1)
                                    printf("resnd\tdata\t#%d,\twinSize = %d\n", base, int(cwnd));
                                seg_state[base] = 1;
                                window_size--;
                                last_send = base;
                            }
                            base++;
                        }
                    }
                    if (dup_ack == 3) {
                        // send missing
                        fseek(fp, (acked)*MAX_SEG_SIZE, SEEK_SET);
                        if ((result = fread(send_seg.data, 1, MAX_SEG_SIZE, fp)) < 0) {
                            perror("Error reading data");
                            exit(0);
                        }
                        send_seg.head.length = result;
                        send_seg.head.seqNumber = acked + 1;
                        send_seg.head.checksum = crc32(0L, (const Bytef *)send_seg.data, result);
                        if ((tmp = sendto(sock_fd, &send_seg, sizeof(send_seg), 0, (struct sockaddr *)&recv_addr, sizeof(recv_addr))) < 0) {
                            perror("Error sending package");
                            exit(0);
                        }
                        printf("resnd\tdata\t#%d,\twinSize = %d\n", acked + 1, int(cwnd));
                    }
                }
            }
        }
        // change state
        if (cwnd >= threshold) {
            stateslow = 0;
        }
        if (acked == last) {
            send_seg.head.fin = 1;
            send_seg.head.seqNumber = acked + 1;
            if (sendto(sock_fd, &send_seg, sizeof(send_seg), 0, (struct sockaddr *)&recv_addr, sizeof(sockaddr)) < 0) {
                perror("Error sending package");
                exit(0);
            }
            printf("send\tfin\n");
            printf("recv\tfinack\n");
            break;
        }
    }

    fclose(fp);
    exit(0);

    // // make a segment (do file IO stuff on your own)
    // const char *data = "hello";
    // int len = 5;
    
    // socklen_t recv_addr_sz;
    // segment sgmt{};
    // sgmt.head.length = len;
    // sgmt.head.seqNumber = 1;
    // bzero(sgmt.data, sizeof(char) * MAX_SEG_SIZE);
    // memcpy(sgmt.data, data, len);
    // sgmt.head.checksum = crc32(0L, (const Bytef *)sgmt.data, MAX_SEG_SIZE);
    
    // // send a segment! (do the logging on your own)
    // sendto(sock_fd, &sgmt, sizeof(sgmt), 0, (struct sockaddr *)&recv_addr, sizeof(sockaddr));

    // // receive a segment!
    // recvfrom(sock_fd, &sgmt, sizeof(sgmt), 0, (struct sockaddr *)&recv_addr, &recv_addr_sz);

    // cerr << "get ack number: " << sgmt.head.ackNumber << endl;
}