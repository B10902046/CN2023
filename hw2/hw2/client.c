#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/socket.h> 
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<unistd.h> 
#include <netdb.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "utils/base64.h"

#define BUFF_SIZE 1024
#define PORT 9999
#define ERR_EXIT(a){ perror(a); exit(1); }

char* urlEncode(const char* input) {
    int len = strlen(input);
    char* encoded = (char*)malloc(3 * len + 1); // Maximum possible length after encoding

    int j = 0;
    for (int i = 0; i < len; ++i) {
        char c = input[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~' || c == '/') {
            encoded[j++] = c;
        } else {
            sprintf(&encoded[j], "%%%02X", c);
            j += 3;
        }
    }
    encoded[j] = '\0';

    return encoded;
}

int extract_content_length(const char *headers) {
    const char *content_length_str = "Content-Length:";
    const char *content_length_start = strstr(headers, content_length_str);

    if (content_length_start != NULL) {
        // Move to the value part after "Content-Length:"
        content_length_start += strlen(content_length_str);

        // Extract the content length as an integer
        return atoi(content_length_start);
    }

    // Content-Length not found in headers
    return -1;
}

int main(int argc , char *argv[]){
    if (argc < 3 || argc > 4) {
        fprintf(stderr, "Usage: %s [host] [port] [username:password]\n", argv[0]); 
        exit(-1); 
    }

    int sockfd;
    // struct sockaddr_in addr;
    struct addrinfo hints;
    struct addrinfo *res, *p;
    char buffer[BUFF_SIZE] = {};

    // Get socket file descriptor
    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        ERR_EXIT("socket()");
    }
    
    // Set up hints for getaddrinfo
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM;

    // Get address info for the host
    if (getaddrinfo(argv[1], argv[2], &hints, &res) != 0) {
        fprintf(stderr, "getaddrinfo() failed\n");
        exit(-1);
    }

    // Attempt to connect using the obtained address info
    for (p = res; p != NULL; p = p->ai_next) {
        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == 0) {
            break; // Success
        }
    }

    if (p == NULL) {
        perror("connect()");
        exit(-1);
    }

    freeaddrinfo(res); 
   
    while(1){
        printf("> ");

        /* Processing input arguments */
        char* line = NULL;
        size_t len = 0;
        getline(&line, &len, stdin);
        
        char* temp = strdup(line);
        char* save = temp;
        strsep(&temp, "\n");
        char* cmd = strtok(save, " ");
        if(strcmp(cmd, "put") == 0) {
            char *filename = (char *)malloc(32 * sizeof(char));
            
            if (strlen(line) == 4) {
                fprintf(stderr, "Usage: put [file]\n"); 
                continue;
            }
            for (int i = strlen(cmd) + 1; i < strlen(line); i++) {
                filename[i - strlen(cmd) - 1] = line[i];
            }
            filename[strlen(line) - strlen(cmd) - 1] = '\0';
            char filepath[64];
            snprintf(filepath, strlen(filename), "%s", filename);

            FILE *file = fopen(filepath, "rb");
            if (file == NULL) {
                fprintf(stderr, "Command failed.\n"); 
                continue;
            }
            fseek(file, 0, SEEK_END);
            long length = ftell(file);
            fseek(file, 0, SEEK_SET);
            
            
            unsigned char *response = (unsigned char *)malloc(length);
            if (response != NULL) {
                fread(response, 1, length, file);
                fclose(file);
                unsigned char *pass_de = (unsigned char *)malloc(256);
                size_t de_len;
                pass_de = base64_encode(argv[3], strlen(argv[3]), &de_len);
                char *http_request = (char *)malloc(length + 4096);
                sprintf(http_request, "POST /api/file HTTP/1.1\r\n"
                                    "Host: %s\r\n"
                                    "User-Agent: CN2023Client/1.0\r\n"
                                    "Connection: keep-alive\r\n"
                                    "Content-Type: multipart/form-data;boundary=WebKitFormBoundary\r\n"
                                    "Authorization: Basic %s\r\n"
                                    "Content-Length: %ld\r\n\r\n", argv[1], pass_de, length);
                if (send(sockfd, http_request, strlen(http_request), 0) < 0) {
                    ERR_EXIT("send()");
                }
                sprintf(http_request, "WebKitFormBoundary\r\n"
                                    "Content-Disposition: form-data; name=\"upfile\"; filename=\"%s\"\r\n"
                                    "Content-Type: text/plain\r\n"
                                    "\r\n",
                    filepath);
                int len = strlen(http_request) + length;
                memcpy(http_request + strlen(http_request), response, length);
                if (send(sockfd, http_request, len, 0) < 0) {
                    ERR_EXIT("send()");
                }
                const char *response_end =  "\r\nWebKitFormBoundary";
                if (send(sockfd, response_end, strlen(response_end), 0) < 0) {
                    ERR_EXIT("send()");
                }
                fprintf(stdout, "Command succeeded.\n"); 
                if(read(sockfd, buffer, sizeof(buffer)) < 0){
                    ERR_EXIT("read()");
                }
                free(http_request);
            }
            free(response);
            free(filename);
        }else if (strcmp(cmd, "putv") == 0) {
            char *filename = (char *)malloc(32 * sizeof(char));
            
            if (strlen(line) == 5) {
                fprintf(stderr, "Usage: putv [file]\n"); 
                continue;
            }

            for (int i = strlen(cmd) + 1; i < strlen(line); i++) {
                filename[i - strlen(cmd) - 1] = line[i];
            }
            filename[strlen(line) - strlen(cmd) - 1] = '\0';
            char filepath[64];
            snprintf(filepath, strlen(filename), "%s", filename);

            FILE *file = fopen(filepath, "rb");
            if (file == NULL) {
                fprintf(stderr, "Command failed.\n"); 
                continue;
            }
            fseek(file, 0, SEEK_END);
            long length = ftell(file);
            fseek(file, 0, SEEK_SET);
            
            
            unsigned char *response = (unsigned char *)malloc(length);
            if (response != NULL) {
                fread(response, 1, length, file);
                fclose(file);
                unsigned char *pass_de = (unsigned char *)malloc(256);
                size_t de_len;
                pass_de = base64_encode(argv[3], strlen(argv[3]), &de_len);
                char *http_request = (char *)malloc(length + 4096);
                sprintf(http_request, "POST /api/video HTTP/1.1\r\n"
                                    "Host: %s\r\n"
                                    "User-Agent: CN2023Client/1.0\r\n"
                                    "Connection: keep-alive\r\n"
                                    "Content-Type: multipart/form-data;boundary=WebKitFormBoundary\r\n"
                                    "Authorization: Basic %s\r\n"
                                    "Content-Length: %ld\r\n\r\n", argv[1], pass_de, length);
                if (send(sockfd, http_request, strlen(http_request), 0) < 0) {
                    ERR_EXIT("send()");
                }
                sprintf(http_request, "WebKitFormBoundary\r\n"
                                    "Content-Disposition: form-data; name=\"upfile\"; filename=\"%s\"\r\n"
                                    "Content-Type: video/mp4\r\n"
                                    "\r\n",
                    filepath);
                int len = strlen(http_request) + length;
                memcpy(http_request + strlen(http_request), response, length);
                if (send(sockfd, http_request, len, 0) < 0) {
                    ERR_EXIT("send()");
                }
                const char *response_end =  "\r\nWebKitFormBoundary";
                if (send(sockfd, response_end, strlen(response_end), 0) < 0) {
                    ERR_EXIT("send()");
                }
                fprintf(stdout, "Command succeeded.\n"); 
                if(read(sockfd, buffer, sizeof(buffer)) < 0){
                    ERR_EXIT("read()");
                }
                free(http_request);
            }
            free(response);
            free(filename);
        }else if (strcmp(cmd, "get") == 0) {
            char *filename = (char *)malloc(32 * sizeof(char));
            if (strlen(line) == 4) {
                fprintf(stderr, "Usage: get [file]"); 
                continue;
            }
            for (int i = strlen(cmd) + 1; i < strlen(line); i++) {
                filename[i - strlen(cmd) - 1] = line[i];
            }
            char filepath[64];
            snprintf(filepath, strlen(filename), "%s", filename);
            printf("%s", filepath);
            char* encoded = urlEncode(filepath);
            printf("%s", encoded);
            const char *path1 = "./files";
            mkdir(path1, 0755);

            char *http_request = (char *)malloc(4096);
            sprintf(http_request, "GET /api/file/%s HTTP/1.1\r\n"
                                "Host: %s\r\n"
                                "User-Agent: CN2023Client/1.0\r\n"
                                "Connection: keep-alive\r\n"
                                , encoded, argv[1]);
            if (send(sockfd, http_request, strlen(http_request), 0) < 0) {
                ERR_EXIT("send()");
            }
            if(read(sockfd, buffer, sizeof(buffer)) < 0){
                ERR_EXIT("read()");
            }
            if (strstr(buffer, "404 Not Found")!=NULL) {
                fprintf(stderr, "Command failed.\n"); 
                continue;
            }else {
    
                int length = extract_content_length(buffer);
                
                char *start = strstr(buffer, "\r\n\r\n");
                if (start == NULL) {
                    ERR_EXIT("start");
                }
                start += strlen("\r\n\r\n");
                int start_index = start-buffer;
                length -= 1024;
                char full_path[128];
                snprintf(full_path, sizeof(full_path), "./files/%s", filepath);
                FILE *file = fopen(full_path, "wb");
                while (length > 0) {
                    for (int i = start_index; i < 1024; i++) {
                        fwrite(&(buffer[i]), sizeof(char), 1, file);
                    }
                    if(read(sockfd, buffer, sizeof(buffer)) < 0){
                        ERR_EXIT("read()");
                    }
                    length -= 1024;
                    start_index = 0;
                }
                char *end = strstr(buffer, "\r\n");
                fwrite(buffer, sizeof(char), end - buffer, file);
                fclose(file);
                fprintf(stdout, "Command succeeded.\n"); 
            }
            free(filename);
            free(http_request);
        }else if (strcmp(cmd, "quit") == 0) {
            fprintf(stderr, "Bye.\n"); 
            const char *close_connect = "Connection: close";
            if (send(sockfd, close_connect, strlen(close_connect), 0) < 0) {
                ERR_EXIT("send()");
            }
            if(read(sockfd, buffer, sizeof(buffer)) < 0){
                ERR_EXIT("read()");
            }
            break;
        }else {
            fprintf(stderr, "Command Not Found.\n"); 
        }
    }

    close(sockfd);

    return 0;
}
