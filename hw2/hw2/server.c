#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stddef.h>

#include "utils/base64.h"

#define ERR_EXIT(a){ perror(a); exit(1); }

int handle_request(int connfd);

void *memmem(const void *haystack, size_t haystack_len, const void *needle, size_t needle_len) {
    const unsigned char *h = haystack;
    const unsigned char *n = needle;

    size_t i, j;
    for (i = 0; i <= haystack_len - needle_len; ++i) {
        for (j = 0; j < needle_len; ++j) {
            if (h[i + j] != n[j]) {
                break;
            }
        }
        if (j == needle_len) {
            return (void *)(h + i);
        }
    }

    return NULL;
}

int get_line(FILE *file, char *buffer, int max_length) {
    if (fgets(buffer, max_length, file) == NULL) {
        return 0; // Failed to read a line
    }
    // Remove newline character if present
    size_t length = strlen(buffer);
    if (length > 0 && buffer[length - 1] == '\n') {
        buffer[length - 1] = '\0';
    }
    return 1; // Successfully read a line
}

int validate_credentials(const char *password) {
    FILE *file = fopen("./secret", "r");
    if (file == NULL) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }
    char line[128];
    while (get_line(file, line, 128)) {
        // Split the line into username and password
        
        
        // Check if the provided credentials match the stored credentials
        if (strncmp(password, line, strlen(line) - 1) == 0) {
            
            fclose(file);
            return 1; // Credentials are valid
        }
    }
    fclose(file);
    return 0; // Credentials are not valid
}

char hexToChar(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else {
        return -1; // Invalid hex character
    }
}

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

char* urlDecode(const char* input) {
    int len = strlen(input);
    char* decoded = (char*)malloc(len + 1);

    int j = 0;
    for (int i = 0; i < len; ++i) {
        char c = input[i];
        if (c == '%' && i + 2 < len) {
            char hex1 = input[i + 1];
            char hex2 = input[i + 2];
            char decodedChar = hexToChar(hex1) * 16 + hexToChar(hex2);
            if (decodedChar != -1) {
                decoded[j++] = decodedChar;
                i += 2; // Skip the two hex characters
            } else {
                // Invalid hex characters, keep '%' as is
                decoded[j++] = c;
            }
        } else {
            decoded[j++] = c;
        }
    }
    decoded[j] = '\0';

    return decoded;
}

bool check_bound(const char *buffer, unsigned int lenth) {
    for (int i = 0; i < lenth-6; i++) {
        if ((buffer[i] == 'W') && (buffer[i+1] == 'e') && (buffer[i+2] == 'b') && (buffer[i+3] == 'K') && (buffer[i+4] == 'i') && (buffer[i+5] == 't'))
            return true;
    }
    return false;
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

int main(int argc, char *argv[]){
    const char *path1 = "./web/files";
    const char *path2 = "./web/videos";
    const char *path3 = "./web/tmp";
    if (!(mkdir(path1, 0755) == 0 && mkdir(path2, 0755) == 0 && mkdir(path3, 0755) == 0)) {
        perror("Error creating directory");
    }

    if (argc < 2) {
        fprintf(stderr, "Usage: %s [port]\n", argv[0]); 
        exit(-1); 
    }

    int client_socket[100];
    for (int i = 0; i < 100; i++)  
    {  
        client_socket[i] = 0;  
    }
    int opt = 1; 

    int listenfd, connfd;
    struct sockaddr_in server_addr, client_addr;
    int client_addr_len = sizeof(client_addr);

    // Get socket file descriptor
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        ERR_EXIT("socket()");
    if( setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt,sizeof(opt)) < 0 )
    {
        ERR_EXIT("setsockopt");
    }
    // Set server address information
    bzero(&server_addr, sizeof(server_addr)); // erase the data
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons((uint16_t)strtol(argv[1], NULL, 10));
    // Bind the server file descriptor to the server address
    if(bind(listenfd, (struct sockaddr *)&server_addr , sizeof(server_addr)) < 0)
        ERR_EXIT("bind()");
    // Listen on the server file descriptor
    if(listen(listenfd , 3) < 0)
        ERR_EXIT("listen()");
    
    fd_set master_fds, read_fds;
    FD_ZERO(&master_fds);
    FD_SET(listenfd, &master_fds);
    int max_fd = listenfd;
    int sd, activity, new_socket;
    int addrlen = sizeof(server_addr);
    while (1)
    {
        read_fds = master_fds;
        if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) == -1)
            ERR_EXIT("select()!!");

        for (int fd = 0; fd <= max_fd; ++fd)
        {
            if (FD_ISSET(fd, &read_fds))
            {
                if (fd == listenfd)
                {
                    // New connection
                    if ((connfd = accept(listenfd, (struct sockaddr *)&client_addr, (socklen_t *)&client_addr_len)) < 0)
                    {
                        ERR_EXIT("accept()");
                    }

                    FD_SET(connfd, &master_fds);
                    if (connfd > max_fd)
                    {
                        max_fd = connfd;
                    }
                }
                else
                {
                    // Handle request
                    if (handle_request(fd) == 1)
                    {
                        // Connection closed by client
                        close(fd);
                        FD_CLR(fd, &master_fds);
                    }
                }
            }
        }
    }    
}

int handle_request(int connfd)
{
    char buffer[4096];
    memset(buffer, 0, sizeof(buffer));
    int close_flag = 0;
    // Receive data from the client
    if (recv(connfd, buffer, sizeof(buffer), 0) < 0)
    {
        ERR_EXIT("recv()");
    }
    // Check the Connection field in the request
    if (strstr(buffer, "Connection: close") != NULL) {
        // Close the connection
        close_flag = 1;
    }
    int content_length = extract_content_length(buffer);
    char method[10]; // Assuming the method name won't be longer than 10 characters
    char path[256]; 
    if (sscanf(buffer, "%9s %255s", method, path) != 2) {
        return 0;
    }
    if (strcmp(path, "/") == 0) {
        if (strcmp(method, "GET") == 0) {
            FILE *file = fopen("./web/index.html", "r");
            if (file == NULL)
            {
                // Handle file opening error
                perror("fopen()");
                exit(1);
            }
            fseek(file, 0, SEEK_END);
            long length = ftell(file);
            fseek(file, 0, SEEK_SET);
            char *response = (char *)malloc(4096 + length);
            if (response == NULL)
            {
                // Handle memory allocation error
                perror("malloc()1");
                fclose(file);
                exit(1);
            }
            fread(response, 1, length, file);
            fclose(file);
            response[length] = '\0';
            char *http_response = (char *)malloc(4096 + length);
            
            sprintf(http_response, "HTTP/1.1 200 OK\r\n"
                                "Server: CN2023Server/1.0\r\n"
                                "Content-Type: text/html\r\n"
                                "Content-Length: %ld\r\n"
                                "\r\n%s",
                    length, response);
            if (send(connfd, http_response, strlen(http_response), 0) < 0)
            {
                ERR_EXIT("send() /");
            }
            free(response);
            free(http_response);
        }else {
            const char *http_response = "HTTP/1.1 405 Method Not Allowed\r\n"
                                "Server: CN2023Server/1.0\r\n"
                                "Allow: GET\r\n"
                                "Content-Length: 0\r\n"
                                "\r\n";
            // Send the response to the client
            if (send(connfd, http_response, strlen(http_response), 0) < 0) {
                ERR_EXIT("send() /");
            }
            for (int i = 0; i <= content_length / 4096; i++) {
                if (recv(connfd, buffer, sizeof(buffer), 0) < 0)
                {
                    ERR_EXIT("recv()");
                }
            }
        }
    }else if (strcmp(path, "/file/") == 0) {
        if (strcmp(method, "GET") == 0) {
            // Route: /file/
            FILE *file = fopen("./web/listf.rhtml", "r");
            if (file == NULL)
            {
                // Handle file opening error
                perror("fopen()");
                exit(1);
            }
            // Read the content of listf.rhtml
            fseek(file, 0, SEEK_END);
            long length = ftell(file);
            fseek(file, 0, SEEK_SET);
            char *response = (char *)malloc(length + 4096);
            if (response == NULL)
            {
                // Handle memory allocation error
                perror("malloc()3");
                fclose(file);
                exit(1);
            }
            fread(response, 1, length, file);
            fclose(file);
            response[length] = '\0';
            // Preprocess the HTML by replacing <?FILE_LIST?> with file list
            char file_list[1024] = "";
            DIR *dir;
            struct dirent *ent;

            if ((dir = opendir("./web/files")) != NULL)
            {
                while ((ent = readdir(dir)) != NULL)
                {
                    if (ent->d_type == DT_REG) // Only consider regular files
                    {
                        char file_row[1024];
                        char* encoded = urlEncode(ent->d_name);
                        sprintf(file_row, "<tr><td><a href=\"/api/file/%s\">%s</a></td></tr>\n", encoded, ent->d_name);
                        strcat(file_list, file_row);
                    }
                }
                closedir(dir);
            }
            else
            {
                // Handle directory opening error
                perror("opendir()");
                exit(1);
            }

            // Replace <?FILE_LIST?> with the actual file list
            char *file_list_tag = "<?FILE_LIST?>";
            char *file_list_start = strstr(response, file_list_tag);
            if (file_list_start != NULL)
            {
                // Calculate the length of the remaining part after replacing <?FILE_LIST?>
                size_t remaining_length = strlen(file_list_start + strlen(file_list_tag));

                // // Calculate the new length of the response after replacing <?FILE_LIST?>
                // size_t new_response_length = strlen(response) + strlen(file_list) - strlen(file_list_tag) + 1;

                // Resize the memory block to accommodate the new content

                // Move the remaining part to the correct position after resizing
                memmove(file_list_start + strlen(file_list), file_list_start + strlen(file_list_tag), remaining_length + 1);

                // Copy the file list to the correct position
                memcpy(file_list_start, file_list, strlen(file_list));
            }
            char http_response[length + 4096];
            sprintf(http_response, "HTTP/1.1 200 OK\r\n"
                                "Server: CN2023Server/1.0\r\n"
                                "Content-Type: text/html\r\n"
                                "Content-Length: %ld\r\n"
                                "\r\n%s",
                    strlen(response), response);

            // Send the response to the client
            if (send(connfd, http_response, strlen(http_response), 0) < 0)
            {
                ERR_EXIT("send() /file/ ");
            }

            free(response);
        }else {
            const char *http_response = "HTTP/1.1 405 Method Not Allowed\r\n"
                                "Server: CN2023Server/1.0\r\n"
                                "Allow: GET\r\n"
                                "Content-Length: 0\r\n"
                                "\r\n";

            // Send the response to the client
            if (send(connfd, http_response, strlen(http_response), 0) < 0) {
                ERR_EXIT("send() /file/ ");
            }
            for (int i = 0; i <= content_length / 4096; i++) {
                if (recv(connfd, buffer, sizeof(buffer), 0) < 0)
                {
                    ERR_EXIT("recv()");
                }
            }
        }
    }else if (strcmp(path, "/upload/file") == 0) { 
        if (strcmp(method, "GET") == 0) {
            char *authorization_header = strstr(buffer, "Authorization: Basic ");
            if (authorization_header == NULL)
            {
                const char *http_response = "HTTP/1.1 401 Unauthorized\r\n"
                        "Server: CN2023Server /1.0\r\n"
                        "WWW-Authenticate: Basic realm=b10902046\r\n"
                        "Content-Length: 0\r\n"
                        "\r\n";
                if (send(connfd, http_response, strlen(http_response), 0) < 0)
                {
                    ERR_EXIT("ask for ");
                }
                for (int i = 0; i <= content_length / 4096; i++) {
                    if (recv(connfd, buffer, sizeof(buffer), 0) < 0)
                    {
                        ERR_EXIT("recv()");
                    }
                }
            }else {
                
                authorization_header += strlen("Authorization: Basic ");
                char *authorization_end = strstr(authorization_header, "\r\n");
                if (authorization_end == NULL)
                {
                    ERR_EXIT("authorization_end");
                }

                char password[32] = {0};
                size_t password_len = authorization_end - authorization_header;
                if (password_len >= 32) {
                    fprintf(stderr, "password_len is too long\n");
                    return 0;
                }
                strncpy(password, authorization_header, password_len);
                password[password_len] = '\0';
                size_t de_len;
                unsigned char *pass_de = (unsigned char *)malloc(33);
                if (pass_de == NULL)
                    ERR_EXIT("pass_de");
                pass_de = base64_decode(password, password_len, &de_len);
                if (validate_credentials(pass_de) != 1) {
                    const char *http_response = "HTTP/1.1 401 Unauthorized\r\n"
                        "Server: CN2023Server /1.0\r\n"
                        "WWW-Authenticate: Basic realm=b10902046\r\n"
                        "Content-Length: 13\r\n"
                        "\r\n"
                        "Unauthorized\n";
                    if (send(connfd, http_response, strlen(http_response), 0) < 0)
                    {
                        ERR_EXIT("send()2");
                    }
                    for (int i = 0; i <= content_length / 4096; i++) {
                        if (recv(connfd, buffer, sizeof(buffer), 0) < 0)
                        {
                            ERR_EXIT("recv()");
                        }
                    }
                }else {
                    FILE *file = fopen("./web/uploadf.html", "r");
                    if (file == NULL)
                    {
                        // Handle file opening error
                        perror("fopen()");
                        exit(1);
                    }
                    fseek(file, 0, SEEK_END);
                    long length = ftell(file);
                    fseek(file, 0, SEEK_SET);
                    char *response = (char *)malloc(length + 1);
                    if (response == NULL)
                    {
                        // Handle memory allocation error
                        perror("malloc()2");
                        fclose(file);
                        exit(1);
                    }

                    fread(response, 1, length, file);
                    fclose(file);

                    response[length] = '\0';

                    char http_response[length + 1024];
                    sprintf(http_response, "HTTP/1.1 200 OK\r\n"
                                        "Server: CN2023Server/1.0\r\n"
                                        "Content-Type: text/html\r\n"
                                        "Content-Length: %ld\r\n"
                                        "\r\n%s",
                            length, response);

                    if (send(connfd, http_response, strlen(http_response), 0) < 0)
                    {
                        ERR_EXIT("send()/upload/file");
                    }

                    free(response);
                }
            }
        }else {
            const char *http_response = "HTTP/1.1 405 Method Not Allowed\r\n"
                                "Server: CN2023Server/1.0\r\n"
                                "Allow: GET\r\n"
                                "Content-Length: 0\r\n"
                                "\r\n";

            // Send the response to the client
            if (send(connfd, http_response, strlen(http_response), 0) < 0) {
                ERR_EXIT("send()/upload/file");
            }
            for (int i = 0; i <= content_length / 4096; i++) {
                if (recv(connfd, buffer, sizeof(buffer), 0) < 0)
                {
                    ERR_EXIT("recv()");
                }
            }
        }
    }else if (strcmp(path, "/api/file") == 0) {
        if (strcmp(method, "POST") == 0) {
            

            char *authorization_header = strstr(buffer, "Authorization: Basic ");
            if (authorization_header == NULL)
            {
                const char *http_response = "HTTP/1.1 401 Unauthorized\r\n"
                        "Server: CN2023Server /1.0\r\n"
                        "WWW-Authenticate: Basic realm=b10902046\r\n"
                        "Content-Length: 0\r\n"
                        "\r\n";
                if (send(connfd, http_response, strlen(http_response), 0) < 0)
                {
                    ERR_EXIT("ask for ");
                }
                for (int i = 0; i <= content_length / 4096; i++) {
                    if (recv(connfd, buffer, sizeof(buffer), 0) < 0)
                    {
                        ERR_EXIT("recv()");
                    }
                }
            }else {
                
                authorization_header += strlen("Authorization: Basic ");
                char *authorization_end = strstr(authorization_header, "\r\n");
                if (authorization_end == NULL)
                {
                    ERR_EXIT("authorization_end");
                }

                char password[256] = {0};
                size_t password_len = authorization_end - authorization_header;
                if (password_len >= 256) {
                    fprintf(stderr, "password_len is too long\n");
                    return 0;
                }
                strncpy(password, authorization_header, password_len);
                password[password_len] = '\0';
                size_t de_len;
                unsigned char *pass_de = (unsigned char *)malloc(256);
                if (pass_de == NULL)
                    perror("pass_de");
                pass_de = base64_decode(password, strlen(password) - strlen(password) % 4 , &de_len);
                if (pass_de == NULL)
                    ERR_EXIT("NULL");
                if (validate_credentials(pass_de) != 1) {
                    
                    const char *http_response = "HTTP/1.1 401 Unauthorized\r\n"
                        "Server: CN2023Server /1.0\r\n"
                        "WWW-Authenticate: Basic realm=b10902046\r\n"
                        "Content-Length: 0\r\n"
                        "\r\n"
                        "Unauthorized\n";
                    if (send(connfd, http_response, strlen(http_response), 0) < 0)
                    {
                        ERR_EXIT("send()2");
                    }
                    for (int i = 0; i <= content_length / 4096; i++) {
                        if (recv(connfd, buffer, sizeof(buffer), 0) < 0)
                        {
                            ERR_EXIT("recv()");
                        }
                    }
                }
                else if (strstr(buffer, "Content-Type: multipart/form-data") != NULL)
                { 
                    
                    const char *bound_start = strstr(buffer, "boundary=");
                    bound_start += (strlen("boundary="));
                    const char *bound_end = strstr(bound_start, "\r\n");
                    char bound[32] = {0};
                    strncpy(bound, bound_start, bound_end - bound_start);

                    const char *filename_start = strstr(buffer, "filename=\"");
                    int buffer_len = sizeof(buffer);
                    if (filename_start == NULL) {
                        memset(buffer, 0, 4096);
                        buffer_len = recv(connfd, buffer, 4096, 0);
                        if (buffer_len < 0) {
                            ERR_EXIT("recv()");
                        }
                        filename_start = strstr(buffer, "filename=\"");
                    }
                    
                    filename_start += strlen("filename=\"");
                    const char *filename_end = strchr(filename_start, '\"');
                    if (filename_end == NULL) {
                        fprintf(stderr, "Invalid multipart data format: filename end not found\n");
                        return 0;
                    }

                    size_t filename_length = filename_end - filename_start;
                    char *filename = (char *)malloc(64 * sizeof(char));
                    strncpy(filename, filename_start, filename_length);
                    filename[filename_length] = '\0';
                    char *filepath = (char *)malloc(128 * sizeof(char));
                    snprintf(filepath, 128, "./web/files/%s", filename);

                    int index_start = -1;
                    for (int i = (filename_start - buffer); i < buffer_len; i++) {
                        if ((buffer[i] == '\r') && (buffer[i+1] == '\n') && (buffer[i+2] == '\r') && (buffer[i+3] == '\n')) {
                            index_start = i+4;
                            break;
                        }
                    }
                    FILE *file = fopen(filepath, "wb");
                    int index_end = -1;
                    for (int i = 0; i < (index_start); i++) {
                        buffer[i] = 's';
                    }
                    
                    while(memmem(buffer, sizeof(buffer), bound, sizeof(bound)) == NULL){
                        for (int i = index_start; i < buffer_len; i++) {
                            if (content_length > 0) {
                                fwrite(&(buffer[i]), sizeof(char), 1, file);
                                content_length--;
                            }
                        }
                        index_start = 0;
                        memset(buffer, 0, 4096);
                        buffer_len = recv(connfd, buffer, 4096, 0);
                        if (buffer_len < 0) {
                            ERR_EXIT("recv()");
                        }
                    }
                    
                    const char *content_end = memmem(buffer, sizeof(buffer), bound, sizeof(bound));
                    
                    for (int i = (content_end - buffer); i > 0; i--) {
                        if ((buffer[i-1] == '\r')&&(buffer[i] == '\n')) {
                            index_end = i-1;
                        }
                    }
                    for (int i = index_start; i < index_end; i++) {
                        if (content_length > 0) {
                            fwrite(&(buffer[i]), sizeof(char), 1, file);
                            content_length--;
                        }
                    }
                    fclose(file);
                    const char *response = "HTTP/1.1 200 OK\r\n"
                                        "Server: CN2023Server/1.0\r\n"
                                        "Content-Type: text/plain\r\n"
                                        "Content-Length: 14\r\n"
                                        "\r\nFile Uploaded\n";

                    if (send(connfd, response, strlen(response), 0) < 0)
                    {
                        ERR_EXIT("send()3");
                    }
                    free(filename);
                    free(filepath);
                }
            }        
        }else {
            const char *http_response = "HTTP/1.1 405 Method Not Allowed\r\n"
                                "Server: CN2023Server/1.0\r\n"
                                "Allow: POST\r\n"
                                "Content-Length: 0\r\n"
                                "\r\n";

            // Send the response to the client
            if (send(connfd, http_response, strlen(http_response), 0) < 0) {
                ERR_EXIT("send()/api/file");
            }
            for (int i = 0; i <= content_length / 4096; i++) {
                if (recv(connfd, buffer, sizeof(buffer), 0) < 0)
                {
                    ERR_EXIT("recv()");
                }
            }
        }
    }else if (strstr(path, "/api/file/") != NULL) {
        
        if (strcmp(method, "GET") == 0) {
            char filepath_url[128];
            if (sscanf(buffer, "GET /api/file/%s", filepath_url) == 1) {
                char *filename = urlDecode(filepath_url);
                char full_path[128];
                snprintf(full_path, sizeof(full_path), "./web/files/%s", filename);
                
                FILE *file = fopen(full_path, "rb");
                if (file != NULL) {
                    // File exists, read its content and send it as the response
                    
                    fseek(file, 0, SEEK_END);
                    long length = ftell(file);
                    fseek(file, 0, SEEK_SET);

                    if (strstr(filepath_url, ".txt")) {
                        char *response = (char *)malloc(length + 1);
                        if (response != NULL) {
                            fread(response, 1, length, file);
                            fclose(file);

                            // Construct the HTTP response
                            char *http_response = (char *)malloc(length + 512);
                            sprintf(http_response, "HTTP/1.1 200 OK\r\n"
                                                "Server: CN2023Server/1.0\r\n"
                                                "Content-Type: text/plain\r\n"
                                                "Content-Length: %ld\r\n"
                                                "\r\n%s\r\n",
                                    length, response);

                            // Send the response to the client
                            if (send(connfd, http_response, strlen(http_response), 0) < 0) {
                                ERR_EXIT("send()");
                            }
                            free(http_response);    
                        } else {
                            // Handle memory allocation error
                            
                            fclose(file);
                            exit(1);
                        }
                        free(response);
                    }else {
                        unsigned char *response = (unsigned char *)malloc(length);
                        if (response != NULL) {
                            fread(response, 1, length, file);
                            fclose(file);

                            // Construct the HTTP response
                            char *http_response = (char *)malloc(length + 512);
                            sprintf(http_response, "HTTP/1.1 200 OK\r\n"
                                                "Server: CN2023Server/1.0\r\n"
                                                "Content-Type: application/octet-stream\r\n" // Set the content type to binary
                                                "Content-Length: %ld\r\n"
                                                "\r\n",
                                    length);
                            int final_len = strlen(http_response) + length;
                            // Concatenate the binary data to the HTTP response
                            memcpy(http_response + strlen(http_response), response, length);

                            // Send the response to the client
                            if (send(connfd, http_response, final_len, 0) < 0) {
                                perror("send()");
                                exit(EXIT_FAILURE);
                            }

                            free(http_response);
                            free(response);
                        }
                    }        
                } else {
                    // File not found, send a 404 Not Found response
                    const char *not_found_response = "HTTP/1.1 404 Not Found\r\n"
                                                    "Server: CN2023Server/1.0\r\n"
                                                    "Content-Type: text/plain\r\n"
                                                    "Content-Length: 0\r\n"
                                                    "\r\n";

                    if (send(connfd, not_found_response, strlen(not_found_response), 0) < 0) {
                        ERR_EXIT("send()");
                    }
                    for (int i = 0; i <= content_length / 4096; i++) {
                        if (recv(connfd, buffer, sizeof(buffer), 0) < 0)
                        {
                            ERR_EXIT("recv()");
                        }
                    }
                }
            }
        }else {
            const char *http_response = "HTTP/1.1 405 Method Not Allowed\r\n"
                                "Server: CN2023Server/1.0\r\n"
                                "Allow: GET\r\n"
                                "Content-Length: 0\r\n"
                                "\r\n";

            // Send the response to the client
            if (send(connfd, http_response, strlen(http_response), 0) < 0) {
                ERR_EXIT("send()");
            }
            for (int i = 0; i <= content_length / 4096; i++) {
                if (recv(connfd, buffer, sizeof(buffer), 0) < 0)
                {
                    ERR_EXIT("recv()");
                }
            }
        }
    }else if (strcmp(path, "/video/") == 0) {
        if (strcmp(method, "GET") == 0) {
            // Route: /video/
            FILE *file = fopen("./web/listv.rhtml", "r");
            if (file == NULL)
            {
                // Handle file opening error
                perror("fopen()");
                exit(1);
            }

            // Read the content of listv.rhtml
            fseek(file, 0, SEEK_END);
            long length = ftell(file);
            fseek(file, 0, SEEK_SET);

            char *response = (char *)malloc(length + 4096);
            if (response == NULL)
            {
                // Handle memory allocation error
                perror("malloc()5");
                fclose(file);
                exit(1);
            }

            fread(response, 1, length, file);
            fclose(file);

            response[length] = '\0';

            // Preprocess the HTML by replacing <?VIDEO_LIST?> with video list
            char video_list[1024] = "";
            DIR *dir;
            struct dirent *ent;

            if ((dir = opendir("./web/videos")) != NULL)
            {
                int count = 2;
                while ((ent = readdir(dir)) != NULL)
                {
                    if (ent->d_type == DT_DIR) // Only consider directories
                    {
                        if (count > 0) {
                            count--;
                            continue;
                        }
                        char video_row[1024];
                        char *url = urlEncode(ent->d_name);
                        
                        sprintf(video_row, "<tr><td><a href=\"/video/%s\">%s</a></td></tr>\n", url, ent->d_name);
                        strcat(video_list, video_row);
                    }
                }
                closedir(dir);
            }
            else
            {
                // Handle directory opening error
                perror("opendir()");
                exit(1);
            }

            // Replace <?VIDEO_LIST?> with the actual video list
            char *video_list_tag = "<?VIDEO_LIST?>";
            char *video_list_start = strstr(response, video_list_tag);
            if (video_list_start != NULL)
            {
                // Calculate the length of the remaining part after replacing <?VIDEO_LIST?>
                size_t remaining_length = strlen(video_list_start + strlen(video_list_tag));

                // Resize the memory block to accommodate the new content

                // Move the remaining part to the correct position after resizing
                memmove(video_list_start + strlen(video_list), video_list_start + strlen(video_list_tag), remaining_length + 1);

                // Copy the video list to the correct position
                memcpy(video_list_start, video_list, strlen(video_list));
            }

            // Construct the HTTP response
            
            char http_response[length + 4096];
            sprintf(http_response, "HTTP/1.1 200 OK\r\n"
                                "Server: CN2023Server/1.0\r\n"
                                "Content-Type: text/html\r\n"
                                "Content-Length: %ld\r\n"
                                "\r\n%s",
                    strlen(response), response);

            // Send the response to the client
            if (send(connfd, http_response, strlen(http_response), 0) < 0)
            {
                ERR_EXIT("send()");
            }

            free(response);
        }else {
            const char *http_response = "HTTP/1.1 405 Method Not Allowed\r\n"
                                "Server: CN2023Server/1.0\r\n"
                                "Allow: GET\r\n"
                                "Content-Length: 0\r\n"
                                "\r\n";

            // Send the response to the client
            if (send(connfd, http_response, strlen(http_response), 0) < 0) {
                ERR_EXIT("send()");
            }
            for (int i = 0; i <= content_length / 4096; i++) {
                if (recv(connfd, buffer, sizeof(buffer), 0) < 0)
                {
                    ERR_EXIT("recv()");
                }
            }
        }
    }else if (strcmp(path, "/upload/video") == 0) {
        if (strcmp(method, "GET") == 0) {
            char *authorization_header = strstr(buffer, "Authorization: Basic ");
            if (authorization_header == NULL)
            {
                const char *http_response = "HTTP/1.1 401 Unauthorized\r\n"
                        "Server: CN2023Server /1.0\r\n"
                        "WWW-Authenticate: Basic realm=b10902046\r\n"
                        "Content-Length: 0\r\n"
                        "\r\n";
                if (send(connfd, http_response, strlen(http_response), 0) < 0)
                {
                    ERR_EXIT("ask for ");
                }
                for (int i = 0; i <= content_length / 4096; i++) {
                    if (recv(connfd, buffer, sizeof(buffer), 0) < 0)
                    {
                        ERR_EXIT("recv()");
                    }
                }
            }else {
                
                authorization_header += strlen("Authorization: Basic ");
                char *authorization_end = strstr(authorization_header, "\r\n");
                if (authorization_end == NULL)
                {
                    ERR_EXIT("authorization_end");
                }

                char password[32] = {0};
                size_t password_len = authorization_end - authorization_header;
                if (password_len >= 32) {
                    fprintf(stderr, "password_len is too long\n");
                    return 0;
                }
                strncpy(password, authorization_header, password_len);
                password[password_len] = '\0';
                size_t de_len;
                unsigned char *pass_de = (unsigned char *)malloc(33);
                if (pass_de == NULL)
                    ERR_EXIT("pass_de");
                pass_de = base64_decode(password, password_len, &de_len);
                if (validate_credentials(pass_de) != 1) {
                    const char *http_response = "HTTP/1.1 401 Unauthorized\r\n"
                        "Server: CN2023Server /1.0\r\n"
                        "WWW-Authenticate: Basic realm=b10902046\r\n"
                        "Content-Length: 13\r\n"
                        "\r\n"
                        "Unauthorized\n";
                    if (send(connfd, http_response, strlen(http_response), 0) < 0)
                    {
                        ERR_EXIT("send()2");
                    }
                    for (int i = 0; i <= content_length / 4096; i++) {
                        if (recv(connfd, buffer, sizeof(buffer), 0) < 0)
                        {
                            ERR_EXIT("recv()");
                        }
                    }
                }else {
                    // Route: /upload/video
                    FILE *file = fopen("./web/uploadv.html", "r");
                    if (file == NULL)
                    {
                        // Handle file opening error
                        perror("fopen()");
                        exit(1);
                    }

                    fseek(file, 0, SEEK_END);
                    long length = ftell(file);
                    fseek(file, 0, SEEK_SET);

                    char *response = (char *)malloc(length + 1);
                    if (response == NULL)
                    {
                        // Handle memory allocation error
                        perror("malloc()4");
                        fclose(file);
                        exit(1);
                    }

                    fread(response, 1, length, file);
                    fclose(file);

                    response[length] = '\0';

                    char http_response[length + 1024];
                    sprintf(http_response, "HTTP/1.1 200 OK\r\n"
                                        "Server: CN2023Server/1.0\r\n"
                                        "Content-Type: text/html\r\n"
                                        "Content-Length: %ld\r\n"
                                        "\r\n%s",
                            length, response);

                    if (send(connfd, http_response, strlen(http_response), 0) < 0)
                    {
                        ERR_EXIT("send()");
                    }

                    free(response); 
                }
            }
        }else {
            const char *http_response = "HTTP/1.1 405 Method Not Allowed\r\n"
                                "Server: CN2023Server/1.0\r\n"
                                "Allow: GET\r\n"
                                "Content-Length: 0\r\n"
                                "\r\n";

            // Send the response to the client
            if (send(connfd, http_response, strlen(http_response), 0) < 0) {
                ERR_EXIT("send()");
            }
            for (int i = 0; i <= content_length / 4096; i++) {
                if (recv(connfd, buffer, sizeof(buffer), 0) < 0)
                {
                    ERR_EXIT("recv()");
                }
            }
        }
    }else if (strcmp(path, "/api/video") == 0) {
        if (strcmp(method, "POST") == 0) {
            char *authorization_header = strstr(buffer, "Authorization: Basic ");
            if (authorization_header == NULL)
            {
                const char *http_response = "HTTP/1.1 401 Unauthorized\r\n"
                        "Server: CN2023Server /1.0\r\n"
                        "WWW-Authenticate: Basic realm=b10902046\r\n"
                        "Content-Length: 0\r\n"
                        "\r\n";
                if (send(connfd, http_response, strlen(http_response), 0) < 0)
                {
                    ERR_EXIT("ask for ");
                }
                for (int i = 0; i <= content_length / 4096; i++) {
                    if (recv(connfd, buffer, sizeof(buffer), 0) < 0)
                    {
                        ERR_EXIT("recv()");
                    }
                }
            }else {
                
                authorization_header += strlen("Authorization: Basic ");
                char *authorization_end = strstr(authorization_header, "\r\n");
                if (authorization_end == NULL)
                {
                    ERR_EXIT("authorization_end");
                }

                char password[256] = {0};
                size_t password_len = authorization_end - authorization_header;
                if (password_len >= 256) {
                    fprintf(stderr, "password_len is too long\n");
                    return 0;
                }
                strncpy(password, authorization_header, password_len);
                password[password_len] = '\0';
                size_t de_len;
                unsigned char *pass_de = (unsigned char *)malloc(256);
                if (pass_de == NULL)
                    perror("pass_de");
                pass_de = base64_decode(password, strlen(password) - strlen(password) % 4 , &de_len);
                if (pass_de == NULL)
                    ERR_EXIT("NULL");
                if (validate_credentials(pass_de) != 1) {
                    const char *http_response = "HTTP/1.1 401 Unauthorized\r\n"
                        "Server: CN2023Server /1.0\r\n"
                        "WWW-Authenticate: Basic realm=b10902046\r\n"
                        "Content-Length: 0\r\n"
                        "\r\n"
                        "Unauthorized\n";
                    if (send(connfd, http_response, strlen(http_response), 0) < 0)
                    {
                        ERR_EXIT("send()2");
                    }
                    for (int i = 0; i <= content_length / 4096; i++) {
                        if (recv(connfd, buffer, sizeof(buffer), 0) < 0)
                        {
                            ERR_EXIT("recv()");
                        }
                    }
                }else if (strstr(buffer, "Content-Type: multipart/form-data") != NULL)
                {   
                    const char *bound_start = strstr(buffer, "boundary=");
                    bound_start += (strlen("boundary="));
                    const char *bound_end = strstr(bound_start, "\r\n");
                    char bound[32] = {0};
                    strncpy(bound, bound_start, bound_end - bound_start);

                    const char *filename_start = strstr(buffer, "filename=\"");
                    int buffer_len = sizeof(buffer);
                    if (filename_start == NULL) {
                        memset(buffer, 0, 4096);
                        buffer_len = recv(connfd, buffer, 4096, 0);
                        if (buffer_len < 0) {
                            ERR_EXIT("recv()");
                        }
                        filename_start = strstr(buffer, "filename=\"");
                    }
                    
                    filename_start += strlen("filename=\"");
                    const char *filename_end = strchr(filename_start, '\"');
                    if (filename_end == NULL) {
                        fprintf(stderr, "Invalid multipart data format: filename end not found\n");
                        return 0;
                    }

                    size_t filename_length = filename_end - filename_start;
                    char *filename = (char *)malloc(64 * sizeof(char));
                    strncpy(filename, filename_start, filename_length);
                    filename[filename_length] = '\0';
                    char *filepath = (char *)malloc(128 * sizeof(char));
                    snprintf(filepath, 128, "./web/tmp/%s", filename);
                    
                    int index_start = -1;
                    for (int i = (filename_start - buffer); i < buffer_len; i++) {
                        if ((buffer[i] == '\r') && (buffer[i+1] == '\n') && (buffer[i+2] == '\r') && (buffer[i+3] == '\n')) {
                            index_start = i+4;
                            break;
                        }
                    }
                    FILE *file = fopen(filepath, "wb");
                    int index_end = -1;
                    for (int i = 0; i < (index_start); i++) {
                        buffer[i] = 's';
                    }
                    
                    while(memmem(buffer, sizeof(buffer), bound, sizeof(bound)) == NULL){
                        for (int i = index_start; i < buffer_len; i++) {
                            if (content_length > 0) {
                                fwrite(&(buffer[i]), sizeof(char), 1, file);
                                content_length--;
                            }
                        }
                        index_start = 0;
                        memset(buffer, 0, 4096);
                        buffer_len = recv(connfd, buffer, 4096, 0);
                        if (buffer_len < 0) {
                            ERR_EXIT("recv()");
                        }
                    }
                    
                    const char *content_end = memmem(buffer, sizeof(buffer), bound, sizeof(bound));
                    
                    for (int i = (content_end - buffer); i > 0; i--) {
                        if ((buffer[i-1] == '\r')&&(buffer[i] == '\n')) {
                            index_end = i-1;
                        }
                    }
                    for (int i = index_start; i < index_end; i++) {
                        if (content_length > 0) {
                            fwrite(&(buffer[i]), sizeof(char), 1, file);
                            content_length--;
                        }
                    }
                    
                    fclose(file);
                    const char *response = "HTTP/1.1 200 OK\r\n"
                                        "Server: CN2023Server/1.0\r\n"
                                        "Content-Type: text/plain\r\n"
                                        "Content-Length: 15\r\n"
                                        "\r\nVideo Uploaded\n";

                    if (send(connfd, response, strlen(response), 0) < 0)
                    {
                        ERR_EXIT("send()");
                    }
                    char name[64] = {0};
                    strncpy(name, filename, strlen(filename)-4);
                    name[strlen(filename)-4] = '\0';
                    
                    char *dirpath = (char *)malloc(128 * sizeof(char));
                    snprintf(dirpath, 128, "./web/videos/%s", name);
                    mkdir(dirpath, 0755);
                    char ffmpeg_command[1024];
                    char mpd[128];
                    snprintf(mpd, 128, "./web/videos/%s/dash.mpd", name);
                    pid_t child_pid = fork();

                    if (child_pid == -1) {
                        perror("fork");
                        exit(EXIT_FAILURE);
                    } else if (child_pid == 0) {
                        snprintf(ffmpeg_command, sizeof(ffmpeg_command),
                                "ffmpeg -re -i \"%s\" -c:a aac -c:v libx264 "
                                "-map 0 -b:v:1 6M -s:v:1 1920x1080 -profile:v:1 high "
                                "-map 0 -b:v:0 144k -s:v:0 256x144 -profile:v:0 baseline "
                                "-bf 1 -keyint_min 120 -g 120 -sc_threshold 0 -b_strategy 0 "
                                "-ar:a:1 22050 -use_timeline 1 -use_template 1 "
                                "-adaptation_sets \"id=0,streams=v id=1,streams=a\" -f dash "
                                "\"%s\"",
                                filepath, mpd);
                        system(ffmpeg_command);   
                        free(filename);
                        free(filepath);
                        exit(EXIT_SUCCESS);
                    }else {
                        int status;
                        pid_t result = waitpid(child_pid, &status, WNOHANG);
                    }    
                }
            }
        }else {
            const char *http_response = "HTTP/1.1 405 Method Not Allowed\r\n"
                                "Server: CN2023Server/1.0\r\n"
                                "Allow: POST\r\n"
                                "Content-Length: 0\r\n"
                                "\r\n";

            // Send the response to the client
            if (send(connfd, http_response, strlen(http_response), 0) < 0) {
                ERR_EXIT("send()");
            }
            for (int i = 0; i <= content_length / 4096; i++) {
                if (recv(connfd, buffer, sizeof(buffer), 0) < 0)
                {
                    ERR_EXIT("recv()");
                }
            }
        }
    }else if (strstr(path, "/api/video/") != NULL) {
        
        if (strcmp(method, "GET") == 0) {
            char filepath[64];
            if (sscanf(buffer, "GET /api/video/%s", filepath) == 1) {        
                char *url = urlDecode(filepath);
                // Construct the full path to the file
                char full_path[128];
                snprintf(full_path, sizeof(full_path), "./web/videos/%s", url);
                
                // Open the file in read mode
                FILE *file = fopen(full_path, "rb");
                
                if (file != NULL) {
                    fseek(file, 0, SEEK_END);
                    long length = ftell(file);
                    fseek(file, 0, SEEK_SET);

                    unsigned char *response = (unsigned char *)malloc(length);
                    if (response != NULL) {
                        fread(response, 1, length, file);
                        fclose(file);

                        // Construct the HTTP response
                        char *http_response = (char *)malloc(length + 512);
                        sprintf(http_response, "HTTP/1.1 200 OK\r\n"
                                            "Server: CN2023Server/1.0\r\n"
                                            "Content-Type: %s\r\n" // Set the content type to binary
                                            "Content-Length: %ld\r\n"
                                            "\r\n",
                               (strstr(filepath, "mpd") != NULL) ? "application/dash+xml" : "video/iso.segment", length);
                        int final_len = strlen(http_response) + length;
                        // Concatenate the binary data to the HTTP response
                        memcpy(http_response + strlen(http_response), response, length);

                        // Send the response to the client
                        if (send(connfd, http_response, final_len, 0) < 0) {
                            perror("send()");
                            exit(EXIT_FAILURE);
                        }

                        free(http_response);
                        free(response);
                    }
                } else {
                    // File not found, send a 404 Not Found response
                    const char *not_found_response = "HTTP/1.1 404 Not Found\r\n"
                                                    "Server: CN2023Server/1.0\r\n"
                                                    "Content-Type: text/plain\r\n"
                                                    "Content-Length: 0\r\n"
                                                    "\r\n";

                    if (send(connfd, not_found_response, strlen(not_found_response), 0) < 0) {
                        ERR_EXIT("send()");
                    }
                    for (int i = 0; i <= content_length / 4096; i++) {
                        if (recv(connfd, buffer, sizeof(buffer), 0) < 0)
                        {
                            ERR_EXIT("recv()");
                        }
                    }
                }
            }
        }else {
            const char *http_response = "HTTP/1.1 405 Method Not Allowed\r\n"
                                "Server: CN2023Server/1.0\r\n"
                                "Allow: GET\r\n"
                                "Content-Length: 0\r\n"
                                "\r\n";

            // Send the response to the client
            if (send(connfd, http_response, strlen(http_response), 0) < 0) {
                ERR_EXIT("send()");
            }
            for (int i = 0; i <= content_length / 4096; i++) {
                if (recv(connfd, buffer, sizeof(buffer), 0) < 0)
                {
                    ERR_EXIT("recv()");
                }
            }
        }
    }else if (strstr(path, "/video/") != NULL) {
        if (strcmp(method, "GET") == 0) {
            char videoname_url[256];
            if (sscanf(buffer, "GET /video/%s", videoname_url) == 1)
            {
                // Read the content of player.rhtml
                FILE *file = fopen("./web/player.rhtml", "r");
                if (file == NULL)
                {
                    // Handle file opening error
                    perror("fopen()");
                    exit(1);
                }

                fseek(file, 0, SEEK_END);
                long length = ftell(file);
                fseek(file, 0, SEEK_SET);

                char *response = (char *)malloc(length + 1);
                if (response == NULL)
                {
                    // Handle memory allocation error
                    perror("malloc()6");
                    fclose(file);
                    exit(1);
                }

                fread(response, 1, length, file);
                fclose(file);

                response[length] = '\0';
                
                // Replace <?VIDEO_NAME?> with the actual videoname
                char *videoname_tag = "<?VIDEO_NAME?>";
                char *videoname_start = strstr(response, videoname_tag);
                if (videoname_start != NULL)
                {
                    char *videoname = urlDecode(videoname_url);
                    size_t remaining_length = strlen(videoname_start + strlen(videoname_tag));
                    size_t new_response_length = strlen(response) + strlen(videoname) - strlen(videoname_tag) + 1;

                    response = realloc(response, new_response_length);
                    if (response == NULL)
                    {
                        perror("realloc()");
                        exit(1);
                    }
                    memmove(videoname_start + strlen(videoname), videoname_start + strlen(videoname_tag), remaining_length + 1);
                    memcpy(videoname_start, videoname, strlen(videoname));
                }

                //    \"/api/file/%s\"
                
                // Replace <?MPD_PATH?> with the actual MPD URL
                char mpd_path_tag[] = "<?MPD_PATH?>";
                char mpd_path[512];
                snprintf(mpd_path, sizeof(mpd_path), "\"/api/video/%s/dash.mpd\"", videoname_url);
                char *mpd_path_start = strstr(response, mpd_path_tag);
                if (mpd_path_start != NULL)
                {
                    size_t remaining_length = strlen(mpd_path_start + strlen(mpd_path_tag));
                    size_t new_response_length = strlen(response) + strlen(mpd_path) - strlen(mpd_path_tag) + 1;

                    response = realloc(response, new_response_length);
                    if (response == NULL)
                    {
                        perror("realloc()");
                        exit(1);
                    }

                    memmove(mpd_path_start + strlen(mpd_path), mpd_path_start + strlen(mpd_path_tag), remaining_length + 1);
                    memcpy(mpd_path_start, mpd_path, strlen(mpd_path));
                }
                
                // Construct the HTTP response
                char http_response[length + 4096];
                sprintf(http_response, "HTTP/1.1 200 OK\r\n"
                                    "Server: CN2023Server/1.0\r\n"
                                    "Content-Type: text/html\r\n"
                                    "Content-Length: %ld\r\n"
                                    "\r\n%s",
                        strlen(response), response);

                // Send the response to the client
                if (send(connfd, http_response, strlen(http_response), 0) < 0)
                {
                    ERR_EXIT("send()");
                }
                free(response);
            }
        }else {
            const char *http_response = "HTTP/1.1 405 Method Not Allowed\r\n"
                                "Server: CN2023Server/1.0\r\n"
                                "Allow: GET\r\n"
                                "Content-Length: 0\r\n"
                                "\r\n";

            // Send the response to the client
            if (send(connfd, http_response, strlen(http_response), 0) < 0) {
                ERR_EXIT("send()");
            }
            for (int i = 0; i <= content_length / 4096; i++) {
                if (recv(connfd, buffer, sizeof(buffer), 0) < 0)
                {
                    ERR_EXIT("recv()");
                }
            }
        }
    }else {
        const char *not_found_response = "HTTP/1.1 404 Not Found\r\n"
                                                "Server: CN2023Server/1.0\r\n"
                                                "Content-Type: text/plain\r\n"
                                                "Content-Length: 0\r\n"
                                                "\r\n";

        if (send(connfd, not_found_response, strlen(not_found_response), 0) < 0) {
            ERR_EXIT("send()");
        }
        for (int i = 0; i <= content_length / 4096; i++) {
            if (recv(connfd, buffer, sizeof(buffer), 0) < 0)
            {
                ERR_EXIT("recv()");
            }
        }
    }
    return close_flag;
}
