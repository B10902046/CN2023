.PHONY: all clean

all: server client
server: server.c
	gcc -o server server.c ./utils/base64.c
client: client.c
	gcc -o client client.c ./utils/base64.c
clean:
	@rm -rf server client 
