#CC=mips-gcc
TestServer := testCommsServer
TestClient := testCommsClient

CFLAGS = -Wall -g
INC = -I./socket -I./crypto

all: $(TestServer) $(TestClient)

libcomms.a: comms.o crypto.o socket.o
	ar rcs libcomms.a comms.o crypto.o socket.o

testCommsServer: testCommsServer.o libcomms.a
	$(CC) $(CFLAGS) $(INC) testCommsServer.o libcomms.a -o testCommsServer
testCommsServer.o: testCommsServer.c
	$(CC) $(CFLAGS) $(INC) -c testCommsServer.c

testCommsClient: testCommsClient.o libcomms.a
	$(CC) $(CFLAGS) $(INC) testCommsClient.o libcomms.a -o testCommsClient
testCommsClient.o: testCommsClient.c
	$(CC) $(CFLAGS) $(INC) -c testCommsClient.c

comms.o: comms.c
	$(CC) -c $(CFLAGS) $(INC) $< -o $@

crypto.o: crypto/crypto.c
	$(CC) -c $(CFLAGS) $(INC) $< -o $@

socket.o: socket/socket.c
	$(CC) -c $(CFLAGS) $(INC) $< -o $@

clean:
	rm -f *.o $(TestServer) $(TestClient) libcomms.a
