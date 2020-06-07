SRC_DIR := src
OBJ_DIR := obj
LIB_DIR := libs
IFA_DIR := ifa
SHA_DIR := sha

CC=gcc
CFLAGS=-std=c99 -w -pthread -D_BSD_SOURCE 
CFLAGSANDROID=-std=c99 -w -pthread -D_BSD_SOURCE -D_NO_GETADDRINFO

all: tracemore

tracemore: obj_dir tracemore.c $(OBJ_DIR)/sha1.o $(OBJ_DIR)/ifaddrs.o 
	$(CC) -o tracemore tracemore.c $(OBJ_DIR)/sha1.o $(OBJ_DIR)/ifaddrs.o $(CFLAGS)

tracemore.o:	
	$(CC) tracemore.c -o tracemore.o $(CFLAGS)

$(OBJ_DIR)/sha1.o: $(LIB_DIR)/$(SHA_DIR)/sha1.c
	 $(CC) $(LIB_DIR)/$(SHA_DIR)/sha1.c -c -o $(OBJ_DIR)/sha1.o $(CFLAGS)

$(OBJ_DIR)/ifaddrs.o:  $(LIB_DIR)/$(IFA_DIR)/ifaddrs.c
	$(CC) $(LIB_DIR)/$(IFA_DIR)/ifaddrs.c -c -o $(OBJ_DIR)/ifaddrs.o $(CFLAGS)

obj_dir:
	@ mkdir -p $(OBJ_DIR)

clean: 
	@ rm -f $(OBJ_DIR)/*.o tracemore
