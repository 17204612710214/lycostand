#CC      = arm-linux-gnueabihf-gcc
CC      = gcc

EXEC    = lycostand

LIBS    = -lm -lpcap -lpthread

SRC_DIR = .
INC_DIR = ./incl
BUILD_DIR = ./build
SRC     = $(wildcard $(SRC_DIR)/*.c)
OBJ     = $(SRC:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
DEP     = $(OBJ:$(BUILD_DIR)/%.o=$(BUILD_DIR)/%.d)
DEF_FILE = ./options.def  

MKDIR_P = mkdir -p

INC     = -I $(INC_DIR)
CFLAGS  = -Wall -Wextra -Wextra -Wswitch-default -Wswitch-unreachable -Wswitch-bool \
		  -Wmisleading-indentation -Wnull-dereference -Winit-self -Wstack-protector -Wformat \
		  -Wformat-security -Wformat-overflow -Wdouble-promotion -Wunused-parameter -Wunused-const-variable \
		  -Wuninitialized -Wpointer-arith -Wincompatible-pointer-types -Wbad-function-cast \
		  -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wlong-long -Og  -g -O0\
		  -Ofast
LDFLAGS = -gdwarf-2 -L/usr/local/lib


.PHONY: clean cleandep mrproper

all: $(EXEC)

lycostand: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS) 

-include $(DEP)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c 
	@mkdir -p $(BUILD_DIR)
	$(CC) -MMD -o $@ -c $< $(CFLAGS) $(INC) -imacros $(DEF_FILE)

clean:
	rm -rf $(BUILD_DIR)/*.o

cleandep:
	rm -rf $(BUILD_DIR)/*.d
	
mrproper: clean cleandep
	rm -rf $(EXEC)

