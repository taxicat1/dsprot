ifeq ($(OS),Windows_NT)
	EXE := .exe
else
	EXE := 
endif

SRC_DIR := ./src
INC_DIR := ./include

C_FILES := $(wildcard $(SRC_DIR)/*.c)
H_FILES := $(wildcard $(INC_DIR)/*.h)

.PHONY: clean

fixdep$(EXE): $(C_FILES) $(H_FILES)
	$(CC) -O3 -I $(INC_DIR) $(C_FILES) -o fixdep$(EXE)

clean:
	$(RM) fixdep$(EXE)
