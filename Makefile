MAKEFLAGS += --no-print-directory

ifeq ($(OS),Windows_NT)
	EXE  := .exe
	WINE := 
else
	EXE  := 
	WINE := wine
endif

# Relevant directories
BUILD_DIR  :=  ./build
SRC_DIR    :=  ./src
INC_DIR    :=  ./include
TOOL_DIR   :=  ./tools

$(shell mkdir -p $(BUILD_DIR))

ELFCODER_DIR  :=  $(TOOL_DIR)/elfcoder
FIXDEP_DIR    :=  $(TOOL_DIR)/fixdep
MW_DIR        :=  $(TOOL_DIR)/mw

# Tools
MWCCARM   :=  $(MW_DIR)/mwccarm.exe
MWASMARM  :=  $(MW_DIR)/mwasmarm.exe
MWLDARM   :=  $(MW_DIR)/mwldarm.exe
ELFCODER  :=  $(ELFCODER_DIR)/build/elfcoder$(EXE)
FIXDEP    :=  $(FIXDEP_DIR)/build/fixdep$(EXE)

# C / ASM compilation parameters
CC_PARAM   :=  -O4,p -enum int -proc arm946E -gccext,on -fp soft -lang c99 -char signed -inline on,noauto -Cpp_exceptions off -interworking -i $(INC_DIR)
ASM_PARAM  :=  -proc arm5TE -i $(INC_DIR)
DEP_PARAM  :=  -gccdep -MD

CC_PARAM   +=  -W all -W pedantic -W noimpl_signedunsigned -W noimplicitconv -W nounusedarg -W nomissingreturn -W error

# Elfcoder parameters
ELFCODER_PARAM := --encode --start Encryptor_StartRange --end Encryptor_EndRange

# Depedency files
DEPS := $(wildcard $(BUILD_DIR)/*.d)

# Output library file
LIBRARY_NAME := dsprot.a

# Files (in this specific order) that will go into the library
LIBRARY_FILES := \
	$(BUILD_DIR)/encryptor.o              \
	$(BUILD_DIR)/rc4.o                    \
	$(BUILD_DIR)/mac_owner_encrypted.o    \
	$(BUILD_DIR)/rom_util_encrypted.o     \
	$(BUILD_DIR)/rom_test_encrypted.o     \
	$(BUILD_DIR)/dsprot_main_encrypted.o


.PHONY: all clean tools dsprot
.DELETE_ON_ERROR : 

all:
	$(MAKE) tools
	$(MAKE) dsprot

clean:
	$(MAKE) -C $(ELFCODER_DIR) clean
	$(MAKE) -C $(FIXDEP_DIR) clean
	$(RM) $(BUILD_DIR)/*

tools:
	$(MAKE) -C $(ELFCODER_DIR)
	$(MAKE) -C $(FIXDEP_DIR)

dsprot:
	$(MAKE) $(BUILD_DIR)/$(LIBRARY_NAME)


# Library output
$(BUILD_DIR)/$(LIBRARY_NAME): $(LIBRARY_FILES)
	$(WINE) $(MWLDARM) -nostdlib -library $(LIBRARY_FILES) -o $(BUILD_DIR)/$(LIBRARY_NAME)


# RC4 module
$(BUILD_DIR)/rc4.o: $(SRC_DIR)/rc4.c
	$(WINE) $(MWCCARM) $(CC_PARAM) $(DEP_PARAM) $(SRC_DIR)/rc4.c -o $(BUILD_DIR)/rc4.o
	$(FIXDEP) $(BUILD_DIR)/rc4.d


# Encryptor module
$(BUILD_DIR)/encryptor.o: $(SRC_DIR)/encryptor.c
	$(WINE) $(MWCCARM) $(CC_PARAM) $(DEP_PARAM) $(SRC_DIR)/encryptor.c -o $(BUILD_DIR)/encryptor.o
	$(FIXDEP) $(BUILD_DIR)/encryptor.d


# Core tests module: MAC/Owner, ROM utilities, ROM tests
$(BUILD_DIR)/mac_owner_encrypted.o: $(BUILD_DIR)/mac_owner.o $(ELFCODER)
	cp $(BUILD_DIR)/mac_owner.o $(BUILD_DIR)/mac_owner_encrypted.o
	$(ELFCODER) $(ELFCODER_PARAM) -i $(BUILD_DIR)/mac_owner_encrypted.o

$(BUILD_DIR)/rom_util_encrypted.o: $(BUILD_DIR)/rom_util.o $(ELFCODER)
	cp $(BUILD_DIR)/rom_util.o $(BUILD_DIR)/rom_util_encrypted.o
	$(ELFCODER) $(ELFCODER_PARAM) -i $(BUILD_DIR)/rom_util_encrypted.o

$(BUILD_DIR)/rom_test_encrypted.o: $(BUILD_DIR)/rom_test.o $(ELFCODER)
	cp $(BUILD_DIR)/rom_test.o $(BUILD_DIR)/rom_test_encrypted.o
	$(ELFCODER) $(ELFCODER_PARAM) -i $(BUILD_DIR)/rom_test_encrypted.o

$(BUILD_DIR)/mac_owner.o: $(SRC_DIR)/mac_owner.c
	$(WINE) $(MWCCARM) $(CC_PARAM) $(DEP_PARAM) $(SRC_DIR)/mac_owner.c -o $(BUILD_DIR)/mac_owner.o
	$(FIXDEP) $(BUILD_DIR)/mac_owner.d

$(BUILD_DIR)/rom_util.o: $(SRC_DIR)/rom_util.c
	$(WINE) $(MWCCARM) $(CC_PARAM) $(DEP_PARAM) $(SRC_DIR)/rom_util.c -o $(BUILD_DIR)/rom_util.o
	$(FIXDEP) $(BUILD_DIR)/rom_util.d

$(BUILD_DIR)/rom_test.o: $(SRC_DIR)/rom_test.c
	$(WINE) $(MWCCARM) $(CC_PARAM) $(DEP_PARAM) $(SRC_DIR)/rom_test.c -o $(BUILD_DIR)/rom_test.o
	$(FIXDEP) $(BUILD_DIR)/rom_test.d


# Main module
$(BUILD_DIR)/dsprot_main_encrypted.o: $(BUILD_DIR)/dsprot_main.o $(ELFCODER)
	cp $(BUILD_DIR)/dsprot_main.o $(BUILD_DIR)/dsprot_main_encrypted.o
	$(ELFCODER) $(ELFCODER_PARAM) -i $(BUILD_DIR)/dsprot_main_encrypted.o

$(BUILD_DIR)/dsprot_main.o: $(SRC_DIR)/dsprot_main.c
	$(WINE) $(MWCCARM) $(CC_PARAM) $(DEP_PARAM) $(SRC_DIR)/dsprot_main.c -o $(BUILD_DIR)/dsprot_main.o
	$(FIXDEP) $(BUILD_DIR)/dsprot_main.d


-include $(DEPS)
