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
MWCCARM_DIR   ?=  $(TOOL_DIR)/mwccarm

MW_VER := 2.0/sp2p2

# Tools
MWCCARM   :=  $(MWCCARM_DIR)/$(MW_VER)/mwccarm.exe
MWASMARM  :=  $(MWCCARM_DIR)/$(MW_VER)/mwasmarm.exe
MWLDARM   :=  $(MWCCARM_DIR)/$(MW_VER)/mwldarm.exe
ELFCODER  :=  $(ELFCODER_DIR)/build/elfcoder$(EXE)
FIXDEP    :=  $(FIXDEP_DIR)/build/fixdep$(EXE)

# C / ASM compilation parameters
CC_PARAM   :=  -O4,p -enum int -proc arm946E -gccext,on -fp soft -lang c99 -char signed -inline on,noauto -Cpp_exceptions off -interworking -c -i $(INC_DIR)
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


.PHONY: all clean tools dsprot install
.DELETE_ON_ERROR: 

all:
	$(MAKE) tools
	$(MAKE) dsprot

clean:
	$(MAKE) -C $(ELFCODER_DIR) clean
	$(MAKE) -C $(FIXDEP_DIR) clean
	$(RM) -r $(BUILD_DIR)

tools:
	$(MAKE) -C $(ELFCODER_DIR)
	$(MAKE) -C $(FIXDEP_DIR)

dsprot:
	$(MAKE) $(BUILD_DIR)/$(LIBRARY_NAME)

ifeq ($(INSTALL_DIR),)
install:
	$(error Nowhere to install. Specify INSTALL_DIR)
else
install:
	$(MAKE) all
	$(shell mkdir -p $(INSTALL_DIR)/lib/)
	cp $(BUILD_DIR)/$(LIBRARY_NAME) $(INSTALL_DIR)/lib/
endif


# Assembly assembling
$(BUILD_DIR)/%.o: $(BUILD_DIR)/%.s
	$(WINE) $(MWASMARM) $(ASM_PARAM) $< -o $@


# C compilation
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(WINE) $(MWCCARM) $(CC_PARAM) $(DEP_PARAM) $< -o $@
	$(FIXDEP) $(@:.o=.d)


# Library output
$(BUILD_DIR)/$(LIBRARY_NAME): $(LIBRARY_FILES)
	$(WINE) $(MWLDARM) -nostdlib -library $(LIBRARY_FILES) -o $(BUILD_DIR)/$(LIBRARY_NAME)


# Core tests module: MAC/Owner, ROM utilities, ROM tests function encoding
$(BUILD_DIR)/mac_owner_encrypted.o: $(BUILD_DIR)/mac_owner.o $(ELFCODER)
	cp $(BUILD_DIR)/mac_owner.o $(BUILD_DIR)/mac_owner_encrypted.o
	$(ELFCODER) $(ELFCODER_PARAM) -i $(BUILD_DIR)/mac_owner_encrypted.o

$(BUILD_DIR)/rom_util_encrypted.o: $(BUILD_DIR)/rom_util.o $(ELFCODER)
	cp $(BUILD_DIR)/rom_util.o $(BUILD_DIR)/rom_util_encrypted.o
	$(ELFCODER) $(ELFCODER_PARAM) -i $(BUILD_DIR)/rom_util_encrypted.o

$(BUILD_DIR)/rom_test_encrypted.o: $(BUILD_DIR)/rom_test.o $(ELFCODER)
	cp $(BUILD_DIR)/rom_test.o $(BUILD_DIR)/rom_test_encrypted.o
	$(ELFCODER) $(ELFCODER_PARAM) -i $(BUILD_DIR)/rom_test_encrypted.o


# Main module function encoding
$(BUILD_DIR)/dsprot_main_encrypted.o: $(BUILD_DIR)/dsprot_main.o $(ELFCODER)
	cp $(BUILD_DIR)/dsprot_main.o $(BUILD_DIR)/dsprot_main_encrypted.o
	$(ELFCODER) $(ELFCODER_PARAM) -i $(BUILD_DIR)/dsprot_main_encrypted.o


-include $(DEPS)
