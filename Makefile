# ===================================================================
# See doc/BUILD_OVERVIEW.TXT for a clearer outline of this build process
# ===================================================================

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
COMPARE_DIR   :=  $(TOOL_DIR)/compare
MWCCARM_DIR   ?=  $(TOOL_DIR)/mwccarm

MW_VER := dsi/1.2

# Tools
MWCCARM   :=  $(MWCCARM_DIR)/$(MW_VER)/mwccarm.exe
MWASMARM  :=  $(MWCCARM_DIR)/$(MW_VER)/mwasmarm.exe
MWLDARM   :=  $(MWCCARM_DIR)/$(MW_VER)/mwldarm.exe
ELFCODER  :=  $(ELFCODER_DIR)/build/elfcoder$(EXE)
FIXDEP    :=  $(FIXDEP_DIR)/build/fixdep$(EXE)

# C / ASM compilation parameters
CC_PARAM   :=  -O4,p -enum int -proc arm946E -gccext,on -fp soft -lang c99 -char signed -inline on,noauto -Cpp_exceptions off -interworking -c -i $(INC_DIR)
ASM_PARAM  :=  -proc arm5TE -i $(INC_DIR)
LIB_PARAM  :=  -nostdlib -library
DEP_PARAM  :=  -gccdep -MD

CC_PARAM   +=  -W all -W pedantic -W noimpl_signedunsigned -W noimplicitconv -W nounusedarg -W nomissingreturn -W error

# Depedency files
DEPS := $(wildcard $(BUILD_DIR)/*.d)

# Output library file
LIBRARY_NAME  :=  dsprot.a
LIBRARY       :=  $(BUILD_DIR)/$(LIBRARY_NAME)

# Files (in this specific order) that will go into the library
LIBRARY_FILES := \
	$(BUILD_DIR)/dsprot_main_encrypted.o          \
	$(BUILD_DIR)/dsprot_main_decrypter_encoded.o  \
	$(BUILD_DIR)/dsprot_main_decrypter_decoder.o  \
	$(BUILD_DIR)/extra.o                          \
	$(BUILD_DIR)/integrity_encrypted.o            \
	$(BUILD_DIR)/integrity_decrypter_encoded.o    \
	$(BUILD_DIR)/integrity_decrypter_decoder.o    \
	$(BUILD_DIR)/encryptor_encoded.o              \
	$(BUILD_DIR)/encryptor_decoder.o              \
	$(BUILD_DIR)/mac_owner_encrypted.o            \
	$(BUILD_DIR)/mac_owner_decrypter_encoded.o    \
	$(BUILD_DIR)/rom_util_encrypted.o             \
	$(BUILD_DIR)/rom_util_decrypter_encoded.o     \
	$(BUILD_DIR)/rom_test_encrypted.o             \
	$(BUILD_DIR)/rom_test_decrypter_encoded.o     \
	$(BUILD_DIR)/dummy_encrypted.o                \
	$(BUILD_DIR)/dummy_decrypter_encoded.o        \
	$(BUILD_DIR)/coretests_decrypter_decoder.o    \
	$(BUILD_DIR)/rc4_encoded.o                    \
	$(BUILD_DIR)/rc4_decoder.o

# Encryption keys
KEY_DSPROT_MAIN := 50B7
KEY_INTEGRITY   := 0BCB
KEY_CORE_TESTS  := C826


.PHONY: all compare clean tools dsprot install
.DELETE_ON_ERROR: 
.NOTPARALLEL: 

all:
	$(MAKE) tools
	$(MAKE) dsprot

compare:
	$(MAKE) all COMPARE=1

clean:
	$(MAKE) -C $(ELFCODER_DIR) clean
	$(MAKE) -C $(FIXDEP_DIR) clean
	$(MAKE) -C $(COMPARE_DIR) clean
	$(RM) -r $(BUILD_DIR)

tools:
	$(MAKE) -C $(ELFCODER_DIR)
	$(MAKE) -C $(FIXDEP_DIR)

dsprot:
	$(MAKE) $(LIBRARY)
ifneq ($(COMPARE),)
	$(MAKE) -C $(COMPARE_DIR) MWCCARM_DIR=$(abspath $(MWCCARM_DIR)) MW_VER=$(MW_VER) LIBRARY=$(abspath $(LIBRARY))
endif

install:
ifeq ($(INSTALL_DIR),)
	$(error Nowhere to install. Specify INSTALL_DIR)
else
	$(MAKE) all
	$(shell mkdir -p $(INSTALL_DIR)/lib/)
	cp $(LIBRARY) $(INSTALL_DIR)/lib/
endif


# Assembly assembling
$(BUILD_DIR)/%.o: $(BUILD_DIR)/%.s
	$(WINE) $(MWASMARM) $(ASM_PARAM) $< -o $@


# C compilation
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(WINE) $(MWCCARM) $(CC_PARAM) $(DEP_PARAM) $< -o $@
	$(FIXDEP) $(@:.o=.d)


# Library output
$(LIBRARY): $(LIBRARY_FILES)
	$(WINE) $(MWLDARM) $(LIB_PARAM) $^ -o $@


# Main module function encoding
$(BUILD_DIR)/dsprot_main_decrypter_encoded.o \
$(BUILD_DIR)/dsprot_main_decrypter_decoder.s: $(BUILD_DIR)/dsprot_main_decrypter.o $(ELFCODER)
	cp $(BUILD_DIR)/dsprot_main_decrypter.o $(BUILD_DIR)/dsprot_main_decrypter_encoded.o
	$(ELFCODER) -e -i $(BUILD_DIR)/dsprot_main_decrypter_encoded.o -o $(BUILD_DIR)/dsprot_main_decrypter_decoder.s -g Garbage -f \
		__DSProt_DetectFlashcart     \
		__DSProt_DetectNotFlashcart  \
		__DSProt_DetectEmulator      \
		__DSProt_DetectNotEmulator   \
		__DSProt_DetectDummy         \
		__DSProt_DetectNotDummy

$(BUILD_DIR)/dsprot_main_encrypted.o \
$(BUILD_DIR)/dsprot_main_decrypter.s: $(BUILD_DIR)/dsprot_main.o $(ELFCODER)
	cp $(BUILD_DIR)/dsprot_main.o $(BUILD_DIR)/dsprot_main_encrypted.o
	$(ELFCODER) -e -i $(BUILD_DIR)/dsprot_main_encrypted.o -o $(BUILD_DIR)/dsprot_main_decrypter.s -k $(KEY_DSPROT_MAIN) -p __DSProt_ -f \
		DetectFlashcart     \
		DetectNotFlashcart  \
		DetectEmulator      \
		DetectNotEmulator   \
		DetectDummy         \
		DetectNotDummy


# Integrity module function encoding
$(BUILD_DIR)/integrity_decrypter_encoded.o \
$(BUILD_DIR)/integrity_decrypter_decoder.s: $(BUILD_DIR)/integrity_decrypter.o $(ELFCODER)
	cp $(BUILD_DIR)/integrity_decrypter.o $(BUILD_DIR)/integrity_decrypter_encoded.o
	$(ELFCODER) -e -i $(BUILD_DIR)/integrity_decrypter_encoded.o -o $(BUILD_DIR)/integrity_decrypter_decoder.s -f \
		RunEncrypted_Integrity_MACOwner_IsBad   \
		RunEncrypted_Integrity_MACOwner_IsGood  \
		RunEncrypted_Integrity_ROMTest_IsBad    \
		RunEncrypted_Integrity_ROMTest_IsGood

$(BUILD_DIR)/integrity_encrypted.o \
$(BUILD_DIR)/integrity_decrypter.s: $(BUILD_DIR)/integrity.o $(ELFCODER)
	cp $(BUILD_DIR)/integrity.o $(BUILD_DIR)/integrity_encrypted.o
	$(ELFCODER) -e -i $(BUILD_DIR)/integrity_encrypted.o -o $(BUILD_DIR)/integrity_decrypter.s -k $(KEY_INTEGRITY) -f \
		Integrity_MACOwner_IsBad   \
		Integrity_MACOwner_IsGood  \
		Integrity_ROMTest_IsBad    \
		Integrity_ROMTest_IsGood


# Encryptor module function encoding
$(BUILD_DIR)/encryptor_encoded.o \
$(BUILD_DIR)/encryptor_decoder.s: $(BUILD_DIR)/encryptor.o $(ELFCODER)
	cp $(BUILD_DIR)/encryptor.o $(BUILD_DIR)/encryptor_encoded.o
	$(ELFCODER) -e -i $(BUILD_DIR)/encryptor_encoded.o -o $(BUILD_DIR)/encryptor_decoder.s -f \
		Encryptor_EncryptFunction  \
		Encryptor_DecryptFunction


# Core tests module: MAC/Owner, ROM utilities, ROM tests, dummy function encoding
$(BUILD_DIR)/mac_owner_decrypter_encoded.o \
$(BUILD_DIR)/rom_util_decrypter_encoded.o  \
$(BUILD_DIR)/rom_test_decrypter_encoded.o  \
$(BUILD_DIR)/dummy_decrypter_encoded.o     \
$(BUILD_DIR)/coretests_decrypter_decoder.s: $(BUILD_DIR)/mac_owner_decrypter.o $(BUILD_DIR)/rom_util_decrypter.o $(BUILD_DIR)/rom_test_decrypter.o $(BUILD_DIR)/dummy_decrypter.o $(ELFCODER)
	cp $(BUILD_DIR)/mac_owner_decrypter.o $(BUILD_DIR)/mac_owner_decrypter_encoded.o
	cp $(BUILD_DIR)/rom_util_decrypter.o $(BUILD_DIR)/rom_util_decrypter_encoded.o
	cp $(BUILD_DIR)/rom_test_decrypter.o $(BUILD_DIR)/rom_test_decrypter_encoded.o
	cp $(BUILD_DIR)/dummy_decrypter.o $(BUILD_DIR)/dummy_decrypter_encoded.o
	$(ELFCODER) -e -i $(BUILD_DIR)/mac_owner_decrypter_encoded.o $(BUILD_DIR)/rom_util_decrypter_encoded.o $(BUILD_DIR)/rom_test_decrypter_encoded.o $(BUILD_DIR)/dummy_decrypter_encoded.o -o $(BUILD_DIR)/coretests_decrypter_decoder.s -f \
		RunEncrypted_ROMTest_IsBad    \
		RunEncrypted_ROMTest_IsGood   \
		RunEncrypted_MACOwner_IsBad   \
		RunEncrypted_MACOwner_IsGood  \
		RunEncrypted_ROMUtil_Read     \
		RunEncrypted_ROMUtil_CRC32    \
		RunEncrypted_Dummy_IsBad      \
		RunEncrypted_Dummy_IsGood

$(BUILD_DIR)/mac_owner_encrypted.o \
$(BUILD_DIR)/mac_owner_decrypter.s: $(BUILD_DIR)/mac_owner.o $(ELFCODER)
	cp $(BUILD_DIR)/mac_owner.o $(BUILD_DIR)/mac_owner_encrypted.o
	$(ELFCODER) -e -i $(BUILD_DIR)/mac_owner_encrypted.o -o $(BUILD_DIR)/mac_owner_decrypter.s -k $(KEY_CORE_TESTS) -f \
		MACOwner_IsBad   \
		MACOwner_IsGood

$(BUILD_DIR)/rom_util_encrypted.o \
$(BUILD_DIR)/rom_util_decrypter.s: $(BUILD_DIR)/rom_util.o $(ELFCODER)
	cp $(BUILD_DIR)/rom_util.o $(BUILD_DIR)/rom_util_encrypted.o
	$(ELFCODER) -e -i $(BUILD_DIR)/rom_util_encrypted.o -o $(BUILD_DIR)/rom_util_decrypter.s -k $(KEY_CORE_TESTS) -f \
		ROMUtil_Read   \
		ROMUtil_CRC32

$(BUILD_DIR)/rom_test_encrypted.o \
$(BUILD_DIR)/rom_test_decrypter.s: $(BUILD_DIR)/rom_test.o $(ELFCODER)
	cp $(BUILD_DIR)/rom_test.o $(BUILD_DIR)/rom_test_encrypted.o
	$(ELFCODER) -e -i $(BUILD_DIR)/rom_test_encrypted.o -o $(BUILD_DIR)/rom_test_decrypter.s -k $(KEY_CORE_TESTS) -f \
		ROMTest_IsBad   \
		ROMTest_IsGood

$(BUILD_DIR)/dummy_encrypted.o \
$(BUILD_DIR)/dummy_decrypter.s: $(BUILD_DIR)/dummy.o $(ELFCODER)
	cp $(BUILD_DIR)/dummy.o $(BUILD_DIR)/dummy_encrypted.o
	$(ELFCODER) -e -i $(BUILD_DIR)/dummy_encrypted.o -o $(BUILD_DIR)/dummy_decrypter.s -k $(KEY_CORE_TESTS) -f \
		Dummy_IsBad   \
		Dummy_IsGood


# RC4 module function encoding
$(BUILD_DIR)/rc4_encoded.o \
$(BUILD_DIR)/rc4_decoder.s: $(BUILD_DIR)/rc4.o $(ELFCODER)
	cp $(BUILD_DIR)/rc4.o $(BUILD_DIR)/rc4_encoded.o
	$(ELFCODER) -e -i $(BUILD_DIR)/rc4_encoded.o -o $(BUILD_DIR)/rc4_decoder.s -f \
		RC4_Init                        \
		RC4_InitSBox                    \
		RC4_EncryptInstructions         \
		RC4_DecryptInstructions         \
		RC4_InitAndEncryptInstructions  \
		RC4_InitAndDecryptInstructions  \
		RC4_Byte


-include $(DEPS)
