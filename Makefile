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
MWCCARM_DIR   ?=  $(TOOL_DIR)/mwccarm

MW_VER := dsi/1.2p2

# Tools
MWCCARM   :=  $(MWCCARM_DIR)/$(MW_VER)/mwccarm.exe
MWASMARM  :=  $(MWCCARM_DIR)/$(MW_VER)/mwasmarm.exe
MWLDARM   :=  $(MWCCARM_DIR)/$(MW_VER)/mwldarm.exe
ELFCODER  :=  $(ELFCODER_DIR)/build/elfcoder$(EXE)
FIXDEP    :=  $(FIXDEP_DIR)/build/fixdep$(EXE)

# C / ASM compilation parameters
CC_PARAM   :=  -O4,p -enum int -proc arm946E -gccext,on -fp soft -lang c99 -char signed -inline on,noauto -Cpp_exceptions off -ipa file -interworking -c -i $(INC_DIR)
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
	$(BUILD_DIR)/integrity_encrypted.o            \
	$(BUILD_DIR)/integrity_decrypter_encoded.o    \
	$(BUILD_DIR)/integrity_decrypter_decoder.o    \
	$(BUILD_DIR)/rc4_encoded.o                    \
	$(BUILD_DIR)/rc4_decoder.o                    \
	$(BUILD_DIR)/dsprot_main_encrypted.o          \
	$(BUILD_DIR)/dsprot_main_decrypter_encoded.o  \
	$(BUILD_DIR)/dsprot_main_decrypter_decoder.o  \
	$(BUILD_DIR)/callback.o                       \
	$(BUILD_DIR)/extra.o                          \
	$(BUILD_DIR)/encryptor_encoded.o              \
	$(BUILD_DIR)/encryptor_decoder.o              \
	$(BUILD_DIR)/mac_owner_encrypted.o            \
	$(BUILD_DIR)/rom_util_encoded.o               \
	$(BUILD_DIR)/rom_test_encrypted.o             \
	$(BUILD_DIR)/rom_test_decrypter_encoded.o     \
	$(BUILD_DIR)/mac_owner_decrypter_encoded.o    \
	$(BUILD_DIR)/coretests_decoder.o

# Encryption keys
KEY_DSPROT_MAIN := 170B4
KEY_INTEGRITY   := EC46
KEY_MAC_OWNER   := 10E4A
KEY_ROM_TEST    := 110DA


.PHONY: all clean tools dsprot install
.DELETE_ON_ERROR: 
.NOTPARALLEL: 

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
	$(MAKE) $(LIBRARY)

ifeq ($(INSTALL_DIR),)
install:
	$(error Nowhere to install. Specify INSTALL_DIR)
else
install:
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


# Integrity module function encoding
$(BUILD_DIR)/integrity_decrypter_encoded.o \
$(BUILD_DIR)/integrity_decrypter_decoder.s: $(BUILD_DIR)/integrity_decrypter.o $(ELFCODER)
	cp $(BUILD_DIR)/integrity_decrypter.o $(BUILD_DIR)/integrity_decrypter_encoded.o
	$(ELFCODER) -e -i $(BUILD_DIR)/integrity_decrypter_encoded.o -o $(BUILD_DIR)/integrity_decrypter_decoder.s -n Integrity_DecodeFunctions -f \
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


# RC4 module function encoding
$(BUILD_DIR)/rc4_encoded.o \
$(BUILD_DIR)/rc4_decoder.s: $(BUILD_DIR)/rc4.o $(ELFCODER)
	cp $(BUILD_DIR)/rc4.o $(BUILD_DIR)/rc4_encoded.o
	$(ELFCODER) -e -i $(BUILD_DIR)/rc4_encoded.o -o $(BUILD_DIR)/rc4_decoder.s -n RC4_DecodeFunctions -f \
		RC4_Init                        \
		RC4_EncryptInstructions         \
		RC4_DecryptInstructions         \
		RC4_InitAndEncryptInstructions  \
		RC4_InitAndDecryptInstructions  \
		RC4_Byte


# Main module function encoding
$(BUILD_DIR)/dsprot_main_decrypter_encoded.o \
$(BUILD_DIR)/dsprot_main_decrypter_decoder.s: $(BUILD_DIR)/dsprot_main_decrypter.o $(ELFCODER)
	cp $(BUILD_DIR)/dsprot_main_decrypter.o $(BUILD_DIR)/dsprot_main_decrypter_encoded.o
	$(ELFCODER) -e -i $(BUILD_DIR)/dsprot_main_decrypter_encoded.o -o $(BUILD_DIR)/dsprot_main_decrypter_decoder.s -g Garbage -n DSProt_DecodeFunctions -f \
		DSProt_DetectFlashcartA  \
		DSProt_DetectEmulatorA   \
		DSProt_DetectFlashcartB  \
		DSProt_DetectEmulatorB   \
	-P \
		CoreTests_DecodeFunctions  \
		Encryptor_DecodeFunctions  \
		Integrity_DecodeFunctions  \
		RC4_DecodeFunctions

$(BUILD_DIR)/dsprot_main_encrypted.o \
$(BUILD_DIR)/dsprot_main_decrypter.s: $(BUILD_DIR)/dsprot_main.o $(ELFCODER)
	cp $(BUILD_DIR)/dsprot_main.o $(BUILD_DIR)/dsprot_main_encrypted.o
	$(ELFCODER) -e -i $(BUILD_DIR)/dsprot_main_encrypted.o -o $(BUILD_DIR)/dsprot_main_decrypter.s -k $(KEY_DSPROT_MAIN) -p DSProt_ -f \
		DetectFlashcartA  \
		DetectEmulatorA   \
		DetectFlashcartB  \
		DetectEmulatorB


# Encryptor module function encoding
$(BUILD_DIR)/encryptor_encoded.o \
$(BUILD_DIR)/encryptor_decoder.s: $(BUILD_DIR)/encryptor.o $(ELFCODER)
	cp $(BUILD_DIR)/encryptor.o $(BUILD_DIR)/encryptor_encoded.o
	$(ELFCODER) -e -i $(BUILD_DIR)/encryptor_encoded.o -o $(BUILD_DIR)/encryptor_decoder.s -n Encryptor_DecodeFunctions -f \
		Encryptor_EncryptFunction            \
		Encryptor_DecryptFunction            \
		Encryptor_DecryptionWrapperFragment


# Core tests module: MAC/Owner, ROM utilities, ROM tests function encoding
$(BUILD_DIR)/mac_owner_decrypter_encoded.o \
$(BUILD_DIR)/rom_test_decrypter_encoded.o  \
$(BUILD_DIR)/rom_util_encoded.o            \
$(BUILD_DIR)/coretests_decoder.s: $(BUILD_DIR)/mac_owner_decrypter.o $(BUILD_DIR)/rom_util.o $(BUILD_DIR)/rom_test_decrypter.o $(ELFCODER)
	cp $(BUILD_DIR)/mac_owner_decrypter.o $(BUILD_DIR)/mac_owner_decrypter_encoded.o
	cp $(BUILD_DIR)/rom_test_decrypter.o $(BUILD_DIR)/rom_test_decrypter_encoded.o
	cp $(BUILD_DIR)/rom_util.o $(BUILD_DIR)/rom_util_encoded.o
	$(ELFCODER) -e -i $(BUILD_DIR)/mac_owner_decrypter_encoded.o $(BUILD_DIR)/rom_util_encoded.o $(BUILD_DIR)/rom_test_decrypter_encoded.o -o $(BUILD_DIR)/coretests_decoder.s -n CoreTests_DecodeFunctions -f \
		RunEncrypted_ROMTest_IsBad    \
		RunEncrypted_ROMTest_IsGood   \
		RunEncrypted_MACOwner_IsBad   \
		RunEncrypted_MACOwner_IsGood  \
		ROMUtil_CRC32

$(BUILD_DIR)/mac_owner_encrypted.o \
$(BUILD_DIR)/mac_owner_decrypter.s: $(BUILD_DIR)/mac_owner.o $(ELFCODER)
	cp $(BUILD_DIR)/mac_owner.o $(BUILD_DIR)/mac_owner_encrypted.o
	$(ELFCODER) -e -i $(BUILD_DIR)/mac_owner_encrypted.o -o $(BUILD_DIR)/mac_owner_decrypter.s -k $(KEY_MAC_OWNER) -f \
		MACOwner_IsBad   \
		MACOwner_IsGood

$(BUILD_DIR)/rom_test_encrypted.o \
$(BUILD_DIR)/rom_test_decrypter.s: $(BUILD_DIR)/rom_test.o $(ELFCODER)
	cp $(BUILD_DIR)/rom_test.o $(BUILD_DIR)/rom_test_encrypted.o
	$(ELFCODER) -e -i $(BUILD_DIR)/rom_test_encrypted.o -o $(BUILD_DIR)/rom_test_decrypter.s -k $(KEY_ROM_TEST) -f \
		ROMTest_IsBad   \
		ROMTest_IsGood


-include $(DEPS)
