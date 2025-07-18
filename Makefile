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

# Depedency files
DEPS := $(wildcard $(BUILD_DIR)/*.d)

# Output library file
LIBRARY_NAME       :=  dsprot.a
LIBRARY_NAME_PKHG  :=  dsprot_pokeheartgold.a

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
	$(BUILD_DIR)/coretests_decrypter_decoder.o    \
	$(BUILD_DIR)/rc4_encoded.o                    \
	$(BUILD_DIR)/rc4_decoder.o

LIBRARY_FILES_PKHG := \
	$(BUILD_DIR)/dsprot_main_pokeheartgold_encrypted.o          \
	$(BUILD_DIR)/dsprot_main_pokeheartgold_decrypter_encoded.o  \
	$(BUILD_DIR)/dsprot_main_pokeheartgold_decrypter_decoder.o  \
	$(BUILD_DIR)/extra.o                                        \
	$(BUILD_DIR)/integrity_encrypted.o                          \
	$(BUILD_DIR)/integrity_decrypter_encoded.o                  \
	$(BUILD_DIR)/integrity_decrypter_decoder.o                  \
	$(BUILD_DIR)/encryptor_encoded.o                            \
	$(BUILD_DIR)/encryptor_decoder.o                            \
	$(BUILD_DIR)/mac_owner_encrypted.o                          \
	$(BUILD_DIR)/mac_owner_decrypter_encoded.o                  \
	$(BUILD_DIR)/rom_util_encrypted.o                           \
	$(BUILD_DIR)/rom_util_decrypter_encoded.o                   \
	$(BUILD_DIR)/rom_test_encrypted.o                           \
	$(BUILD_DIR)/rom_test_decrypter_encoded.o                   \
	$(BUILD_DIR)/coretests_decrypter_decoder.o                  \
	$(BUILD_DIR)/rc4_encoded.o                                  \
	$(BUILD_DIR)/rc4_decoder.o


.PHONY: all pokeheartgold-compatible clean tools dsprot dsprot-pokeheartgold
.DELETE_ON_ERROR : 

all:
	$(MAKE) tools
	$(MAKE) dsprot

pokeheartgold-compatible:
	$(MAKE) tools
	$(MAKE) dsprot-pokeheartgold

clean:
	$(MAKE) -C $(ELFCODER_DIR) clean
	$(MAKE) -C $(FIXDEP_DIR) clean
	$(RM) $(BUILD_DIR)/*

tools:
	$(MAKE) -C $(ELFCODER_DIR)
	$(MAKE) -C $(FIXDEP_DIR)

dsprot:
	$(MAKE) $(BUILD_DIR)/$(LIBRARY_NAME)

dsprot-pokeheartgold:
	$(MAKE) $(BUILD_DIR)/$(LIBRARY_NAME_PKHG)


# Library output
$(BUILD_DIR)/$(LIBRARY_NAME): $(LIBRARY_FILES)
	$(WINE) $(MWLDARM) -nostdlib -library $(LIBRARY_FILES) -o $(BUILD_DIR)/$(LIBRARY_NAME)


# Library output (pokeheartgold)
$(BUILD_DIR)/$(LIBRARY_NAME_PKHG): $(LIBRARY_FILES_PKHG)
	$(WINE) $(MWLDARM) -nostdlib -library $(LIBRARY_FILES_PKHG) -o $(BUILD_DIR)/$(LIBRARY_NAME_PKHG)


# Main module
$(BUILD_DIR)/dsprot_main_decrypter_decoder.o: $(BUILD_DIR)/dsprot_main_decrypter_decoder.s
	$(WINE) $(MWASMARM) $(ASM_PARAM) $(BUILD_DIR)/dsprot_main_decrypter_decoder.s -o $(BUILD_DIR)/dsprot_main_decrypter_decoder.o

$(BUILD_DIR)/dsprot_main_decrypter_encoded.o \
$(BUILD_DIR)/dsprot_main_decrypter_decoder.s: $(BUILD_DIR)/dsprot_main_decrypter.o $(ELFCODER)
	cp $(BUILD_DIR)/dsprot_main_decrypter.o $(BUILD_DIR)/dsprot_main_decrypter_encoded.o
	$(ELFCODER) -e -i $(BUILD_DIR)/dsprot_main_decrypter_encoded.o -o $(BUILD_DIR)/dsprot_main_decrypter_decoder.s -g Garbage -f \
		DSProt_DetectFlashcart     \
		DSProt_DetectNotFlashcart  \
		DSProt_DetectEmulator      \
		DSProt_DetectNotEmulator   \
		DSProt_DetectDummy         \
		DSProt_DetectNotDummy

$(BUILD_DIR)/dsprot_main_decrypter.o: $(BUILD_DIR)/dsprot_main_decrypter.s
	$(WINE) $(MWASMARM) $(ASM_PARAM) $(BUILD_DIR)/dsprot_main_decrypter.s -o $(BUILD_DIR)/dsprot_main_decrypter.o

$(BUILD_DIR)/dsprot_main_encrypted.o \
$(BUILD_DIR)/dsprot_main_decrypter.s: $(BUILD_DIR)/dsprot_main.o $(ELFCODER)
	cp $(BUILD_DIR)/dsprot_main.o $(BUILD_DIR)/dsprot_main_encrypted.o
	$(ELFCODER) -e -i $(BUILD_DIR)/dsprot_main_encrypted.o -o $(BUILD_DIR)/dsprot_main_decrypter.s -k 6ab2 -p DSProt_ -f \
		DetectFlashcart     \
		DetectNotFlashcart  \
		DetectEmulator      \
		DetectNotEmulator   \
		DetectDummy         \
		DetectNotDummy

$(BUILD_DIR)/dsprot_main.o: $(SRC_DIR)/dsprot_main.c
	$(WINE) $(MWCCARM) $(CC_PARAM) $(DEP_PARAM) $(SRC_DIR)/dsprot_main.c -o $(BUILD_DIR)/dsprot_main.o
	$(FIXDEP) $(BUILD_DIR)/dsprot_main.d


# Main module (pokeheartgold)
$(BUILD_DIR)/dsprot_main_pokeheartgold_decrypter_decoder.o: $(BUILD_DIR)/dsprot_main_pokeheartgold_decrypter_decoder.s
	$(WINE) $(MWASMARM) $(ASM_PARAM) $(BUILD_DIR)/dsprot_main_pokeheartgold_decrypter_decoder.s -o $(BUILD_DIR)/dsprot_main_pokeheartgold_decrypter_decoder.o

$(BUILD_DIR)/dsprot_main_pokeheartgold_decrypter_encoded.o \
$(BUILD_DIR)/dsprot_main_pokeheartgold_decrypter_decoder.s: $(BUILD_DIR)/dsprot_main_pokeheartgold_decrypter.o $(ELFCODER)
	cp $(BUILD_DIR)/dsprot_main_pokeheartgold_decrypter.o $(BUILD_DIR)/dsprot_main_pokeheartgold_decrypter_encoded.o
	$(ELFCODER) -e -i $(BUILD_DIR)/dsprot_main_pokeheartgold_decrypter_encoded.o -o $(BUILD_DIR)/dsprot_main_pokeheartgold_decrypter_decoder.s -g Garbage -f \
		ov123_0225F430  \
		ov123_0225F4A8  \
		ov123_0225F520  \
		ov123_0225F598  \
		ov123_0225F610  \
		ov123_0225F688

$(BUILD_DIR)/dsprot_main_pokeheartgold_decrypter.o: $(BUILD_DIR)/dsprot_main_pokeheartgold_decrypter.s
	$(WINE) $(MWASMARM) $(ASM_PARAM) $(BUILD_DIR)/dsprot_main_pokeheartgold_decrypter.s -o $(BUILD_DIR)/dsprot_main_pokeheartgold_decrypter.o

$(BUILD_DIR)/dsprot_main_pokeheartgold_encrypted.o \
$(BUILD_DIR)/dsprot_main_pokeheartgold_decrypter.s: $(BUILD_DIR)/dsprot_main_pokeheartgold.o $(ELFCODER)
	cp $(BUILD_DIR)/dsprot_main_pokeheartgold.o $(BUILD_DIR)/dsprot_main_pokeheartgold_encrypted.o
	$(ELFCODER) -e -i $(BUILD_DIR)/dsprot_main_pokeheartgold_encrypted.o -o $(BUILD_DIR)/dsprot_main_pokeheartgold_decrypter.s -k 6ab2 -p ov123 -f \
		_0225F430  \
		_0225F4A8  \
		_0225F520  \
		_0225F598  \
		_0225F610  \
		_0225F688

$(BUILD_DIR)/dsprot_main_pokeheartgold.o: $(SRC_DIR)/dsprot_main.c
	$(WINE) $(MWCCARM) $(CC_PARAM) $(DEP_PARAM) $(SRC_DIR)/dsprot_main.c -o $(BUILD_DIR)/dsprot_main_pokeheartgold.o -d POKEHEARTGOLD_COMPATABILITY
	$(FIXDEP) $(BUILD_DIR)/dsprot_main_pokeheartgold.d


# BSS + Garbage
$(BUILD_DIR)/extra.o: $(SRC_DIR)/extra.c
	$(WINE) $(MWCCARM) $(CC_PARAM) $(DEP_PARAM) $(SRC_DIR)/extra.c -o $(BUILD_DIR)/extra.o
	$(FIXDEP) $(BUILD_DIR)/extra.d


# Integrity module
$(BUILD_DIR)/integrity_decrypter_decoder.o: $(BUILD_DIR)/integrity_decrypter_decoder.s
	$(WINE) $(MWASMARM) $(ASM_PARAM) $(BUILD_DIR)/integrity_decrypter_decoder.s -o $(BUILD_DIR)/integrity_decrypter_decoder.o

$(BUILD_DIR)/integrity_decrypter_encoded.o \
$(BUILD_DIR)/integrity_decrypter_decoder.s: $(BUILD_DIR)/integrity_decrypter.o $(ELFCODER)
	cp $(BUILD_DIR)/integrity_decrypter.o $(BUILD_DIR)/integrity_decrypter_encoded.o
	$(ELFCODER) -e -i $(BUILD_DIR)/integrity_decrypter_encoded.o -o $(BUILD_DIR)/integrity_decrypter_decoder.s -f \
		RunEncrypted_Integrity_MACOwner_IsBad   \
		RunEncrypted_Integrity_MACOwner_IsGood  \
		RunEncrypted_Integrity_ROMTest_IsBad    \
		RunEncrypted_Integrity_ROMTest_IsGood

$(BUILD_DIR)/integrity_decrypter.o: $(BUILD_DIR)/integrity_decrypter.s
	$(WINE) $(MWASMARM) $(ASM_PARAM) $(BUILD_DIR)/integrity_decrypter.s -o $(BUILD_DIR)/integrity_decrypter.o

$(BUILD_DIR)/integrity_encrypted.o \
$(BUILD_DIR)/integrity_decrypter.s: $(BUILD_DIR)/integrity.o $(ELFCODER)
	cp $(BUILD_DIR)/integrity.o $(BUILD_DIR)/integrity_encrypted.o
	$(ELFCODER) -e -i $(BUILD_DIR)/integrity_encrypted.o -o $(BUILD_DIR)/integrity_decrypter.s -k 9785 -f \
		Integrity_MACOwner_IsBad   \
		Integrity_MACOwner_IsGood  \
		Integrity_ROMTest_IsBad    \
		Integrity_ROMTest_IsGood

$(BUILD_DIR)/integrity.o: $(SRC_DIR)/integrity.c
	$(WINE) $(MWCCARM) $(CC_PARAM) $(DEP_PARAM) $(SRC_DIR)/integrity.c -o $(BUILD_DIR)/integrity.o
	$(FIXDEP) $(BUILD_DIR)/integrity.d


# Encryptor module
$(BUILD_DIR)/encryptor_decoder.o: $(BUILD_DIR)/encryptor_decoder.s
	$(WINE) $(MWASMARM) $(ASM_PARAM) $(BUILD_DIR)/encryptor_decoder.s -o $(BUILD_DIR)/encryptor_decoder.o

$(BUILD_DIR)/encryptor_encoded.o \
$(BUILD_DIR)/encryptor_decoder.s: $(BUILD_DIR)/encryptor.o $(ELFCODER)
	cp $(BUILD_DIR)/encryptor.o $(BUILD_DIR)/encryptor_encoded.o
	$(ELFCODER) -e -i $(BUILD_DIR)/encryptor_encoded.o -o $(BUILD_DIR)/encryptor_decoder.s -f \
		Encryptor_EncryptFunction  \
		Encryptor_DecryptFunction

$(BUILD_DIR)/encryptor.o: $(SRC_DIR)/encryptor.c
	$(WINE) $(MWCCARM) $(CC_PARAM) $(DEP_PARAM) $(SRC_DIR)/encryptor.c -o $(BUILD_DIR)/encryptor.o
	$(FIXDEP) $(BUILD_DIR)/encryptor.d


# Core tests module: MAC/Owner, ROM utilities, ROM tests
$(BUILD_DIR)/coretests_decrypter_decoder.o: $(BUILD_DIR)/coretests_decrypter_decoder.s
	$(WINE) $(MWASMARM) $(ASM_PARAM) $(BUILD_DIR)/coretests_decrypter_decoder.s -o $(BUILD_DIR)/coretests_decrypter_decoder.o

$(BUILD_DIR)/mac_owner_decrypter_encoded.o \
$(BUILD_DIR)/rom_util_decrypter_encoded.o  \
$(BUILD_DIR)/rom_test_decrypter_encoded.o  \
$(BUILD_DIR)/coretests_decrypter_decoder.s: $(BUILD_DIR)/mac_owner_decrypter.o $(BUILD_DIR)/rom_util_decrypter.o $(BUILD_DIR)/rom_test_decrypter.o $(ELFCODER)
	cp $(BUILD_DIR)/mac_owner_decrypter.o $(BUILD_DIR)/mac_owner_decrypter_encoded.o
	cp $(BUILD_DIR)/rom_util_decrypter.o $(BUILD_DIR)/rom_util_decrypter_encoded.o
	cp $(BUILD_DIR)/rom_test_decrypter.o $(BUILD_DIR)/rom_test_decrypter_encoded.o
	$(ELFCODER) -e -i $(BUILD_DIR)/mac_owner_decrypter_encoded.o $(BUILD_DIR)/rom_util_decrypter_encoded.o $(BUILD_DIR)/rom_test_decrypter_encoded.o -o $(BUILD_DIR)/coretests_decrypter_decoder.s -f \
		RunEncrypted_ROMTest_IsBad    \
		RunEncrypted_ROMTest_IsGood   \
		RunEncrypted_MACOwner_IsBad   \
		RunEncrypted_MACOwner_IsGood  \
		RunEncrypted_ROMUtil_Read     \
		RunEncrypted_ROMUtil_CRC32

$(BUILD_DIR)/mac_owner_decrypter.o: $(BUILD_DIR)/mac_owner_decrypter.s
	$(WINE) $(MWASMARM) $(ASM_PARAM) $(BUILD_DIR)/mac_owner_decrypter.s -o $(BUILD_DIR)/mac_owner_decrypter.o

$(BUILD_DIR)/rom_util_decrypter.o: $(BUILD_DIR)/rom_util_decrypter.s
	$(WINE) $(MWASMARM) $(ASM_PARAM) $(BUILD_DIR)/rom_util_decrypter.s -o $(BUILD_DIR)/rom_util_decrypter.o

$(BUILD_DIR)/rom_test_decrypter.o: $(BUILD_DIR)/rom_test_decrypter.s
	$(WINE) $(MWASMARM) $(ASM_PARAM) $(BUILD_DIR)/rom_test_decrypter.s -o $(BUILD_DIR)/rom_test_decrypter.o

$(BUILD_DIR)/mac_owner_encrypted.o \
$(BUILD_DIR)/mac_owner_decrypter.s: $(BUILD_DIR)/mac_owner.o $(ELFCODER)
	cp $(BUILD_DIR)/mac_owner.o $(BUILD_DIR)/mac_owner_encrypted.o
	$(ELFCODER) -e -i $(BUILD_DIR)/mac_owner_encrypted.o -o $(BUILD_DIR)/mac_owner_decrypter.s -k 0982 -f \
		MACOwner_IsBad  \
		MACOwner_IsGood

$(BUILD_DIR)/rom_util_encrypted.o \
$(BUILD_DIR)/rom_util_decrypter.s: $(BUILD_DIR)/rom_util.o $(ELFCODER)
	cp $(BUILD_DIR)/rom_util.o $(BUILD_DIR)/rom_util_encrypted.o
	$(ELFCODER) -e -i $(BUILD_DIR)/rom_util_encrypted.o -o $(BUILD_DIR)/rom_util_decrypter.s -k 0982 -f \
		ROMUtil_Read   \
		ROMUtil_CRC32

$(BUILD_DIR)/rom_test_encrypted.o \
$(BUILD_DIR)/rom_test_decrypter.s: $(BUILD_DIR)/rom_test.o $(ELFCODER)
	cp $(BUILD_DIR)/rom_test.o $(BUILD_DIR)/rom_test_encrypted.o
	$(ELFCODER) -e -i $(BUILD_DIR)/rom_test_encrypted.o -o $(BUILD_DIR)/rom_test_decrypter.s -k 0982 -f \
		ROMTest_IsBad   \
		ROMTest_IsGood

$(BUILD_DIR)/mac_owner.o: $(SRC_DIR)/mac_owner.c
	$(WINE) $(MWCCARM) $(CC_PARAM) $(DEP_PARAM) $(SRC_DIR)/mac_owner.c -o $(BUILD_DIR)/mac_owner.o
	$(FIXDEP) $(BUILD_DIR)/mac_owner.d

$(BUILD_DIR)/rom_util.o: $(SRC_DIR)/rom_util.c
	$(WINE) $(MWCCARM) $(CC_PARAM) $(DEP_PARAM) $(SRC_DIR)/rom_util.c -o $(BUILD_DIR)/rom_util.o
	$(FIXDEP) $(BUILD_DIR)/rom_util.d

$(BUILD_DIR)/rom_test.o: $(SRC_DIR)/rom_test.c
	$(WINE) $(MWCCARM) $(CC_PARAM) $(DEP_PARAM) $(SRC_DIR)/rom_test.c -o $(BUILD_DIR)/rom_test.o
	$(FIXDEP) $(BUILD_DIR)/rom_test.d


# RC4 module
$(BUILD_DIR)/rc4_decoder.o: $(BUILD_DIR)/rc4_decoder.s
	$(WINE) $(MWASMARM) $(ASM_PARAM) $(BUILD_DIR)/rc4_decoder.s -o $(BUILD_DIR)/rc4_decoder.o

$(BUILD_DIR)/rc4_encoded.o \
$(BUILD_DIR)/rc4_decoder.s: $(BUILD_DIR)/rc4.o $(ELFCODER)
	cp $(BUILD_DIR)/rc4.o $(BUILD_DIR)/rc4_encoded.o
	$(ELFCODER) -e -i $(BUILD_DIR)/rc4_encoded.o -o $(BUILD_DIR)/rc4_decoder.s -f \
		RC4_Init                        \
		RC4_Byte                        \
		RC4_InitSBox                    \
		RC4_EncryptInstructions         \
		RC4_DecryptInstructions         \
		RC4_InitAndEncryptInstructions  \
		RC4_InitAndDecryptInstructions

$(BUILD_DIR)/rc4.o: $(SRC_DIR)/rc4.c
	$(WINE) $(MWCCARM) $(CC_PARAM) $(DEP_PARAM) $(SRC_DIR)/rc4.c -o $(BUILD_DIR)/rc4.o
	$(FIXDEP) $(BUILD_DIR)/rc4.d


-include $(DEPS)
