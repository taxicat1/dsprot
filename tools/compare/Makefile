ifneq ($(OS),Windows_NT)
	WINE := wine
endif

BUILD_DIR := ./build

$(shell mkdir -p $(BUILD_DIR))

MWCCARM_DIR  ?=  ../mwccarm
MW_VER       ?=  2.0/sp2p2

MWCCARM  :=  $(MWCCARM_DIR)/$(MW_VER)/mwccarm.exe
MWLDARM  :=  $(MWCCARM_DIR)/$(MW_VER)/mwldarm.exe

ENV_SRC  :=  ./env.c
ENV_OBJ  :=  $(BUILD_DIR)/env.o

CC_PARAM := -proc arm946E -c

LD_PARAM      :=  -proc arm946e -nodead -nostdlib
COMPARE_LCF   :=  ./compare.lcf
LINKED_ELF    :=  $(BUILD_DIR)/compare_link.elf
COMPARE_SBIN  :=  $(BUILD_DIR)/dsprot_instant.sbin

SHA1SUM          :=  sha1sum
SHA1SUM_COMPARE  :=  ./compare.sha1

.PHONY: all clean

all:
	$(MAKE) $(COMPARE_SBIN)
	$(SHA1SUM) -c $(SHA1SUM_COMPARE)

clean:
	$(RM) -r $(BUILD_DIR)

$(COMPARE_SBIN): $(LIBRARY) $(ENV_OBJ)
ifeq ($(LIBRARY),)
	$(error No dsprot.a provided. Specify LIBRARY)
endif
	$(WINE) $(MWLDARM) $(LD_PARAM) $(COMPARE_LCF) $^ -o $(LINKED_ELF)

$(ENV_OBJ): $(ENV_SRC)
	$(WINE) $(MWCCARM) $(CC_PARAM) $< -o $@
