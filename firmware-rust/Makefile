MSPM0_SDK_INSTALL_DIR ?= $(abspath ../../../../../..)

include $(MSPM0_SDK_INSTALL_DIR)/tools/imports_mak/imports.mak.linux

CC = "$(TICLANG_ARMCOMPILER)/bin/tiarmclang"
LNK = "$(TICLANG_ARMCOMPILER)/bin/tiarmclang"
OBJCOPY = "$(TICLANG_ARMCOMPILER)/bin/tiarmobjcopy"
BUILDDIR ?= /tmp/build
LINKERFILE = "../firmware/firmware.ld"

NAME = hsm

RUST_TARGET = thumbv6m-none-eabi
RUST_PROFILE = release
RUST_LIB = target/$(RUST_TARGET)/$(RUST_PROFILE)/libhsm_rust.a

CSRC = \
    ../firmware/src/startup_mspm0l222x_ticlang.c \
    ../firmware/src/ti_msp_dl_config.c \
    ../firmware/src/simple_flash.c \
    ../firmware/src/filesystem.c \
    ../firmware/src/security.c

COBJS = \
    $(BUILDDIR)/startup_mspm0l222x_ticlang.o \
    $(BUILDDIR)/ti_msp_dl_config.o \
    $(BUILDDIR)/simple_flash.o \
    $(BUILDDIR)/filesystem.o \
    $(BUILDDIR)/security.o

CFLAGS += -I../firmware \
    -I../firmware/inc \
    -D__MSPM0L2228__ \
    -O2 \
    "-I$(MSPM0_SDK_INSTALL_DIR)/source/third_party/CMSIS/Core/Include" \
    "-I$(MSPM0_SDK_INSTALL_DIR)/source" \
    -gdwarf-3 \
    -mcpu=cortex-m0plus \
    -march=thumbv6m \
    -mfloat-abi=soft \
    -mthumb

LFLAGS += "-l$(MSPM0_SDK_INSTALL_DIR)/source/ti/drivers/lib/ticlang/m0p/drivers_mspm0l122x_l222x.a" \
    "-l$(MSPM0_SDK_INSTALL_DIR)/kernel/nortos/lib/ticlang/m0p/nortos_mspm0l122x_l222x.a" \
    "-l$(MSPM0_SDK_INSTALL_DIR)/source/ti/driverlib/lib/ticlang/m0p/mspm0l122x_l222x/driverlib.a" \
    "-L$(MSPM0_SDK_INSTALL_DIR)/source" \
    ./$(LINKERFILE) \
    "-Wl,-m,$(BUILDDIR)/$(NAME).map" \
    -Wl,--rom_model \
    -Wl,--warn_sections \
    "-L$(TICLANG_ARMCOMPILER)/lib" \
    -llibc.a

all: $(BUILDDIR) $(RUST_LIB) $(COBJS) $(BUILDDIR)/$(NAME).elf $(BUILDDIR)/$(NAME).bin

$(BUILDDIR):
	@ mkdir -p $(BUILDDIR)

$(RUST_LIB):
	cargo build --target $(RUST_TARGET) --$(RUST_PROFILE)

$(BUILDDIR)/startup_mspm0l222x_ticlang.o: ../firmware/src/startup_mspm0l222x_ticlang.c | $(BUILDDIR)
	@ $(CC) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/ti_msp_dl_config.o: ../firmware/src/ti_msp_dl_config.c | $(BUILDDIR)
	@ $(CC) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/simple_flash.o: ../firmware/src/simple_flash.c | $(BUILDDIR)
	@ $(CC) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/filesystem.o: ../firmware/src/filesystem.c | $(BUILDDIR)
	@ $(CC) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/security.o: ../firmware/src/security.c | $(BUILDDIR)
	@ $(CC) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/$(NAME).elf: $(COBJS) $(RUST_LIB)
	@ $(LNK) -Wl,-u,_c_int00 $(COBJS) $(RUST_LIB) $(LFLAGS) -o $(BUILDDIR)/$(NAME).elf

$(BUILDDIR)/$(NAME).bin: $(BUILDDIR)/$(NAME).elf
	@ $(OBJCOPY) -O binary $(BUILDDIR)/$(NAME).elf $(BUILDDIR)/$(NAME).bin

clean:
	@ $(RM) -r $(BUILDDIR) > $(DEVNULL) 2>&1
	cargo clean
