DEVNULL = /dev/null

MSPM0_SDK_INSTALL_DIR ?= $(abspath ../../../../../..)


CC = "$(TICLANG_ARMCOMPILER)/bin/tiarmclang"
LNK = "$(TICLANG_ARMCOMPILER)/bin/tiarmclang"
OBJCOPY = "$(TICLANG_ARMCOMPILER)/bin/tiarmobjcopy"
BUILDDIR ?= /tmp/build
VPATH = "src"
LINKERFILE = "firmware.ld"

# Path containing a cross-compiled libsodium install
# Expected layout: $(SODIUM_PREFIX)/include/sodium.h and $(SODIUM_PREFIX)/lib/libsodium.a
SODIUM_PREFIX ?= /opt/libsodium

OBJECTS = $(BUILDDIR)/HSM.so \
    $(BUILDDIR)/simple_uart.so \
    $(BUILDDIR)/ti_msp_dl_config.so \
    $(BUILDDIR)/startup_mspm0l222x_ticlang.so \
    $(BUILDDIR)/simple_flash.so \
    $(BUILDDIR)/host_messaging.so \
    $(BUILDDIR)/security.so \
    $(BUILDDIR)/crypto.so \
    $(BUILDDIR)/filesystem.so \
    $(BUILDDIR)/commands.so

# OBJECTS += $(BUILDDIR)/simple_crypto.so

# Crypto flags for libsodium variant
CFLAGS += -DCRYPTO_EXAMPLE=1
CFLAGS += -I$(SODIUM_PREFIX)/include
CFLAGS += -I./inc

NAME = hsm

CFLAGS += -I.. \
    -D__MSPM0L2228__ \
    -O2 \
    "-I$(MSPM0_SDK_INSTALL_DIR)/source/third_party/CMSIS/Core/Include" \
    "-I$(MSPM0_SDK_INSTALL_DIR)/source" \
	"-I./inc" \
    -gdwarf-3 \
    -mcpu=cortex-m0plus \
    -march=thumbv6m \
    -mfloat-abi=soft \
    -mthumb

LFLAGS += "-l$(MSPM0_SDK_INSTALL_DIR)/source/ti/drivers/lib/ticlang/m0p/drivers_mspm0l122x_l222x.a" \
    "-l$(MSPM0_SDK_INSTALL_DIR)/kernel/nortos/lib/ticlang/m0p/nortos_mspm0l122x_l222x.a" \
    "-l$(MSPM0_SDK_INSTALL_DIR)/source/ti/driverlib/lib/ticlang/m0p/mspm0l122x_l222x/driverlib.a" \
    "-L$(MSPM0_SDK_INSTALL_DIR)/source" \
    -L.. \
    ./$(LINKERFILE) \
    "-Wl,-m,$(BUILDDIR)/$(NAME).map" \
    -Wl,--rom_model \
    -Wl,--warn_sections \
    "-L$(TICLANG_ARMCOMPILER)/lib" \
    "-L$(SODIUM_PREFIX)/lib" \
    -lsodium \
    -llibc.a

all: $(BUILDDIR)/$(NAME).elf $(BUILDDIR)/$(NAME).bin

$(BUILDDIR):
	@ mkdir -p $(BUILDDIR)

$(BUILDDIR)/%.so: ./src/%.c | $(BUILDDIR)
	@ echo Building $@
	@ $(CC) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/$(NAME).elf: $(OBJECTS)
	@ echo linking $@
	@ $(LNK) -Wl,-u,_c_int00 $(OBJECTS)  $(LFLAGS) -o $(BUILDDIR)/$(NAME).elf

$(BUILDDIR)/$(NAME).bin: $(BUILDDIR)/$(NAME).elf
	@ $(OBJCOPY) -O binary $(BUILDDIR)/$(NAME).elf $(BUILDDIR)/$(NAME).bin

clean:
	@ echo Cleaning...
	@ $(RM) $(OBJECTS) > $(DEVNULL) 2>&1
	@ $(RM) $(NAME).elf > $(DEVNULL) 2>&1
	@ $(RM) $(NAME).map > $(DEVNULL) 2>&1
