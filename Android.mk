LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

ifeq ($(TARGET_USE_USERFASTBOOT),true)

LOCAL_SRC_FILES := \
	aboot.c \
	fastboot.c \
	util.c \
	userfastboot.c \
	fstab.c \
	gpt.c \
	network.c \
	ui.cpp \
	sanity.c \
	keystore.c \
	asn1.c \
	hashes.c

LOCAL_CFLAGS := -DDEVICE_NAME=\"$(TARGET_BOOTLOADER_BOARD_NAME)\" \
	-W -Wall -Wextra -Wno-unused-parameter -Wno-format-zero-length -Werror -mrdrnd

ifneq ($(strip $(TARGET_BOOTLOADER_POLICY)),)
    LOCAL_CFLAGS += -DBOOTLOADER_POLICY=$(TARGET_BOOTLOADER_POLICY)
    # Double negation to enforce the use of the EFI variable storage
    # as the default behavior.
    ifneq ($(strip $(TARGET_BOOTLOADER_POLICY_USE_EFI_VAR)),False)
        LOCAL_CFLAGS += -DBOOTLOADER_POLICY_EFI_VAR
    endif
    LOCAL_SRC_FILES += \
	blpolicy.c \
	security.c \
	authenticated_action.c
endif

LOCAL_MODULE := userfastboot-$(TARGET_BUILD_VARIANT)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_PATH := $(PRODUCT_OUT)/userfastboot
LOCAL_UNSTRIPPED_PATH := $(PRODUCT_OUT)/userfastboot/debug

# Marshmallow changed how static executables are linked. In short, see the
# -Wl,--start-group and -Wl,--end-group linker flags, and the
# transform-o-to-static-executable-inner function in build/core/definitions.mk.
# Below, libraries should loosely be listed from 'leaves' to 'core'.
LOCAL_STATIC_LIBRARIES := liblog libsparse_static libminui libpng \
			  libselinux libfs_mgr libiniparser libgpt_static libefivar \
			  libcrypto_static2 libext4_utils_static libcutils libz libm libc \
			  libstdc++
LOCAL_MODULE_STEM := userfastboot

LOCAL_FORCE_STATIC_EXECUTABLE := true

LOCAL_STATIC_LIBRARIES += $(TARGET_USERFASTBOOT_LIBS) $(TARGET_USERFASTBOOT_EXTRA_LIBS)
LOCAL_C_INCLUDES += external/libpng \
                    external/iniparser/src \
                    external/efivar/src \
                    external/openssl/include \
                    bootable/userfastboot/microui \
                    bootable/userfastboot/libgpt/include \
                    bootable/recovery \
                    system/core/libsparse \
                    system/core/mkbootimg \
                    system/core/fs_mgr/include \
                    system/core/libsparse/include \
                    system/extras/ext4_utils

# Each library in TARGET_USERFASTBOOT_LIBS should have a function
# named "<libname>_init()".  Here we emit a little C function that
# gets #included by aboot.c.  It calls all those registration
# functions.

# Devices can also add libraries to TARGET_USERFASTBOOT_EXTRA_LIBS.
# These libs are also linked in with userfastboot, but we don't try to call
# any sort of registration function for these.  Use this variable for
# any subsidiary static libraries required for your registered
# extension libs.

inc := $(call intermediates-dir-for,PACKAGING,userfastboot_extensions)/register.inc

# During the first pass of reading the makefiles, we dump the list of
# extension libs to a temp file, then copy that to the ".list" file if
# it is different than the existing .list (if any).  The register.inc
# file then uses the .list as a prerequisite, so it is only rebuilt
# (and aboot.o recompiled) when the list of extension libs changes.

junk := $(shell mkdir -p $(dir $(inc));\
	        echo $(TARGET_USERFASTBOOT_LIBS) > $(inc).temp;\
	        diff -q $(inc).temp $(inc).list 2>/dev/null || cp -f $(inc).temp $(inc).list)

$(inc) : libs := $(TARGET_USERFASTBOOT_LIBS)
$(inc) : $(inc).list $(LOCAL_PATH)/Android.mk
	$(hide) mkdir -p $(dir $@)
	$(hide) echo "" > $@
	$(hide) $(foreach lib,$(libs), echo -e "extern void $(lib)_init(void);\n" >> $@;)
	$(hide) echo "void register_userfastboot_plugins() {" >> $@
	$(hide) $(foreach lib,$(libs),echo "  $(lib)_init();" >> $@;)
	$(hide) echo "}" >> $@

$(call intermediates-dir-for,EXECUTABLES,userfastboot-$(TARGET_BUILD_VARIANT),,,$(TARGET_PREFER_32_BIT))/aboot.o : $(inc)
LOCAL_C_INCLUDES += $(dir $(inc))

ifeq ($(TARGET_NO_DEVICE_UNLOCK),true)
    LOCAL_CFLAGS += -DNO_DEVICE_UNLOCK
endif
ifneq ($(USERFASTBOOT_NO_GUI),true)
    LOCAL_CFLAGS += -DUSE_GUI
endif
ifeq ($(TARGET_BUILD_VARIANT),user)
    LOCAL_CFLAGS += -DUSER -DUSERDEBUG
endif
ifeq ($(TARGET_BUILD_VARIANT),userdebug)
    LOCAL_CFLAGS += -DUSERDEBUG
endif
include $(BUILD_EXECUTABLE)

##################################
include $(CLEAR_VARS)

get_additional_macros = $(addprefix -D, $(BOARD_SEPOLICY_M4DEFS))

# SELinux policy version.
# Must be <= /sys/fs/selinux/policyvers reported by the Android kernel.
# Must be within the compatibility range reported by checkpolicy -V.
POLICYVERS ?= 30

MLS_SENS=1
MLS_CATS=1024

ifdef BOARD_SEPOLICY_REPLACE
$(error BOARD_SEPOLICY_REPLACE is no longer supported; please remove from your BoardConfig.mk or other .mk file.)
endif

ifdef BOARD_SEPOLICY_IGNORE
$(error BOARD_SEPOLICY_IGNORE is no longer supported; please remove from your BoardConfig.mk or other .mk file.)
endif

ifdef BOARD_SEPOLICY_UNION
$(warning BOARD_SEPOLICY_UNION is no longer required - all files found in BOARD_SEPOLICY_DIRS are implicitly unioned; please remove from your BoardConfig.mk or other .mk file.)
endif

# Builds paths for all policy files found in BOARD_SEPOLICY_DIRS.
# $(1): the set of policy name paths to build
build_policy = $(foreach type, $(1), $(wildcard $(addsuffix /$(type), external/sepolicy $(BOARD_SEPOLICY_DIRS))))

sepolicy_build_files := security_classes \
                        initial_sids \
                        access_vectors \
                        global_macros \
                        mls_macros \
                        mls \
                        neverallow_macros \
                        policy_capabilities \
                        te_macros \
                        attributes \
                        ioctl_macros \
                        *.te \
                        roles \
                        users \
                        initial_sid_contexts \
                        fs_use \
                        genfs_contexts \
                        port_contexts

LOCAL_MODULE := sepolicy.userfastboot
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_TAGS := optional

include $(BUILD_SYSTEM)/base_rules.mk
sepolicy_policy_userfastboot.conf := $(intermediates)/policy_userfastboot.conf
$(sepolicy_policy_userfastboot.conf): PRIVATE_MLS_SENS := $(MLS_SENS)
$(sepolicy_policy_userfastboot.conf): PRIVATE_MLS_CATS := $(MLS_CATS)
$(sepolicy_policy_userfastboot.conf): PRIVATE_LOCAL_PATH := $(LOCAL_PATH)
$(sepolicy_policy_userfastboot.conf): PRIVATE_M4DEFS := $(call get_additional_macros)
$(sepolicy_policy_userfastboot.conf) : $(call build_policy, $(sepolicy_build_files))
	@mkdir -p $(dir $@)
	$(hide) m4 $(PRIVATE_M4DEFS) \
		-D mls_num_sens=$(PRIVATE_MLS_SENS) -D mls_num_cats=$(PRIVATE_MLS_CATS) \
		-D target_build_variant=$(TARGET_BUILD_VARIANT) \
		-D target_userfastboot=true \
		-s $^ | ./$(PRIVATE_LOCAL_PATH)/nallow-filter.py > $@

$(LOCAL_BUILT_MODULE) : $(sepolicy_policy_userfastboot.conf) $(HOST_OUT_EXECUTABLES)/checkpolicy
	@mkdir -p $(dir $@)
	$(hide) $(HOST_OUT_EXECUTABLES)/checkpolicy -M -c $(POLICYVERS) -o $@ $<

sepolicy_policy_userfastboot.conf :=
sepolicy_build_files :=

endif # TARGET_USE_USERFASTBOOT

include bootable/userfastboot/libgpt/Android.mk
