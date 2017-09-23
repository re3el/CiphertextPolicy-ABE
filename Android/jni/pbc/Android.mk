LOCAL_PATH := $(call my-dir)
ROOT_PATH:= $(LOCAL_PATH)
include $(call all-subdir-makefiles)
include $(CLEAR_VARS)
LOCAL_PATH:= $(ROOT_PATH)
LOCAL_CFLAGS:=-Wall -Wextra
include $(LOCAL_PATH)/arith/source.mk
include $(LOCAL_PATH)/benchmark/source.mk
include $(LOCAL_PATH)/ecc/source.mk
include $(LOCAL_PATH)/gen/source.mk
include $(LOCAL_PATH)/guru/source.mk
include $(LOCAL_PATH)/misc/source.mk
#include $(LOCAL_PATH)/pbc/source.mk
LOCAL_MODULE:= pbc
#LOCAL_EXPORT_C_INCLUDES := -L$(LOCAL_PATH)/include/
LOCAL_LDLIBS:= -L$(SYSROOT)/usr/lib -L$(SYSROOT)/usr/include/readline -llog 
#LOCAL_LDFLAGS := -L$(LOCAL_PATH)/include/
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include/ 
LOCAL_SHARED_LIBRARIES:= gmp
LOCAL_C_FLAGS:=-g
include $(BUILD_SHARED_LIBRARY)