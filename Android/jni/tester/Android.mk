LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
include $(call all-subdir-makefiles)
LOCAL_LDLIBS	:= -llog
LOCAL_LDLIBS    += -landroid
LOCAL_MODULE    := tester
LOCAL_SRC_FILES := tester.c
LOCAL_SHARED_LIBRARIES := gmp pbc glib
LOCAL_STATIC_LIBRARIES := ssl_static crypto_static
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../pbc/include/ 
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../openssl/include/
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../glib/
include $(BUILD_SHARED_LIBRARY)