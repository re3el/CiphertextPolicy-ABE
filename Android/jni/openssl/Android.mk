LOCAL_PATH := $(call my-dir)

#include $(CLEAR_VARS)
#LOCAL_MODULE    := ssl
#LOCAL_SRC_FILES := $(TARGET_ARCH_ABI)/lib/libssl.so 
#include $(PREBUILT_SHARED_LIBRARY)

#include $(CLEAR_VARS)
#LOCAL_MODULE    := crypto
#LOCAL_SRC_FILES := $(TARGET_ARCH_ABI)/lib/libcrypto.so
#include $(PREBUILT_SHARED_LIBRARY)




include $(CLEAR_VARS)
LOCAL_MODULE := ssl_static
LOCAL_SRC_FILES := $(TARGET_ARCH_ABI)/lib/libsslNative.a
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/include/openssl/
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := crypto_static
LOCAL_SRC_FILES := $(TARGET_ARCH_ABI)/lib/libcryptoNative.a
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/include/openssl/
include $(PREBUILT_STATIC_LIBRARY)


include $(CLEAR_VARS)
LOCAL_MODULE := ssl_static_shared
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/include/openssl/
LOCAL_STATIC_LIBRARIES := ssl_static
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := crypto_static_shared
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/include/openssl/
LOCAL_STATIC_LIBRARIES := crypto_static
include $(BUILD_SHARED_LIBRARY)