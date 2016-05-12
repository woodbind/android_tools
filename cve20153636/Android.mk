LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := poc_3636
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_SRC_FILES := poc.c
LOCAL_CFLAGS += -DDEBUG -D__ARM__ -Wno-error=sequence-point
LOCAL_LDFLAGS += -static
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_STATIC_LIBRARIES := \
    libc \
    libc++_static \
    libdl \
    libm

include $(BUILD_EXECUTABLE)

