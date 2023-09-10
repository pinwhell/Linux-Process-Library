LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_ARM_MODE := arm
LOCAL_LDLIBS := -llog
LOCAL_ARM_NEON := false
LOCAL_MODULE := mem
LOCAL_SRC_FILES := main.cpp ProcessManager.cpp ElfUtils.cpp
LOCAL_CFLAGS := -fexceptions
LOCAL_CPPFLAGS := 
include $(BUILD_EXECUTABLE)