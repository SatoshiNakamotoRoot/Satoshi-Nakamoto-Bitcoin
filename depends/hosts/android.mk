ANDROID_SDK=$(ANDROID_SDK)
ANDROID_NDK=$(ANDROID_NDK)
NDK_VERSION=4.9
ANDROID_API_LEVEL=$(ANDROID_API_LEVEL)
ANDROID_TARGET_ARCH=$(ANDROID_TARGET_ARCH)

ifeq (ANDROID_TARGET_ARCH,armeabi-v7a)
android_AR=$(ANDROID_TOOLCHAIN_BIN)/arm-linux-androideabi-ar
android_CXX=$(ANDROID_TOOLCHAIN_BIN)/$(HOST)eabi$(ANDROID_API_LEVEL)-clang++
android_CC=$(ANDROID_TOOLCHAIN_BIN)/$(HOST)eabi$(ANDROID_API_LEVEL)-clang
android_RANLIB=$(ANDROID_TOOLCHAIN_BIN)/arm-linux-androideabi-ranlib
elseif (ANDROID_TARGET_ARCH,x86)
android_AR=$(ANDROID_TOOLCHAIN_BIN)/i686-linux-android-ar
android_CXX=$(ANDROID_TOOLCHAIN_BIN)/i686-linux-android$(ANDROID_API_LEVEL)-clang++
android_CC=$(ANDROID_TOOLCHAIN_BIN)/i686-linux-android$(ANDROID_API_LEVEL)-clang
android_RANLIB=$(ANDROID_TOOLCHAIN_BIN)/i686-linux-android-ranlib
else
android_AR=$(ANDROID_TOOLCHAIN_BIN)/$(HOST)-ar
android_CXX=$(ANDROID_TOOLCHAIN_BIN)/$(HOST)$(ANDROID_API_LEVEL)-clang++
android_CC=$(ANDROID_TOOLCHAIN_BIN)/$(HOST)$(ANDROID_API_LEVEL)-clang
android_RANLIB=$(ANDROID_TOOLCHAIN_BIN)/$(HOST)-ranlib
endif
