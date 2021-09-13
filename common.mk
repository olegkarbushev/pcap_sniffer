OS_FLAGS :=
OS_LIB_FLAGS :=
LIB_EXT :=
ifeq ($(OS),Windows_NT) 			# Windows
	OS_FLAGS += -D WIN32
	OS_LIB_FLAGS += -shared -fPIC
	LIB_EXT = dll
	ifeq ($(PROCESSOR_ARCHITECTURE),AMD64)
		OS_FLAGS += -D AMD64
	endif
	ifeq ($(PROCESSOR_ARCHITECTURE),x86)
		OS_FLAGS += -D IA32
	endif
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux) 		# Linux
		OS_FLAGS += -D LINUX
		OS_LIB_FLAGS += -shared -fPIC
		LIB_EXT = so
		UNAME_P := $(shell uname -p)
	endif
	ifeq ($(UNAME_S),Darwin)		# Mac
		OS_FLAGS += -D OSX
		OS_LIB_FLAGS += -dynamic -fPIC
		LIB_EXT = dylib
		UNAME_P := $(shell uname -m)
	endif
	# Figure out arch
	ifeq ($(UNAME_P),x86_64)
		OS_FLAGS += -D AMD64
	endif
	ifneq ($(filter %86,$(UNAME_P)),)
		OS_FLAGS += -D IA32
	endif
	ifneq ($(filter arm%,$(UNAME_P)),)
		OS_FLAGS += -D ARM
	endif
endif
