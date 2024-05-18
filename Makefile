#   * python3-config
#   * $(PYTHON)-config (If PYTHON is user supplied but PYTHON_CONFIG isn't)
#
PYTHON_AUTO := python-config
PYTHON_AUTO := $(if $(call get-executable,python2-config),python2-config,$(PYTHON_AUTO))
PYTHON_AUTO := $(if $(call get-executable,python-config),python-config,$(PYTHON_AUTO))
PYTHON_AUTO := $(if $(call get-executable,python3-config),python3-config,$(PYTHON_AUTO))

# If PYTHON is defined but PYTHON_CONFIG isn't, then take $(PYTHON)-config as if it was the user
# supplied value for PYTHON_CONFIG. Because it's "user supplied", error out if it doesn't exist.
ifdef PYTHON
  ifndef PYTHON_CONFIG
    PYTHON_CONFIG_AUTO := $(call get-executable,$(PYTHON)-config)
    PYTHON_CONFIG := $(if $(PYTHON_CONFIG_AUTO),$(PYTHON_CONFIG_AUTO),\
                          $(call $(error $(PYTHON)-config not found)))
  endif
endif

# Select either auto detected python and python-config or use user supplied values if they are
# defined. get-executable-or-default fails with an error if the first argument is supplied but
# doesn't exist.
override PYTHON_CONFIG := $(call get-executable-or-default,PYTHON_CONFIG,$(PYTHON_AUTO))
override PYTHON := $(call get-executable-or-default,PYTHON,$(subst -config,,$(PYTHON_CONFIG)))

grep-libs  = $(filter -l%,$(1))
strip-libs  = $(filter-out -l%,$(1))

PYTHON_CONFIG_SQ := $(call shell-sq,$(PYTHON_CONFIG))

# Python 3.8 changed the output of `python-config --ldflags` to not include the
# '-lpythonX.Y' flag unless '--embed' is also passed. The feature check for
# libpython fails if that flag is not included in LDFLAGS
ifeq ($(shell $(PYTHON_CONFIG_SQ) --ldflags --embed 2>&1 1>/dev/null; echo $$?), 0)
  PYTHON_CONFIG_LDFLAGS := --ldflags --embed
else
  PYTHON_CONFIG_LDFLAGS := --ldflags
endif

ifdef PYTHON_CONFIG
  PYTHON_EMBED_LDOPTS := $(shell $(PYTHON_CONFIG_SQ) $(PYTHON_CONFIG_LDFLAGS) 2>/dev/null)
  PYTHON_EMBED_LDFLAGS := $(call strip-libs,$(PYTHON_EMBED_LDOPTS))
  PYTHON_EMBED_LIBADD := $(call grep-libs,$(PYTHON_EMBED_LDOPTS)) -lutil
  PYTHON_EMBED_CCOPTS := $(shell $(PYTHON_CONFIG_SQ) --includes 2>/dev/null)
  FLAGS_PYTHON_EMBED := $(PYTHON_EMBED_CCOPTS) $(PYTHON_EMBED_LDOPTS)
  ifeq ($(CC_NO_CLANG), 0)
    PYTHON_EMBED_CCOPTS := $(filter-out -ffat-lto-objects, $(PYTHON_EMBED_CCOPTS))
  endif
endif

FEATURE_CHECK_CFLAGS-libpython := $(PYTHON_EMBED_CCOPTS)
FEATURE_CHECK_LDFLAGS-libpython := $(PYTHON_EMBED_LDOPTS)

FEATURE_CHECK_LDFLAGS-libaio = -lrt

FEATURE_CHECK_LDFLAGS-disassembler-four-args = -lbfd -lopcodes -ldl
FEATURE_CHECK_LDFLAGS-disassembler-init-styled = -lbfd -lopcodes -ldl

CORE_CFLAGS += -fno-omit-frame-pointer
CORE_CFLAGS += -Wall
CORE_CFLAGS += -Wextra
CORE_CFLAGS += -std=gnu11

CXXFLAGS += -std=gnu++17 -fno-exceptions -fno-rtti
CXXFLAGS += -Wall
CXXFLAGS += -Wextra
CXXFLAGS += -fno-omit-frame-pointer

HOSTCFLAGS += -Wall
HOSTCFLAGS += -Wextra

# Enforce a non-executable stack, as we may regress (again) in the future by
# adding assembler files missing the .GNU-stack linker note.
LDFLAGS += -Wl,-z,noexecstack

EXTLIBS = -lpthread -lrt -lm -ldl

ifneq ($(TCMALLOC),)
  CFLAGS += -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free
  EXTLIBS += -ltcmalloc
endif

ifeq ($(FEATURES_DUMP),)
# We will display at the end of this Makefile.config, using $(call feature_display_entries)
# As we may retry some feature detection here, see the disassembler-four-args case, for instance
  FEATURE_DISPLAY_DEFERRED := 1
include $(srctree)/tools/build/Makefile.feature
else
include $(FEATURES_DUMP)
endif

ifeq ($(feature-stackprotector-all), 1)
  CORE_CFLAGS += -fstack-protector-all
endif

ifeq ($(DEBUG),0)
  ifeq ($(feature-fortify-source), 1)
    CORE_CFLAGS += -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
  endif
endif

INC_FLAGS += -I$(src-perf)/util/include
INC_FLAGS += -I$(src-perf)/arch/$(SRCARCH)/include
INC_FLAGS += -I$(srctree)/tools/include/
INC_FLAGS += -I$(srctree)/tools/arch/$(SRCARCH)/include/uapi
INC_FLAGS += -I$(srctree)/tools/include/uapi
INC_FLAGS += -I$(srctree)/tools/arch/$(SRCARCH)/include/
INC_FLAGS += -I$(srctree)/tools/arch/$(SRCARCH)/

# $(obj-perf)      for generated common-cmds.h
# $(obj-perf)/util for generated bison/flex headers
ifneq ($(OUTPUT),)
INC_FLAGS += -I$(obj-perf)/util
INC_FLAGS += -I$(obj-perf)
endif

INC_FLAGS += -I$(src-perf)/util
INC_FLAGS += -I$(src-perf)

CORE_CFLAGS += -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE

CFLAGS   += $(CORE_CFLAGS) $(INC_FLAGS)
CXXFLAGS += $(INC_FLAGS)

LIBPERF_CFLAGS := $(CORE_CFLAGS) $(EXTRA_CFLAGS)

ifeq ($(feature-pthread-attr-setaffinity-np), 1)
  CFLAGS += -DHAVE_PTHREAD_ATTR_SETAFFINITY_NP
endif

ifeq ($(feature-pthread-barrier), 1)
  CFLAGS += -DHAVE_PTHREAD_BARRIER
endif

ifndef NO_BIONIC
  $(call feature_check,bionic)
  ifeq ($(feature-bionic), 1)
    BIONIC := 1
    CFLAGS += -DLACKS_SIGQUEUE_PROTOTYPE
    CFLAGS += -DLACKS_OPEN_MEMSTREAM_PROTOTYPE
    EXTLIBS := $(filter-out -lrt,$(EXTLIBS))
    EXTLIBS := $(filter-out -lpthread,$(EXTLIBS))
  endif
endif

ifeq ($(feature-eventfd), 1)
  CFLAGS += -DHAVE_EVENTFD_SUPPORT
endif

ifeq ($(feature-get_current_dir_name), 1)
  CFLAGS += -DHAVE_GET_CURRENT_DIR_NAME
endif

ifeq ($(feature-gettid), 1)
  CFLAGS += -DHAVE_GETTID
endif

ifeq ($(feature-file-handle), 1)
  CFLAGS += -DHAVE_FILE_HANDLE
endif

ifdef NO_LIBELF
  NO_DWARF := 1
  NO_LIBUNWIND := 1
  NO_LIBDW_DWARF_UNWIND := 1
  NO_LIBBPF := 1
  NO_JVMTI := 1
else
  ifeq ($(feature-libelf), 0)
    ifeq ($(feature-glibc), 1)
      LIBC_SUPPORT := 1
    endif
    ifeq ($(BIONIC),1)
      LIBC_SUPPORT := 1
    endif
    ifeq ($(LIBC_SUPPORT),1)
      msg := $(error ERROR: No libelf found. Disables 'probe' tool, jvmti and BPF support. Please install libelf-dev, libelf-devel, elfutils-libelf-devel or build with NO_LIBELF=1.)
    else
      ifneq ($(filter s% -fsanitize=address%,$(EXTRA_CFLAGS),),)
        ifneq ($(shell ldconfig -p | grep libasan >/dev/null 2>&1; echo $$?), 0)
          msg := $(error No libasan found, please install libasan);
        endif
      endif

      ifneq ($(filter s% -fsanitize=undefined%,$(EXTRA_CFLAGS),),)
        ifneq ($(shell ldconfig -p | grep libubsan >/dev/null 2>&1; echo $$?), 0)
          msg := $(error No libubsan found, please install libubsan);
        endif
      endif

      ifneq ($(filter s% -static%,$(LDFLAGS),),)
        msg := $(error No static glibc found, please install glibc-static);
      else
        msg := $(error No gnu/libc-version.h found, please install glibc-dev[el]);
      endif
    endif
  else
    ifndef NO_LIBDW_DWARF_UNWIND
      ifneq ($(feature-libdw-dwarf-unwind),1)
        NO_LIBDW_DWARF_UNWIND := 1
        msg := $(warning No libdw DWARF unwind found, Please install elfutils-devel/libdw-dev >= 0.158 and/or set LIBDW_DIR);
      endif
    endif
    ifneq ($(feature-dwarf), 1)
      ifndef NO_DWARF
        msg := $(warning No libdw.h found or old libdw.h found or elfutils is older than 0.138, disables dwarf support. Please install new elfutils-devel/libdw-dev);
        NO_DWARF := 1
      endif
    else
      ifneq ($(feature-dwarf_getlocations), 1)
        msg := $(warning Old libdw.h, finding variables at given 'perf probe' point will not work, install elfutils-devel/libdw-dev >= 0.157);
      else
        CFLAGS += -DHAVE_DWARF_GETLOCATIONS_SUPPORT
      endif # dwarf_getlocations
    endif # Dwarf support
  endif # libelf support
endif # NO_LIBELF

ifeq ($(feature-libaio), 1)
  ifndef NO_AIO
    CFLAGS += -DHAVE_AIO_SUPPORT
  endif
endif

ifdef NO_DWARF
  NO_LIBDW_DWARF_UNWIND := 1
endif

ifeq ($(feature-scandirat), 1)
  CFLAGS += -DHAVE_SCANDIRAT_SUPPORT
endif

ifeq ($(feature-sched_getcpu), 1)
  CFLAGS += -DHAVE_SCHED_GETCPU_SUPPORT
endif

ifeq ($(feature-setns), 1)
  CFLAGS += -DHAVE_SETNS_SUPPORT
  $(call detected,CONFIG_SETNS)
endif

ifdef CORESIGHT
  $(call feature_check,libopencsd)
  ifeq ($(feature-libopencsd), 1)
    CFLAGS += -DHAVE_CSTRACE_SUPPORT $(LIBOPENCSD_CFLAGS)
    ifeq ($(feature-reallocarray), 0)
      CFLAGS += -DCOMPAT_NEED_REALLOCARRAY
    endif
    LDFLAGS += $(LIBOPENCSD_LDFLAGS)
    EXTLIBS += $(OPENCSDLIBS)
    $(call detected,CONFIG_LIBOPENCSD)
    ifdef CSTRACE_RAW
      CFLAGS += -DCS_DEBUG_RAW
      ifeq (${CSTRACE_RAW}, packed)
        CFLAGS += -DCS_RAW_PACKED
      endif
    endif
  else
    dummy := $(error Error: No libopencsd library found or the version is not up-to-date. Please install recent libopencsd to build with CORESIGHT=1)
  endif
endif

ifndef NO_LIBELF
  CFLAGS += -DHAVE_LIBELF_SUPPORT
  EXTLIBS += -lelf
  $(call detected,CONFIG_LIBELF)

  ifeq ($(feature-libelf-getphdrnum), 1)
    CFLAGS += -DHAVE_ELF_GETPHDRNUM_SUPPORT
  endif

  ifeq ($(feature-libelf-gelf_getnote), 1)
    CFLAGS += -DHAVE_GELF_GETNOTE_SUPPORT
  else
    msg := $(warning gelf_getnote() not found on libelf, SDT support disabled);
  endif

  ifeq ($(feature-libelf-getshdrstrndx), 1)
    CFLAGS += -DHAVE_ELF_GETSHDRSTRNDX_SUPPORT
  endif

  ifndef NO_LIBDEBUGINFOD
    $(call feature_check,libdebuginfod)
    ifeq ($(feature-libdebuginfod), 1)
      CFLAGS += -DHAVE_DEBUGINFOD_SUPPORT
      EXTLIBS += -ldebuginfod
    endif
  endif

  ifndef NO_DWARF
    ifeq ($(origin PERF_HAVE_DWARF_REGS), undefined)
      msg := $(warning DWARF register mappings have not been defined for architecture $(SRCARCH), DWARF support disabled);
      NO_DWARF := 1
    else
      CFLAGS += -DHAVE_DWARF_SUPPORT $(LIBDW_CFLAGS)
      LDFLAGS += $(LIBDW_LDFLAGS)
      EXTLIBS += ${DWARFLIBS}
      $(call detected,CONFIG_DWARF)
    endif # PERF_HAVE_DWARF_REGS
  endif # NO_DWARF

  ifndef NO_LIBBPF
    ifeq ($(feature-bpf), 1)
      CFLAGS += -DHAVE_LIBBPF_SUPPORT
      $(call detected,CONFIG_LIBBPF)

      # detecting libbpf without LIBBPF_DYNAMIC, so make VF=1 shows libbpf detection status
      $(call feature_check,libbpf)

      ifdef LIBBPF_DYNAMIC
        ifeq ($(feature-libbpf), 1)
          EXTLIBS += -lbpf
          $(call detected,CONFIG_LIBBPF_DYNAMIC)
        else
          dummy := $(error Error: No libbpf devel library found or older than v1.0, please install/update libbpf-devel);
        endif
      else
        # Libbpf will be built as a static library from tools/lib/bpf.
	LIBBPF_STATIC := 1
      endif
    endif
  endif # NO_LIBBPF
endif # NO_LIBELF

ifndef NO_SDT
  ifneq ($(feature-sdt), 1)
    msg := $(warning No sys/sdt.h found, no SDT events are defined, please install systemtap-sdt-devel or systemtap-sdt-dev);
    NO_SDT := 1;
  else
    CFLAGS += -DHAVE_SDT_EVENT
    $(call detected,CONFIG_SDT_EVENT)
  endif
endif

ifdef PERF_HAVE_JITDUMP
  ifndef NO_LIBELF
    $(call detected,CONFIG_JITDUMP)
    CFLAGS += -DHAVE_JITDUMP
  endif
endif

ifeq ($(SRCARCH),powerpc)
  ifndef NO_DWARF
    CFLAGS += -DHAVE_SKIP_CALLCHAIN_IDX
  endif
endif

ifndef NO_LIBUNWIND
  have_libunwind :=

  $(call feature_check,libunwind-x86)
  ifeq ($(feature-libunwind-x86), 1)
    $(call detected,CONFIG_LIBUNWIND_X86)
    CFLAGS += -DHAVE_LIBUNWIND_X86_SUPPORT
    LDFLAGS += -lunwind-x86
    EXTLIBS_LIBUNWIND += -lunwind-x86
    have_libunwind = 1
  endif

  $(call feature_check,libunwind-aarch64)
  ifeq ($(feature-libunwind-aarch64), 1)
    $(call detected,CONFIG_LIBUNWIND_AARCH64)
    CFLAGS += -DHAVE_LIBUNWIND_AARCH64_SUPPORT
    LDFLAGS += -lunwind-aarch64
    EXTLIBS_LIBUNWIND += -lunwind-aarch64
    have_libunwind = 1
    $(call feature_check,libunwind-debug-frame-aarch64)
    ifneq ($(feature-libunwind-debug-frame-aarch64), 1)
      msg := $(warning No debug_frame support found in libunwind-aarch64);
      CFLAGS += -DNO_LIBUNWIND_DEBUG_FRAME_AARCH64
    endif
  endif

  ifneq ($(feature-libunwind), 1)
    msg := $(warning No libunwind found. Please install libunwind-dev[el] >= 1.1 and/or set LIBUNWIND_DIR);
    NO_LOCAL_LIBUNWIND := 1
  else
    have_libunwind := 1
    $(call detected,CONFIG_LOCAL_LIBUNWIND)
  endif

  ifneq ($(have_libunwind), 1)
    NO_LIBUNWIND := 1
  endif
else
  NO_LOCAL_LIBUNWIND := 1
endif

ifndef NO_LIBBPF
  ifneq ($(feature-bpf), 1)
    msg := $(warning BPF API too old. Please install recent kernel headers. BPF support in 'perf record' is disabled.)
    NO_LIBBPF := 1
  endif
endif

ifdef BUILD_BPF_SKEL
  $(call feature_check,clang-bpf-co-re)
  ifeq ($(feature-clang-bpf-co-re), 0)
    dummy := $(error Error: clang too old/not installed. Please install recent clang to build with BUILD_BPF_SKEL)
  endif
  ifeq ($(filter -DHAVE_LIBBPF_SUPPORT, $(CFLAGS)),)
    dummy := $(error Error: BPF skeleton support requires libbpf)
  endif
  $(call detected,CONFIG_PERF_BPF_SKEL)
  CFLAGS += -DHAVE_BPF_SKEL
endif

ifndef GEN_VMLINUX_H
  VMLINUX_H=$(src-perf)/util/bpf_skel/vmlinux/vmlinux.h
endif

dwarf-post-unwind := 1
dwarf-post-unwind-text := BUG

# setup DWARF post unwinder
ifdef NO_LIBUNWIND
  ifdef NO_LIBDW_DWARF_UNWIND
    msg := $(warning Disabling post unwind, no support found.);
    dwarf-post-unwind := 0
  else
    dwarf-post-unwind-text := libdw
    $(call detected,CONFIG_LIBDW_DWARF_UNWIND)
  endif
else
  dwarf-post-unwind-text := libunwind
  $(call detected,CONFIG_LIBUNWIND)
  # Enable libunwind support by default.
  ifndef NO_LIBDW_DWARF_UNWIND
    NO_LIBDW_DWARF_UNWIND := 1
  endif
endif

ifeq ($(dwarf-post-unwind),1)
  CFLAGS += -DHAVE_DWARF_UNWIND_SUPPORT
  $(call detected,CONFIG_DWARF_UNWIND)
else
  NO_DWARF_UNWIND := 1
endif

ifndef NO_LOCAL_LIBUNWIND
  ifeq ($(SRCARCH),$(filter $(SRCARCH),arm arm64))
    $(call feature_check,libunwind-debug-frame)
    ifneq ($(feature-libunwind-debug-frame), 1)
      msg := $(warning No debug_frame support found in libunwind);
      CFLAGS += -DNO_LIBUNWIND_DEBUG_FRAME
    endif
  else
    # non-ARM has no dwarf_find_debug_frame() function:
    CFLAGS += -DNO_LIBUNWIND_DEBUG_FRAME
  endif
  EXTLIBS += $(LIBUNWIND_LIBS)
  LDFLAGS += $(LIBUNWIND_LIBS)
endif
ifeq ($(findstring -static,${LDFLAGS}),-static)
  # gcc -static links libgcc_eh which contans piece of libunwind
  LIBUNWIND_LDFLAGS += -Wl,--allow-multiple-definition
endif

ifndef NO_LIBUNWIND
  CFLAGS  += -DHAVE_LIBUNWIND_SUPPORT
  CFLAGS  += $(LIBUNWIND_CFLAGS)
  LDFLAGS += $(LIBUNWIND_LDFLAGS)
  EXTLIBS += $(EXTLIBS_LIBUNWIND)
endif

ifneq ($(NO_LIBTRACEEVENT),1)
  ifeq ($(NO_SYSCALL_TABLE),0)
    $(call detected,CONFIG_TRACE)
  else
    ifndef NO_LIBAUDIT
      $(call feature_check,libaudit)
      ifneq ($(feature-libaudit), 1)
        msg := $(warning No libaudit.h found, disables 'trace' tool, please install audit-libs-devel or libaudit-dev);
        NO_LIBAUDIT := 1
      else
        CFLAGS += -DHAVE_LIBAUDIT_SUPPORT
        EXTLIBS += -laudit
        $(call detected,CONFIG_TRACE)
      endif
    endif
  endif
endif

ifndef NO_LIBCRYPTO
  ifneq ($(feature-libcrypto), 1)
    msg := $(warning No libcrypto.h found, disables jitted code injection, please install openssl-devel or libssl-dev);
    NO_LIBCRYPTO := 1
  else
    CFLAGS += -DHAVE_LIBCRYPTO_SUPPORT
    EXTLIBS += -lcrypto
    $(call detected,CONFIG_CRYPTO)
  endif
endif

ifndef NO_SLANG
  ifneq ($(feature-libslang), 1)
    ifneq ($(feature-libslang-include-subdir), 1)
      msg := $(warning slang not found, disables TUI support. Please install slang-devel, libslang-dev or libslang2-dev);
      NO_SLANG := 1
    else
      CFLAGS += -DHAVE_SLANG_INCLUDE_SUBDIR
    endif
  endif
  ifndef NO_SLANG
    # Fedora has /usr/include/slang/slang.h, but ubuntu /usr/include/slang.h
    CFLAGS += -DHAVE_SLANG_SUPPORT
    EXTLIBS += -lslang
    $(call detected,CONFIG_SLANG)
  endif
endif

ifdef GTK2
  FLAGS_GTK2=$(CFLAGS) $(LDFLAGS) $(EXTLIBS) $(shell $(PKG_CONFIG) --libs --cflags gtk+-2.0 2>/dev/null)
  $(call feature_check,gtk2)
  ifneq ($(feature-gtk2), 1)
    msg := $(warning GTK2 not found, disables GTK2 support. Please install gtk2-devel or libgtk2.0-dev);
    NO_GTK2 := 1
  else
    $(call feature_check,gtk2-infobar)
    ifeq ($(feature-gtk2-infobar), 1)
      GTK_CFLAGS := -DHAVE_GTK_INFO_BAR_SUPPORT
    endif
    CFLAGS += -DHAVE_GTK2_SUPPORT
    GTK_CFLAGS += $(shell $(PKG_CONFIG) --cflags gtk+-2.0 2>/dev/null)
    GTK_LIBS := $(shell $(PKG_CONFIG) --libs gtk+-2.0 2>/dev/null)
    EXTLIBS += -ldl
  endif
endif

ifdef NO_LIBPERL
  CFLAGS += -DNO_LIBPERL
else
  PERL_EMBED_LDOPTS = $(shell perl -MExtUtils::Embed -e ldopts 2>/dev/null)
  PERL_EMBED_LDFLAGS = $(call strip-libs,$(PERL_EMBED_LDOPTS))
  PERL_EMBED_LIBADD = $(call grep-libs,$(PERL_EMBED_LDOPTS))
  PERL_EMBED_CCOPTS = $(shell perl -MExtUtils::Embed -e ccopts 2>/dev/null)
  PERL_EMBED_CCOPTS := $(filter-out -specs=%,$(PERL_EMBED_CCOPTS))
  PERL_EMBED_CCOPTS := $(filter-out -flto=auto -ffat-lto-objects, $(PERL_EMBED_CCOPTS))
  PERL_EMBED_LDOPTS := $(filter-out -specs=%,$(PERL_EMBED_LDOPTS))
  FLAGS_PERL_EMBED=$(PERL_EMBED_CCOPTS) $(PERL_EMBED_LDOPTS)

  ifneq ($(feature-libperl), 1)
    CFLAGS += -DNO_LIBPERL
    NO_LIBPERL := 1
    msg := $(warning Missing perl devel files. Disabling perl scripting support, please install perl-ExtUtils-Embed/libperl-dev);
  else
    LDFLAGS += $(PERL_EMBED_LDFLAGS)
    EXTLIBS += $(PERL_EMBED_LIBADD)
    CFLAGS += -DHAVE_LIBPERL_SUPPORT
    ifeq ($(CC_NO_CLANG), 0)
      CFLAGS += -Wno-compound-token-split-by-macro
    endif
    $(call detected,CONFIG_LIBPERL)
  endif
endif

ifeq ($(feature-timerfd), 1)
  CFLAGS += -DHAVE_TIMERFD_SUPPORT
else
  msg := $(warning No timerfd support. Disables 'perf kvm stat live');
endif

disable-python = $(eval $(disable-python_code))
define disable-python_code
  CFLAGS += -DNO_LIBPYTHON
  $(warning $1)
  NO_LIBPYTHON := 1
endef

PYTHON_EXTENSION_SUFFIX := '.so'
ifdef NO_LIBPYTHON
  $(call disable-python,Python support disabled by user)
else

  ifndef PYTHON
    $(call disable-python,No python interpreter was found: disables Python support - please install python-devel/python-dev)
  else
    PYTHON_WORD := $(call shell-wordify,$(PYTHON))

    ifndef PYTHON_CONFIG
      $(call disable-python,No 'python-config' tool was found: disables Python support - please install python-devel/python-dev)
    else

      ifneq ($(feature-libpython), 1)
        $(call disable-python,No 'Python.h' was found: disables Python support - please install python-devel/python-dev)
      else
         LDFLAGS += $(PYTHON_EMBED_LDFLAGS)
         EXTLIBS += $(PYTHON_EMBED_LIBADD)
         PYTHON_SETUPTOOLS_INSTALLED := $(shell $(PYTHON) -c 'import setuptools;' 2> /dev/null && echo "yes" || echo "no")
         ifeq ($(PYTHON_SETUPTOOLS_INSTALLED), yes)
           PYTHON_EXTENSION_SUFFIX := $(shell $(PYTHON) -c 'from importlib import machinery; print(machinery.EXTENSION_SUFFIXES[0])')
           LANG_BINDINGS += $(obj-perf)python/perf$(PYTHON_EXTENSION_SUFFIX)
	 else
           msg := $(warning Missing python setuptools, the python binding won't be built, please install python3-setuptools or equivalent);
         endif
         CFLAGS += -DHAVE_LIBPYTHON_SUPPORT
         $(call detected,CONFIG_LIBPYTHON)
      endif
    endif
  endif
endif

ifneq ($(NO_JEVENTS),1)
  ifeq ($(wildcard pmu-events/arch/$(SRCARCH)/mapfile.csv),)
    NO_JEVENTS := 1
  endif
endif
ifneq ($(NO_JEVENTS),1)
  NO_JEVENTS := 0
  ifndef PYTHON
    $(error ERROR: No python interpreter needed for jevents generation. Install python or build with NO_JEVENTS=1.)
  else
    # jevents.py uses f-strings present in Python 3.6 released in Dec. 2016.
    JEVENTS_PYTHON_GOOD := $(shell $(PYTHON) -c 'import sys;print("1" if(sys.version_info.major >= 3 and sys.version_info.minor >= 6) else "0")' 2> /dev/null)
    ifneq ($(JEVENTS_PYTHON_GOOD), 1)
      $(error ERROR: Python interpreter needed for jevents generation too old (older than 3.6). Install a newer python or build with NO_JEVENTS=1.)
    endif
  endif
endif

ifdef BUILD_NONDISTRO
  ifeq ($(feature-libbfd), 1)
    EXTLIBS += -lbfd -lopcodes
  else
    # we are on a system that requires -liberty and (maybe) -lz
    # to link against -lbfd; test each case individually here

    # call all detections now so we get correct
    # status in VF output
    $(call feature_check,libbfd-liberty)
    $(call feature_check,libbfd-liberty-z)

    ifeq ($(feature-libbfd-liberty), 1)
      EXTLIBS += -lbfd -lopcodes -liberty
      FEATURE_CHECK_LDFLAGS-disassembler-four-args += -liberty -ldl
      FEATURE_CHECK_LDFLAGS-disassembler-init-styled += -liberty -ldl
    else
      ifeq ($(feature-libbfd-liberty-z), 1)
        EXTLIBS += -lbfd -lopcodes -liberty -lz
        FEATURE_CHECK_LDFLAGS-disassembler-four-args += -liberty -lz -ldl
        FEATURE_CHECK_LDFLAGS-disassembler-init-styled += -liberty -lz -ldl
      endif
    endif
    $(call feature_check,disassembler-four-args)
    $(call feature_check,disassembler-init-styled)
  endif

  CFLAGS += -DHAVE_LIBBFD_SUPPORT
  CXXFLAGS += -DHAVE_LIBBFD_SUPPORT
  ifeq ($(feature-libbfd-buildid), 1)
    CFLAGS += -DHAVE_LIBBFD_BUILDID_SUPPORT
  else
    msg := $(warning Old version of libbfd/binutils things like PE executable profiling will not be available);
  endif
endif

ifndef NO_DEMANGLE
  $(call feature_check,cxa-demangle)
  ifeq ($(feature-cxa-demangle), 1)
    EXTLIBS += -lstdc++
    CFLAGS += -DHAVE_CXA_DEMANGLE_SUPPORT
    CXXFLAGS += -DHAVE_CXA_DEMANGLE_SUPPORT
    $(call detected,CONFIG_CXX_DEMANGLE)
  endif
  ifdef BUILD_NONDISTRO
    ifeq ($(filter -liberty,$(EXTLIBS)),)
      $(call feature_check,cplus-demangle)
      ifeq ($(feature-cplus-demangle), 1)
        EXTLIBS += -liberty
      endif
    endif
    ifneq ($(filter -liberty,$(EXTLIBS)),)
      CFLAGS += -DHAVE_CPLUS_DEMANGLE_SUPPORT
      CXXFLAGS += -DHAVE_CPLUS_DEMANGLE_SUPPORT
    endif
  endif
endif

ifndef NO_ZLIB
  ifeq ($(feature-zlib), 1)
    CFLAGS += -DHAVE_ZLIB_SUPPORT
    EXTLIBS += -lz
    $(call detected,CONFIG_ZLIB)
  else
    NO_ZLIB := 1
  endif
endif

ifndef NO_LZMA
  ifeq ($(feature-lzma), 1)
    CFLAGS += -DHAVE_LZMA_SUPPORT
    EXTLIBS += -llzma
    $(call detected,CONFIG_LZMA)
  else
    msg := $(warning No liblzma found, disables xz kernel module decompression, please install xz-devel/liblzma-dev);
    NO_LZMA := 1
  endif
endif

ifndef NO_LIBZSTD
  ifeq ($(feature-libzstd), 1)
    CFLAGS += -DHAVE_ZSTD_SUPPORT
    CFLAGS += $(LIBZSTD_CFLAGS)
    LDFLAGS += $(LIBZSTD_LDFLAGS)
    EXTLIBS += -lzstd
    $(call detected,CONFIG_ZSTD)
  else
    msg := $(warning No libzstd found, disables trace compression, please install libzstd-dev[el] and/or set LIBZSTD_DIR);
    NO_LIBZSTD := 1
  endif
endif

ifndef NO_LIBCAP
  ifeq ($(feature-libcap), 1)
    CFLAGS += -DHAVE_LIBCAP_SUPPORT
    EXTLIBS += -lcap
    $(call detected,CONFIG_LIBCAP)
  else
    msg := $(warning No libcap found, disables capability support, please install libcap-devel/libcap-dev);
    NO_LIBCAP := 1
  endif
endif

ifndef NO_BACKTRACE
  ifeq ($(feature-backtrace), 1)
    CFLAGS += -DHAVE_BACKTRACE_SUPPORT
  endif
endif

ifndef NO_LIBNUMA
  ifeq ($(feature-libnuma), 0)
    msg := $(warning No numa.h found, disables 'perf bench numa mem' benchmark, please install numactl-devel/libnuma-devel/libnuma-dev);
    NO_LIBNUMA := 1
  else
    ifeq ($(feature-numa_num_possible_cpus), 0)
      msg := $(warning Old numa library found, disables 'perf bench numa mem' benchmark, please install numactl-devel/libnuma-devel/libnuma-dev >= 2.0.8);
      NO_LIBNUMA := 1
    else
      CFLAGS += -DHAVE_LIBNUMA_SUPPORT
      EXTLIBS += -lnuma
      $(call detected,CONFIG_NUMA)
    endif
  endif
endif

ifdef HAVE_KVM_STAT_SUPPORT
    CFLAGS += -DHAVE_KVM_STAT_SUPPORT
endif

ifeq ($(feature-disassembler-four-args), 1)
    CFLAGS += -DDISASM_FOUR_ARGS_SIGNATURE
endif

ifeq ($(feature-disassembler-init-styled), 1)
    CFLAGS += -DDISASM_INIT_STYLED
endif

ifeq (${IS_64_BIT}, 1)
  ifndef NO_PERF_READ_VDSO32
    $(call feature_check,compile-32)
    ifeq ($(feature-compile-32), 1)
      CFLAGS += -DHAVE_PERF_READ_VDSO32
    else
      NO_PERF_READ_VDSO32 := 1
    endif
  endif
  ifneq ($(SRCARCH), x86)
    NO_PERF_READ_VDSOX32 := 1
  endif
  ifndef NO_PERF_READ_VDSOX32
    $(call feature_check,compile-x32)
    ifeq ($(feature-compile-x32), 1)
      CFLAGS += -DHAVE_PERF_READ_VDSOX32
    else
      NO_PERF_READ_VDSOX32 := 1
    endif
  endif
else
  NO_PERF_READ_VDSO32 := 1
  NO_PERF_READ_VDSOX32 := 1
endif

ifndef NO_LIBBABELTRACE
  $(call feature_check,libbabeltrace)
  ifeq ($(feature-libbabeltrace), 1)
    CFLAGS += -DHAVE_LIBBABELTRACE_SUPPORT $(LIBBABELTRACE_CFLAGS)
    LDFLAGS += $(LIBBABELTRACE_LDFLAGS)
    EXTLIBS += -lbabeltrace-ctf
    $(call detected,CONFIG_LIBBABELTRACE)
  else
    msg := $(warning No libbabeltrace found, disables 'perf data' CTF format support, please install libbabeltrace-dev[el]/libbabeltrace-ctf-dev);
  endif
endif

ifndef NO_AUXTRACE
  ifeq ($(SRCARCH),x86)
    ifeq ($(feature-get_cpuid), 0)
      msg := $(warning Your gcc lacks the __get_cpuid() builtin, disables support for auxtrace/Intel PT, please install a newer gcc);
      NO_AUXTRACE := 1
    endif
  endif
  ifndef NO_AUXTRACE
    $(call detected,CONFIG_AUXTRACE)
    CFLAGS += -DHAVE_AUXTRACE_SUPPORT
    ifeq ($(feature-reallocarray), 0)
      CFLAGS += -DCOMPAT_NEED_REALLOCARRAY
    endif
  endif
endif

ifdef EXTRA_TESTS
    $(call detected,CONFIG_EXTRA_TESTS)
    CFLAGS += -DHAVE_EXTRA_TESTS
endif

ifndef NO_JVMTI
  ifneq (,$(wildcard /usr/sbin/update-java-alternatives))
    JDIR=$(shell /usr/sbin/update-java-alternatives -l | head -1 | awk '{print $$3}')
  else
    ifneq (,$(wildcard /usr/sbin/alternatives))
      JDIR=$(shell /usr/sbin/alternatives --display java | tail -1 | cut -d' ' -f 5 | sed -e 's%/jre/bin/java.%%g' -e 's%/bin/java.%%g')
    endif
  endif
  ifndef JDIR
    $(warning No alternatives command found, you need to set JDIR= to point to the root of your Java directory)
    NO_JVMTI := 1
  endif
endif

ifndef NO_JVMTI
  FEATURE_CHECK_CFLAGS-jvmti := -I$(JDIR)/include -I$(JDIR)/include/linux
  $(call feature_check,jvmti)
  ifeq ($(feature-jvmti), 1)
    $(call detected_var,JDIR)
    ifndef NO_JVMTI_CMLR
      FEATURE_CHECK_CFLAGS-jvmti-cmlr := $(FEATURE_CHECK_CFLAGS-jvmti)
      $(call feature_check,jvmti-cmlr)
      ifeq ($(feature-jvmti-cmlr), 1)
        CFLAGS += -DHAVE_JVMTI_CMLR
      endif
    endif # NO_JVMTI_CMLR
  else
    $(warning No openjdk development package found, please install JDK package, e.g. openjdk-8-jdk, java-1.8.0-openjdk-devel)
    NO_JVMTI := 1
  endif
endif

ifndef NO_LIBPFM4
  $(call feature_check,libpfm4)
  ifeq ($(feature-libpfm4), 1)
    CFLAGS += -DHAVE_LIBPFM
    EXTLIBS += -lpfm
    ASCIIDOC_EXTRA = -aHAVE_LIBPFM=1
    $(call detected,CONFIG_LIBPFM4)
  else
    msg := $(warning libpfm4 not found, disables libpfm4 support. Please install libpfm4-dev);
  endif
endif

# libtraceevent is a recommended dependency picked up from the system.
ifneq ($(NO_LIBTRACEEVENT),1)
  $(call feature_check,libtraceevent)
  ifeq ($(feature-libtraceevent), 1)
    CFLAGS += -DHAVE_LIBTRACEEVENT
    EXTLIBS += -ltraceevent
    LIBTRACEEVENT_VERSION := $(shell $(PKG_CONFIG) --modversion libtraceevent)
    LIBTRACEEVENT_VERSION_1 := $(word 1, $(subst ., ,$(LIBTRACEEVENT_VERSION)))
    LIBTRACEEVENT_VERSION_2 := $(word 2, $(subst ., ,$(LIBTRACEEVENT_VERSION)))
    LIBTRACEEVENT_VERSION_3 := $(word 3, $(subst ., ,$(LIBTRACEEVENT_VERSION)))
    LIBTRACEEVENT_VERSION_CPP := $(shell expr $(LIBTRACEEVENT_VERSION_1) \* 255 \* 255 + $(LIBTRACEEVENT_VERSION_2) \* 255 + $(LIBTRACEEVENT_VERSION_3))
    CFLAGS += -DLIBTRACEEVENT_VERSION=$(LIBTRACEEVENT_VERSION_CPP)
    $(call detected,CONFIG_LIBTRACEEVENT)
  else
    dummy := $(error ERROR: libtraceevent is missing. Please install libtraceevent-dev/libtraceevent-devel or build with NO_LIBTRACEEVENT=1)
  endif

  $(call feature_check,libtracefs)
  ifeq ($(feature-libtracefs), 1)
    EXTLIBS += -ltracefs
    LIBTRACEFS_VERSION := $(shell $(PKG_CONFIG) --modversion libtracefs)
    LIBTRACEFS_VERSION_1 := $(word 1, $(subst ., ,$(LIBTRACEFS_VERSION)))
    LIBTRACEFS_VERSION_2 := $(word 2, $(subst ., ,$(LIBTRACEFS_VERSION)))
    LIBTRACEFS_VERSION_3 := $(word 3, $(subst ., ,$(LIBTRACEFS_VERSION)))
    LIBTRACEFS_VERSION_CPP := $(shell expr $(LIBTRACEFS_VERSION_1) \* 255 \* 255 + $(LIBTRACEFS_VERSION_2) \* 255 + $(LIBTRACEFS_VERSION_3))
    CFLAGS += -DLIBTRACEFS_VERSION=$(LIBTRACEFS_VERSION_CPP)
  endif
endif

# Among the variables below, these:
#   perfexecdir
#   libbpf_include_dir
#   perf_examples_dir
#   template_dir
#   mandir
#   infodir
#   htmldir
#   ETC_PERFCONFIG (but not sysconfdir)
# can be specified as a relative path some/where/else;
# this is interpreted as relative to $(prefix) and "perf" at
# runtime figures out where they are based on the path to the executable.
# This can help installing the suite in a relocatable way.

# Make the path relative to DESTDIR, not to prefix
ifndef DESTDIR
prefix ?= $(HOME)
endif
bindir_relative = bin
bindir = $(abspath $(prefix)/$(bindir_relative))
includedir_relative = include
includedir = $(abspath $(prefix)/$(includedir_relative))
mandir = share/man
infodir = share/info
perfexecdir = libexec/perf-core
# FIXME: system's libbpf header directory, where we expect to find bpf/bpf_helpers.h, for instance
libbpf_include_dir = /usr/include
perf_examples_dir = lib/perf/examples
sharedir = $(prefix)/share
template_dir = share/perf-core/templates
STRACE_GROUPS_DIR = share/perf-core/strace/groups
htmldir = share/doc/perf-doc
tipdir = share/doc/perf-tip
srcdir = $(srctree)/tools/perf
ifeq ($(prefix),/usr)
sysconfdir = /etc
ETC_PERFCONFIG = $(sysconfdir)/perfconfig
else
sysconfdir = $(prefix)/etc
ETC_PERFCONFIG = etc/perfconfig
endif
ifndef lib
ifeq ($(SRCARCH)$(IS_64_BIT), x861)
lib = lib64
else
lib = lib
endif
endif # lib
libdir = $(prefix)/$(lib)

# Shell quote (do not use $(call) to accommodate ancient setups);
ETC_PERFCONFIG_SQ = $(subst ','\'',$(ETC_PERFCONFIG))
STRACE_GROUPS_DIR_SQ = $(subst ','\'',$(STRACE_GROUPS_DIR))
DESTDIR_SQ = $(subst ','\'',$(DESTDIR))
bindir_SQ = $(subst ','\'',$(bindir))
includedir_SQ = $(subst ','\'',$(includedir))
mandir_SQ = $(subst ','\'',$(mandir))
infodir_SQ = $(subst ','\'',$(infodir))
perfexecdir_SQ = $(subst ','\'',$(perfexecdir))
libbpf_include_dir_SQ = $(subst ','\'',$(libbpf_include_dir))
perf_examples_dir_SQ = $(subst ','\'',$(perf_examples_dir))
template_dir_SQ = $(subst ','\'',$(template_dir))
htmldir_SQ = $(subst ','\'',$(htmldir))
tipdir_SQ = $(subst ','\'',$(tipdir))
prefix_SQ = $(subst ','\'',$(prefix))
sysconfdir_SQ = $(subst ','\'',$(sysconfdir))
libdir_SQ = $(subst ','\'',$(libdir))
srcdir_SQ = $(subst ','\'',$(srcdir))

ifneq ($(filter /%,$(firstword $(perfexecdir))),)
perfexec_instdir = $(perfexecdir)
perf_include_instdir = $(libbpf_include_dir)
perf_examples_instdir = $(perf_examples_dir)
STRACE_GROUPS_INSTDIR = $(STRACE_GROUPS_DIR)
tip_instdir = $(tipdir)
else
perfexec_instdir = $(prefix)/$(perfexecdir)
perf_include_instdir = $(prefix)/$(libbpf_include_dir)
perf_examples_instdir = $(prefix)/$(perf_examples_dir)
STRACE_GROUPS_INSTDIR = $(prefix)/$(STRACE_GROUPS_DIR)
tip_instdir = $(prefix)/$(tipdir)
endif
perfexec_instdir_SQ = $(subst ','\'',$(perfexec_instdir))
perf_include_instdir_SQ = $(subst ','\'',$(perf_include_instdir))
perf_examples_instdir_SQ = $(subst ','\'',$(perf_examples_instdir))
STRACE_GROUPS_INSTDIR_SQ = $(subst ','\'',$(STRACE_GROUPS_INSTDIR))
tip_instdir_SQ = $(subst ','\'',$(tip_instdir))

export perfexec_instdir_SQ

print_var = $(eval $(print_var_code)) $(info $(MSG))
define print_var_code
    MSG = $(shell printf '...%40s: %s' $(1) $($(1)))
endef

ifeq ($(feature_display),1)
  $(call feature_display_entries)
endif

ifeq ($(VF),1)
  # Display EXTRA features which are detected manualy
  # from here with feature_check call and thus cannot
  # be partof global state output.
  $(foreach feat,$(FEATURE_TESTS_EXTRA),$(call feature_print_status,$(feat),) $(info $(MSG)))
  $(call print_var,prefix)
  $(call print_var,bindir)
  $(call print_var,libdir)
  $(call print_var,sysconfdir)
  $(call print_var,LIBUNWIND_DIR)
  $(call print_var,LIBDW_DIR)
  $(call print_var,JDIR)

  ifeq ($(dwarf-post-unwind),1)
    $(call feature_print_text,"DWARF post unwind library", $(dwarf-post-unwind-text)) $(info $(MSG))
  endif
endif

$(info )

$(call detected_var,bindir_SQ)
$(call detected_var,PYTHON_WORD)
ifneq ($(OUTPUT),)
$(call detected_var,OUTPUT)
endif
$(call detected_var,htmldir_SQ)
$(call detected_var,infodir_SQ)
$(call detected_var,mandir_SQ)
$(call detected_var,ETC_PERFCONFIG_SQ)
$(call detected_var,STRACE_GROUPS_DIR_SQ)
$(call detected_var,prefix_SQ)
$(call detected_var,perfexecdir_SQ)
$(call detected_var,libbpf_include_dir_SQ)
$(call detected_var,perf_examples_dir_SQ)
$(call detected_var,tipdir_SQ)
$(call detected_var,srcdir_SQ)
$(call detected_var,LIBDIR)
$(call detected_var,GTK_CFLAGS)
$(call detected_var,PERL_EMBED_CCOPTS)
$(call detected_var,PYTHON_EMBED_CCOPTS)
ifneq ($(BISON_FILE_PREFIX_MAP),)
$(call detected_var,BISON_FILE_PREFIX_MAP)
endif

# re-generate FEATURE-DUMP as we may have called feature_check, found out
# extra libraries to add to LDFLAGS of some other test and then redo those
# tests, see the block about libbfd, disassembler-four-args, for instance.
$(shell rm -f $(FEATURE_DUMP_FILENAME))
$(foreach feat,$(FEATURE_TESTS),$(shell echo "$(call feature_assign,$(feat))" >> $(FEATURE_DUMP_FILENAME)))