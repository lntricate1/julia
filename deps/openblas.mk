## OpenBLAS ##
ifneq ($(USE_BINARYBUILDER_OPENBLAS), 1)
# LAPACK is built into OpenBLAS by default
OPENBLAS_GIT_URL := https://github.com/xianyi/OpenBLAS.git
OPENBLAS_TAR_URL = https://api.github.com/repos/xianyi/OpenBLAS/tarball/$1
$(eval $(call git-external,openblas,OPENBLAS,,,$(BUILDDIR)))

OPENBLAS_BUILD_OPTS := CC="$(CC) $(SANITIZE_OPTS)" FC="$(FC) $(SANITIZE_OPTS)" LD="$(LD) $(SANITIZE_LDFLAGS)" RANLIB="$(RANLIB)" BINARY=$(BINARY)

# Thread support
ifeq ($(OPENBLAS_USE_THREAD), 1)
OPENBLAS_BUILD_OPTS += USE_THREAD=1
OPENBLAS_BUILD_OPTS += GEMM_MULTITHREADING_THRESHOLD=400
# Maximum number of threads for parallelism
OPENBLAS_BUILD_OPTS += NUM_THREADS=512
else
OPENBLAS_BUILD_OPTS += USE_THREAD=0
endif

# don't touch scheduler affinity since we manage this ourselves
OPENBLAS_BUILD_OPTS += NO_AFFINITY=1

# Build for all architectures - required for distribution
ifeq ($(SANITIZE_MEMORY),1)
OPENBLAS_BUILD_OPTS += TARGET=GENERIC
else
OPENBLAS_BUILD_OPTS += TARGET=$(OPENBLAS_TARGET_ARCH)
ifeq ($(OPENBLAS_DYNAMIC_ARCH), 1)
OPENBLAS_BUILD_OPTS += DYNAMIC_ARCH=1
endif
endif

# 64-bit BLAS interface
ifeq ($(USE_BLAS64), 1)
OPENBLAS_BUILD_OPTS += INTERFACE64=1 SYMBOLSUFFIX="$(OPENBLAS_SYMBOLSUFFIX)" LIBPREFIX="libopenblas$(OPENBLAS_LIBNAMESUFFIX)"
ifeq ($(OS), Darwin)
OPENBLAS_BUILD_OPTS += OBJCONV=$(abspath $(build_depsbindir)/objconv)
$(BUILDDIR)/$(OPENBLAS_SRC_DIR)/build-compiled: | $(build_prefix)/manifest/objconv
endif
endif

OPENBLAS_FFLAGS := $(JFFLAGS) $(USE_BLAS_FFLAGS)
OPENBLAS_CFLAGS := -O2

# Decide whether to build for 32-bit or 64-bit arch
ifneq ($(XC_HOST),)
OPENBLAS_BUILD_OPTS += OSNAME=$(OS) CROSS=1 HOSTCC=$(HOSTCC) CROSS_SUFFIX=$(CROSS_COMPILE)
endif
ifeq ($(OS),WINNT)
ifneq ($(ARCH),x86_64)
ifneq ($(USECLANG),1)
OPENBLAS_CFLAGS += -mincoming-stack-boundary=2
endif
OPENBLAS_FFLAGS += -mincoming-stack-boundary=2
endif
endif

# Work around invalid register errors on 64-bit Windows
# See discussion in https://github.com/xianyi/OpenBLAS/issues/1708
# TODO: Remove this once we use a version of OpenBLAS where this is set automatically
ifeq ($(OS),WINNT)
ifeq ($(ARCH),x86_64)
OPENBLAS_CFLAGS += -fno-asynchronous-unwind-tables
endif
endif

OPENBLAS_BUILD_OPTS += CFLAGS="$(CFLAGS) $(OPENBLAS_CFLAGS)"
OPENBLAS_BUILD_OPTS += FFLAGS="$(FFLAGS) $(OPENBLAS_FFLAGS)"
OPENBLAS_BUILD_OPTS += LDFLAGS="$(LDFLAGS) $(RPATH_ESCAPED_ORIGIN)"

# Debug OpenBLAS
ifeq ($(OPENBLAS_DEBUG), 1)
OPENBLAS_BUILD_OPTS += DEBUG=1
endif

# Allow disabling AVX for older binutils
ifeq ($(OPENBLAS_NO_AVX), 1)
OPENBLAS_BUILD_OPTS += NO_AVX=1 NO_AVX2=1 NO_AVX512=1
else ifeq ($(OPENBLAS_NO_AVX2), 1)
OPENBLAS_BUILD_OPTS += NO_AVX2=1 NO_AVX512=1
else ifeq ($(OPENBLAS_NO_AVX512), 1)
OPENBLAS_BUILD_OPTS += NO_AVX512=1
endif

# Do not overwrite the "-j" flag
OPENBLAS_BUILD_OPTS += MAKE_NB_JOBS=0

$(BUILDDIR)/$(OPENBLAS_SRC_DIR)/openblas-winexit.patch-applied: $(BUILDDIR)/$(OPENBLAS_SRC_DIR)/source-extracted
	cd $(BUILDDIR)/$(OPENBLAS_SRC_DIR) && \
		patch -p1 -f < $(SRCDIR)/patches/openblas-winexit.patch
	echo 1 > $@

$(BUILDDIR)/$(OPENBLAS_SRC_DIR)/openblas-ofast-power.patch-applied: $(BUILDDIR)/$(OPENBLAS_SRC_DIR)/openblas-winexit.patch-applied
	cd $(BUILDDIR)/$(OPENBLAS_SRC_DIR) && \
		patch -p1 -f < $(SRCDIR)/patches/openblas-ofast-power.patch
	echo 1 > $@

$(BUILDDIR)/$(OPENBLAS_SRC_DIR)/build-configured: $(BUILDDIR)/$(OPENBLAS_SRC_DIR)/openblas-ofast-power.patch-applied
	echo 1 > $@

$(BUILDDIR)/$(OPENBLAS_SRC_DIR)/build-compiled: $(BUILDDIR)/$(OPENBLAS_SRC_DIR)/build-configured
	echo $(MAKE) -C $(dir $<) $(OPENBLAS_BUILD_OPTS) # echo first, so we only print the error message below in a failure case
	@$(MAKE) -C $(dir $<) $(OPENBLAS_BUILD_OPTS) || (echo $(WARNCOLOR)"*** Clean the OpenBLAS build with 'make -C deps clean-openblas'. Rebuild with 'make OPENBLAS_USE_THREAD=0' if OpenBLAS had trouble linking libpthread.so, and with 'make OPENBLAS_TARGET_ARCH=NEHALEM' if there were errors building SandyBridge support. Both these options can also be used simultaneously. ***"$(ENDCOLOR) && false)
	echo 1 > $@

define OPENBLAS_INSTALL
	$(call SHLIBFILE_INSTALL,$1,$2,$3)
ifeq ($$(OS), Linux)
	ln -sf libopenblas$$(OPENBLAS_LIBNAMESUFFIX).$$(SHLIB_EXT) $2/$$(build_libdir)/libopenblas$$(OPENBLAS_LIBNAMESUFFIX).$$(SHLIB_EXT).0
endif
endef
$(eval $(call staged-install, \
	openblas,$(OPENBLAS_SRC_DIR), \
	OPENBLAS_INSTALL,$(BUILDDIR)/$(OPENBLAS_SRC_DIR)/$(LIBBLASNAME).$(SHLIB_EXT),, \
	$$(INSTALL_NAME_CMD)libopenblas$$(OPENBLAS_LIBNAMESUFFIX).$$(SHLIB_EXT) $$(build_shlibdir)/libopenblas$$(OPENBLAS_LIBNAMESUFFIX).$$(SHLIB_EXT)))

clean-openblas:
	-rm -f $(BUILDDIR)/$(OPENBLAS_SRC_DIR)/build-compiled
	-$(MAKE) -C $(BUILDDIR)/$(OPENBLAS_SRC_DIR) clean


get-openblas: $(OPENBLAS_SRC_FILE)
extract-openblas: $(BUILDDIR)/$(OPENBLAS_SRC_DIR)/source-extracted
configure-openblas: $(BUILDDIR)/$(OPENBLAS_SRC_DIR)/build-configured
compile-openblas: $(BUILDDIR)/$(OPENBLAS_SRC_DIR)/build-compiled
fastcheck-openblas: check-openblas
check-openblas: compile-openblas


## Mac gfortran BLAS wrapper ##
ifeq ($(OS),Darwin)
$(BUILDDIR)/libgfortblas.$(SHLIB_EXT): $(SRCDIR)/gfortblas.c $(SRCDIR)/gfortblas.alias
	$(CC) -Wall -O3 $(CPPFLAGS) $(CFLAGS) $(fPIC) -shared $< -o $@ -pipe \
				-Wl,-reexport_framework,Accelerate -Wl,-alias_list,$(SRCDIR)/gfortblas.alias

$(build_shlibdir)/libgfortblas.$(SHLIB_EXT): $(BUILDDIR)/libgfortblas.$(SHLIB_EXT)
	cp -f $< $@
	$(INSTALL_NAME_CMD)libgfortblas.$(SHLIB_EXT) $@
endif


## LAPACK ##

LAPACK_MFLAGS := NOOPT="$(FFLAGS) $(JFFLAGS) $(USE_BLAS_FFLAGS) -O0" \
    OPTS="$(FFLAGS) $(JFFLAGS) $(USE_BLAS_FFLAGS)" FORTRAN="$(FC)" \
    LOADER="$(FC)" BLASLIB="$(RPATH_ESCAPED_ORIGIN) $(LIBBLAS)"

$(SRCCACHE)/lapack-$(LAPACK_VER).tgz: | $(SRCCACHE)
	$(JLDOWNLOAD) $@ https://www.netlib.org/lapack/$(notdir $@)

$(BUILDDIR)/lapack-$(LAPACK_VER)/source-extracted: $(SRCCACHE)/lapack-$(LAPACK_VER).tgz
	$(JLCHECKSUM) $<
	mkdir -p $(BUILDDIR)
	cd $(BUILDDIR) && $(TAR) -zxf $<
	cp $(dir $@)INSTALL/make.inc.gfortran $(dir $@)make.inc
	echo 1 > $@

checksum-lapack: $(SRCCACHE)/lapack-$(LAPACK_VER).tgz
	$(JLCHECKSUM) $<

ifeq ($(USE_SYSTEM_BLAS), 0)
$(BUILDDIR)/lapack-$(LAPACK_VER)/build-compiled0: | $(build_prefix)/manifest/openblas
else ifeq ($(OS),Darwin)
$(BUILDDIR)/lapack-$(LAPACK_VER)/build-compiled0: | $(build_shlibdir)/libgfortblas.$(SHLIB_EXT)
endif
$(BUILDDIR)/lapack-$(LAPACK_VER)/build-compiled0: $(BUILDDIR)/lapack-$(LAPACK_VER)/source-extracted
	$(MAKE) -C $(dir $@) lapacklib $(LAPACK_MFLAGS)
	echo 1 > $@

$(BUILDDIR)/lapack-$(LAPACK_VER)/build-checked: $(BUILDDIR)/lapack-$(LAPACK_VER)/build-compiled0
ifeq ($(BUILD_OS),$(OS))
	$(MAKE) -C $(dir $@) lapack_testing $(LAPACK_MFLAGS) -k
endif
	echo 1 > $@

$(BUILDDIR)/lapack-$(LAPACK_VER)/build-compiled: $(BUILDDIR)/lapack-$(LAPACK_VER)/build-compiled0 | $(build_prefix)/manifest
	$(FC) -shared $(FFLAGS) $(JFFLAGS) $(dir $<)/SRC/*.o \
		$(dir $<)/INSTALL/dlamch.o $(dir $<)/INSTALL/dsecnd_INT_ETIME.o \
		$(dir $<)/INSTALL/ilaver.o $(dir $<)/INSTALL/slamch.o $(LIBBLAS) \
		-o $(dir $<)/liblapack.$(SHLIB_EXT)
	echo 1 > $@

$(eval $(call staged-install, \
	lapack,lapack-$(LAPACK_VER), \
	SHLIBFILE_INSTALL,$(BUILDDIR)/lapack-$(LAPACK_VER)/liblapack.$(SHLIB_EXT),, \
	$$(INSTALL_NAME_CMD)liblapack.$$(SHLIB_EXT) $$(build_shlibdir)/liblapack.$$(SHLIB_EXT)))

clean-lapack:
	-rm -f $(BUILDDIR)/lapack-$(LAPACK_VER)/build-compiled0 $(BUILDDIR)/lapack-$(LAPACK_VER)/build-compiled
	-$(MAKE) -C $(BUILDDIR)/lapack-$(LAPACK_VER) clean

distclean-lapack:
	rm -rf $(SRCCACHE)/lapack-$(LAPACK_VER).tgz $(BUILDDIR)/lapack-$(LAPACK_VER)


get-lapack: $(SRCCACHE)/lapack-$(LAPACK_VER).tgz
extract-lapack: $(BUILDDIR)/lapack-$(LAPACK_VER)/source-extracted
configure-lapack: extract-lapack
compile-lapack: $(BUILDDIR)/lapack-$(LAPACK_VER)/build-compiled
fastcheck-lapack: check-lapack
check-lapack: $(BUILDDIR)/lapack-$(LAPACK_VER)/build-checked

else # USE_BINARYBUILDER_OPENBLAS

$(eval $(call bb-install,openblas,OPENBLAS,true))
get-lapack: get-openblas
extract-lapack: extract-openblas
configure-lapack: configure-openblas
compile-lapack: compile-openblas
fastcheck-lapack: fastcheck-openblas
check-lapack: check-openblas
clean-lapack: clean-openblas
distclean-lapack: distclean-openblas
install-lapack: install-openblas
endif
