# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

ifeq ("$(origin V)", "command line")
VERBOSE = $(V)
endif
ifndef VERBOSE
VERBOSE = 0
endif

ifeq ($(VERBOSE),0)
MAKEFLAGS += --no-print-directory
Q = @
endif

LESSONS = server client
LESSONS_CLEAN = $(addsuffix _clean,$(LESSONS))

TOOLS = tools/stats
TOOLS_CLEAN = $(addsuffix _clean,$(TOOLS))

.PHONY: clean clobber distclean $(LESSONS) $(LESSONS_CLEAN) $(TOOLS) $(TOOLS_CLEAN)

all: lib $(LESSONS) $(TOOLS)
clean: $(LESSONS_CLEAN) $(TOOLS_CLEAN)
	@echo; echo common; $(MAKE) -C common clean
	@echo; echo lib; $(MAKE) -C lib clean

lib: config.mk check_submodule
	@echo; echo $@; $(MAKE) -C $@

$(LESSONS):
	@echo; echo $@; $(MAKE) -C $@

$(LESSONS_CLEAN):
	@echo; echo $@; $(MAKE) -C $(subst _clean,,$@) clean

$(TOOLS):
	@echo; echo $@; $(MAKE) -C $@

$(TOOLS_CLEAN):
	@echo; echo $@; $(MAKE) -C $(subst _clean,,$@) clean

config.mk: configure
	@sh configure

clobber:
	@touch config.mk
	$(Q)$(MAKE) clean
	$(Q)rm -f config.mk

distclean:	clobber

check_submodule:
	@if [ -d .git ] && `git submodule status lib/libbpf | grep -q '^+'`; then \
		echo "" ;\
		echo "** WARNING **: git submodule SHA-1 out-of-sync" ;\
		echo " consider running: git submodule update"  ;\
		echo "" ;\
	fi\
