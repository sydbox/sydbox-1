AM_MAKEFLAGS= --no-print-directory

CARGO_VERBOSE = $(cargo_verbose_$(V))
cargo_verbose_ = $(cargo_verbose_$(AM_DEFAULT_VERBOSITY))
cargo_verbose_0 =
cargo_verbose_1 = --verbose
if SYDBOX_CARGO_RELEASE
CARGO_FLAGS= $(CARGO_VERBOSE) --$(SYDBOX_CARGO_RELEASE_TYPE)
else
CARGO_FLAGS= $(CARGO_VERBOSE)
endif

check-local:
	CARGO_TARGET_DIR=sydbox_rs $(CARGO) test $(CARGO_FLAGS)
clean-local:
	CARGO_TARGET_DIR=sydbox_rs $(CARGO) clean
install-exec-local:
	CARGO_TARGET_DIR=sydbox_rs $(CARGO) install \
			 --path=. \
			 --root="$(DESTDIR)/usr/$(target_triplet)"
	rm -f $(DESTDIR)/usr/$(target_triplet)/.crates.toml
	rm -f $(DESTDIR)/usr/$(target_triplet)/.crates2.json

target/$(SYDBOX_CARGO_RELEASE_TYPE)/pandora: jobs main.rs
	@mkdir -m700 -p $(builddir)/sydbox_rs
	$(AM_V_GEN)
	$(AM_V_at)$(CARGO) build -j $(JOB_COUNT) $(CARGO_BUILD_FLAGS)

all: target/$(SYDBOX_CARGO_RELEASE_TYPE)/pandora

.PHONY: jobs
jobs: | parallel; @echo >&2 "[0;1;31;91msydb☮x: Make is running $(JOB_COUNT) jobs.[0m"

.PHONY: parallel
parallel: .parallel ; @$(eval JOB_COUNT := $(shell sort -n $< | tail -n 1))
.parallel: FORCE ; @$(MAKE) --no-print-directory par 2>/dev/null >$@ || true
FORCE:

to_n = $(words $2) $(if $(filter-out $1,$(words x $2)),$(call to_n,$1,x $2))

PAR_COUNT :=
par: $(addprefix par-,$(call to_n,32))
par-%: ; @$(eval PAR_COUNT += x)@echo $(words $(PAR_COUNT)) && sleep 1 && false
