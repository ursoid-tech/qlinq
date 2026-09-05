# Makefile for qlinq
.DEFAULT_GOAL := all

CC = gcc
ARCH = $(shell uname -m)
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
  ifeq ($(origin AR),default)
    AR := $(shell xcrun -find ar 2>/dev/null || echo ar)
  endif
  OPENSSL_PREFIX ?= $(shell brew --prefix openssl@3 2>/dev/null || brew --prefix openssl 2>/dev/null || echo /opt/homebrew/opt/openssl)
  OPENSSL_CFLAGS ?= $(shell pkg-config --cflags openssl 2>/dev/null || echo -I$(OPENSSL_PREFIX)/include)
  OPENSSL_LIBS   ?= $(shell pkg-config --libs openssl 2>/dev/null || echo -L$(OPENSSL_PREFIX)/lib -lcrypto -lssl)
  INCLUDES_OPENSSL = $(OPENSSL_CFLAGS)
  LDFLAGS = $(OPENSSL_LIBS) -lpthread -ldl -lm
else
  INCLUDES_OPENSSL =
  LDFLAGS = -lpthread -lrt -ldl -lm -lcrypto -lssl
endif

# Default CFLAGS for our code
CFLAGS ?= -O2
CFLAGS_COMMON = -Wvla -Wall -Wextra -std=c11 -g -D_GNU_SOURCE -D_DEFAULT_SOURCE -DPATHFLOW_ARENA_SIZE=65536
# CODEC_TARGET=portable disables native nanorq/shared OBL targeting.
# Keep explicit FEC_NATIVE_CFLAGS and NANORQ_NATIVE_CFLAGS overrides supported.
CODEC_TARGET ?= native
ifneq ($(CODEC_TARGET),native)
ifneq ($(CODEC_TARGET),portable)
$(error CODEC_TARGET must be native or portable)
endif
endif
FEC_CFLAGS ?= -O3 -funroll-loops -ftree-vectorize
FEC_NATIVE_CFLAGS ?=
NANORQ_NATIVE_CFLAGS ?= $(if $(filter native,$(CODEC_TARGET)),-march=native)
# Quicly's encoder capacity helpers intentionally perform arithmetic from a
# null base pointer. Exclude that one UBSan check while retaining ASan and all
# other undefined-behavior checks across qlinq and its linked dependencies.
SANITIZER_FLAGS = -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize=pointer-overflow
# Quicly is included with -isystem to keep third-party warnings out of qlinq's
# build. Use -MD (rather than -MMD) so ABI-affecting Quicly and picotls headers
# are still tracked as dependencies.
DEPFLAGS = -MD -MP

# Compile Fusion only when this compiler accepts its ISA and runtime guards.
# All transport code remains generic; the ISA flags apply only to fusion.o.
FUSION_CFLAGS = -mavx2 -maes -mpclmul -mvaes -mvpclmulqdq
ifndef WITH_FUSION
WITH_FUSION := $(shell printf '%s\n' '#include <immintrin.h>' \
  'int main(void) { __m256i x = _mm256_setzero_si256(); x = _mm256_aesenc_epi128(x, x); x = _mm256_clmulepi64_epi128(x, x, 0); return _mm_extract_epi64(_mm256_castsi256_si128(x), 0) + (__builtin_cpu_supports("avx2") && __builtin_cpu_supports("aes") && __builtin_cpu_supports("pclmul") && __builtin_cpu_supports("vaes") && __builtin_cpu_supports("vpclmulqdq")); }' \
  | $(CC) $(CFLAGS) $(FUSION_CFLAGS) -x c -c -o /dev/null - >/dev/null 2>&1 && echo 1 || echo 0)
endif
ifneq ($(WITH_FUSION),0)
ifneq ($(WITH_FUSION),1)
$(error WITH_FUSION must be 0 or 1)
endif
endif

# Include paths: use -isystem for quicly and picotls to suppress warning headers
INCLUDES = -Isrc/common -Ideps/nanors -Ideps/nanors/deps/obl -Ideps/nanorq/include -Ideps/nanorq/deps -Ideps/pathflow -Ideps/pathflow/solvers -isystem deps/quicly/include -isystem deps/quicly/deps/picotls/include -Ideps/quicly/deps/klib $(INCLUDES_OPENSSL)

QUICLY_SRCS = deps/quicly/lib/quicly.c \
              deps/quicly/lib/bplus_ranges.c \
              deps/quicly/lib/flexicast.c \
              deps/quicly/lib/flexicast_cc.c \
              deps/quicly/lib/flexicast_cc_multicast.c \
              deps/quicly/lib/flexicast_cc_adaptive.c \
              deps/quicly/lib/defaults.c \
              deps/quicly/lib/frame.c \
              deps/quicly/lib/local_cid.c \
              deps/quicly/lib/loss.c \
              deps/quicly/lib/ranges.c \
              deps/quicly/lib/rate.c \
              deps/quicly/lib/recvstate.c \
              deps/quicly/lib/remote_cid.c \
              deps/quicly/lib/sendstate.c \
              deps/quicly/lib/sentmap.c \
              deps/quicly/lib/streambuf.c \
              deps/quicly/lib/cc-cubic.c \
              deps/quicly/lib/cc-pico.c \
              deps/quicly/deps/picotls/lib/picotls.c \
              deps/quicly/deps/picotls/lib/openssl.c \
              deps/quicly/deps/picotls/lib/pembase64.c \
              deps/quicly/deps/picotls/lib/hpke.c \
              deps/quicly/deps/picotls/lib/asn1.c

ifeq ($(WITH_FUSION),1)
QUICLY_SRCS += deps/quicly/deps/picotls/lib/fusion.c
src/common/transport_tls.o t/00util/test_crypto_backend.o: private CFLAGS_COMMON += -DQLINQ_WITH_FUSION=1
endif

NANORQ_SRCS = deps/nanorq/lib/chooser.c \
              deps/nanorq/lib/nanorq_core.c \
              deps/nanorq/lib/ops.c \
              deps/nanorq/lib/params.c \
              deps/nanorq/lib/precode.c \
              deps/nanorq/lib/rand.c \
              deps/nanorq/lib/tuple.c \
              deps/nanorq/lib/uvec.c

PATHFLOW_SRCS = deps/pathflow/pathflow.c

IFMON_SRCS = src/common/ifmon.c

QUICLY_OBJS = $(QUICLY_SRCS:.c=.o)
NANORQ_OBJS = $(NANORQ_SRCS:.c=.o)
# nanorq shares linked obl kernels with nanors
NANORQ_CODEC_OBJS = $(NANORQ_OBJS) deps/nanors/deps/obl/oblas_common.o \
                   deps/nanors/deps/obl/oblas_lite.o
PATHFLOW_OBJS = $(PATHFLOW_SRCS:.c=.o)
IFMON_OBJS = $(IFMON_SRCS:.c=.o)

TRANSPORT_OBJS = src/common/transport_config.o \
              src/common/qlinq.o \
              src/common/transport_egress.o \
              src/common/transport_fec_state.o \
              src/common/transport_flexicast.o \
              src/common/transport_memory.o \
              src/common/transport_paths.o \
              src/common/transport_protocol.o \
              src/common/transport_publish.o \
              src/common/transport_recovery.o \
              src/common/transport_repair.o \
              src/common/transport_repair_planner.o \
              src/common/transport_scheduler.o \
              src/common/transport_stream.o \
              src/common/transport_subscriptions.o \
              src/common/transport_tls.o \
              src/common/transport_tracks.o \
              src/common/transport_udp.o \
              src/common/transport_wire.o \
              src/common/transport_quicly.o \
              src/common/fec.o \
              deps/nanors/rs.o \
              deps/nanors/deps/obl/oblas_common.o \
              deps/nanors/deps/obl/oblas_lite.o \
              $(QUICLY_OBJS) \
              $(NANORQ_OBJS) \
              $(PATHFLOW_OBJS) \
              $(IFMON_OBJS)

COMMON_OBJS = src/common/data_uds.o \
              $(TRANSPORT_OBJS)

DAEMON_OBJS = src/daemon/main.o \
              $(COMMON_OBJS)

APP_OBJS = src/app/main.o src/app/transfer.o src/app/xfer.o src/app/xfer_file.o
CAST_OBJS = src/cast/main.o

FEC_OBJS = src/common/fec.o \
           deps/nanors/rs.o \
           deps/nanors/deps/obl/oblas_common.o \
           deps/nanors/deps/obl/oblas_lite.o \
           $(NANORQ_OBJS) \
           $(PATHFLOW_OBJS)

# Change the stamp only when effective build inputs change. All objects then
# rebuild together, including tests that include implementations directly.
define BUILD_CONFIG
CC=$(CC)
AR=$(AR)
CFLAGS=$(CFLAGS)
CFLAGS_COMMON=$(CFLAGS_COMMON)
DEPFLAGS=$(DEPFLAGS)
INCLUDES=$(INCLUDES)
FEC_CFLAGS=$(FEC_CFLAGS)
FEC_NATIVE_CFLAGS=$(FEC_NATIVE_CFLAGS)
NANORQ_NATIVE_CFLAGS=$(NANORQ_NATIVE_CFLAGS)
WITH_FUSION=$(WITH_FUSION)
FUSION_CFLAGS=$(FUSION_CFLAGS)
LDFLAGS=$(LDFLAGS)
TRANSPORT_OBJS=$(TRANSPORT_OBJS)
endef

.build-config: FORCE
	$(file >$@.tmp,$(BUILD_CONFIG))
	@cmp -s $@.tmp $@ && rm -f $@.tmp || mv $@.tmp $@

# Rules to compile our source files with full warnings
src/%.o: src/%.c .build-config
	$(CC) $(CFLAGS_COMMON) $(DEPFLAGS) $(INCLUDES) $(CFLAGS) -c $< -o $@

examples/%.o: examples/%.c .build-config
	$(CC) $(CFLAGS_COMMON) $(DEPFLAGS) $(INCLUDES) $(CFLAGS) -c $< -o $@

t/%.o: t/%.c .build-config
	$(CC) $(CFLAGS_COMMON) $(DEPFLAGS) $(INCLUDES) $(CFLAGS) -c $< -o $@

# Rule to compile third-party deps and suppress all warnings with -w

deps/nanors/%.o deps/nanorq/%.o: private CODEC_CFLAGS = $(FEC_CFLAGS) $(FEC_NATIVE_CFLAGS)

deps/%.o: deps/%.c .build-config
	$(CC) $(CFLAGS_COMMON) $(DEPFLAGS) $(INCLUDES) $(CFLAGS) $(CODEC_CFLAGS) -w -c $< -o $@

all: qlinqd qlinq-app qlinq-cast qlinq-tund

# Track only backend inclusion here; other compiler flag changes still require
# a clean build. Switching WITH_FUSION must rebuild its dispatch and tests.
.PHONY: FORCE_FUSION_CONFIG
FORCE_FUSION_CONFIG:

tmp/fusion-config: FORCE_FUSION_CONFIG
	@mkdir -p $(@D)
	@printf 'WITH_FUSION=%s\n' '$(WITH_FUSION)' >$@.tmp
	@cmp -s $@.tmp $@ && rm -f $@.tmp || mv $@.tmp $@

src/common/transport_tls.o t/00util/test_crypto_backend.o: tmp/fusion-config Makefile

deps/quicly/deps/picotls/lib/fusion.o: deps/quicly/deps/picotls/lib/fusion.c Makefile
	$(CC) $(CFLAGS_COMMON) $(DEPFLAGS) $(INCLUDES) $(CFLAGS) $(FUSION_CFLAGS) -w -c $< -o $@

$(NANORQ_CODEC_OBJS): private CODEC_CFLAGS = $(FEC_CFLAGS) $(NANORQ_NATIVE_CFLAGS) -fstack-protector-strong
$(NANORQ_CODEC_OBJS): Makefile deps/nanorq/Makefile

libqlinq.a: $(TRANSPORT_OBJS) .build-config
	rm -f $@.tmp
	$(AR) rcs $@.tmp $(TRANSPORT_OBJS)
	mv $@.tmp $@

qlinqd: $(DAEMON_OBJS)
	$(CC) -o $@ $(DAEMON_OBJS) $(LDFLAGS)

qlinq-app: $(APP_OBJS) libqlinq.a
	$(CC) -o $@ $(APP_OBJS) libqlinq.a $(LDFLAGS)

qlinq-cast: $(CAST_OBJS) libqlinq.a
	$(CC) -o $@ $(CAST_OBJS) libqlinq.a $(LDFLAGS)

qlinq-tun: src/host/linux/tun_metrics.o src/host/linux/tun_control.o src/host/linux/tun_config.o src/host/linux/tun_json.o src/host/linux/tun_direct.o src/host/linux/tun_device.o libqlinq.a
	$(CC) -o $@ $^ $(LDFLAGS)

PREFIX ?= /usr/local
DESTDIR ?=
install-tun: qlinq-tun
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/lib/systemd/system $(DESTDIR)$(PREFIX)/lib/sysusers.d
	install -m 755 qlinq-tun $(DESTDIR)$(PREFIX)/bin/
	sed 's|/usr/local/bin/qlinq-tun|$(PREFIX)/bin/qlinq-tun|' packaging/qlinq-tun@.service > $(DESTDIR)$(PREFIX)/lib/systemd/system/qlinq-tun@.service
	install -m 644 packaging/qlinq.conf $(DESTDIR)$(PREFIX)/lib/sysusers.d/qlinq.conf

check-tun-tool: qlinq-tun t/00util/test_tun_names
	./t/00util/test_tun_names
	python3 t/test_tun_tool.py
	python3 t/test_tun_metrics.py

t/00util/test_tun_names.o: src/host/linux/tun_device.c

t/00util/test_tun_names: t/00util/test_tun_names.o
	$(CC) -o $@ $^ $(LDFLAGS)

t/00util/test_tun_json: t/00util/test_tun_json.o src/host/linux/tun_json.o src/common/cli_parse.o
	$(CC) -o $@ $^ $(LDFLAGS)

check-tun-real: qlinq-tun
	python3 t/test_tun_real.py

package-tun: qlinq-tun
	python3 scripts/package_tun.py

examples/data_multipath_benchmark: examples/data_multipath_benchmark.o $(COMMON_OBJS)
	$(CC) -o $@ examples/data_multipath_benchmark.o $(COMMON_OBJS) $(LDFLAGS)

examples/transit_benchmark: examples/transit_benchmark.o libqlinq.a
	$(CC) -o $@ $^ $(LDFLAGS)

examples/transit_udp_calibration: examples/transit_udp_calibration.o
	$(CC) -o $@ $^ -lm

check-transit-reports: examples/transit_benchmark
	python3 examples/test_multipath_transit_demo.py

check-transit-smoke: check-transit-reports gencerts
	@if [ "$${QLINQ_SKIP_PRIVILEGED:-0}" = 1 ]; then \
		echo "SKIP routed transit smoke test (QLINQ_SKIP_PRIVILEGED=1)"; \
	else \
		mkdir -p tmp; \
		./examples/multipath_transit_demo --scenario healthy --rate-mbps 1000 \
			--mbps 10 --seconds 7 --warmup 2 --drain 2 \
			--output-dir "$$(mktemp -d "$$PWD/tmp/transit-smoke.XXXXXX")"; \
	fi

t/00util/test_xfer_protocol: t/00util/test_xfer_protocol.o src/app/xfer.o src/app/xfer_file.o
	$(CC) -o $@ $^ $(LDFLAGS)

t/00util/test_xfer_file: t/00util/test_xfer_file.o src/app/xfer_file.o
	$(CC) -o $@ $^ $(LDFLAGS)

t/00util/test_fec: t/00util/test_fec.o $(FEC_OBJS)
	$(CC) -o $@ t/00util/test_fec.o $(FEC_OBJS) $(LDFLAGS)

t/00util/test_egress_errors: t/00util/test_egress_errors.o src/common/transport_egress.o
	$(CC) -o $@ $^ $(LDFLAGS)

TRANSPORT_TESTS = t/00util/test_flexicast_transport \
	 t/00util/test_transport_bind \
	t/00util/test_transport_poll \
	t/00util/test_crypto_backend \
	t/00util/test_interleaved_receive \
	t/00util/test_publication_limits \
	t/00util/test_directional_subscriptions \
	t/00util/test_generic_ports \
	t/00util/test_stream_budget \
	t/00util/test_transport \
	t/00util/test_reliable_bidirectional \
	t/00util/test_tund \
	t/00util/test_transport_components \
	t/00util/test_benchmark \
	t/00util/test_tc_benchmark \
	t/00util/test_multipath t/00util/test_multipath_failover \
	t/00util/test_multipath_feedback \
	t/00util/test_multipath_publication \
	t/00util/test_multipath_nack \
	t/00util/test_operational \
	t/00util/test_tls \
	t/00util/test_rateless_benchmark

$(filter-out t/00util/test_multipath_failover t/00util/test_multipath_feedback,$(TRANSPORT_TESTS)): %: %.o $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

API_TESTS = t/00util/test_qlinq_policy \
	t/00util/test_qlinq_event_overflow \
	t/00util/test_qlinq_compat \
	t/00util/test_qlinq_reconnect \
	t/00util/test_qlinq_delivery \
	t/00util/test_qlinq_event_ownership

$(API_TESTS): %: %.o libqlinq.a
	$(CC) -o $@ $^ $(LDFLAGS)

t/00util/test_data_uds: t/00util/test_data_uds.o src/common/data_uds.o
	$(CC) -o $@ t/00util/test_data_uds.o src/common/data_uds.o $(LDFLAGS)

t/00util/test_transport_wire: t/00util/test_transport_wire.o src/common/transport_wire.o
	$(CC) -o $@ t/00util/test_transport_wire.o src/common/transport_wire.o $(LDFLAGS)

t/00util/test_udp_gso_prefix: t/00util/test_udp_gso_prefix.o
	$(CC) -o $@ $< $(LDFLAGS)

t/00util/test_udp_receive: t/00util/test_udp_receive.o src/common/transport_udp.o
	$(CC) -o $@ $^ $(LDFLAGS)

t/00util/test_udp_gro: t/00util/test_udp_gro.o
	$(CC) -o $@ $< $(LDFLAGS)

t/00util/test_ifmon: t/00util/test_ifmon.o
	$(CC) -o $@ $< $(LDFLAGS)
t/00util/test_qlinq_api: t/00util/test_qlinq_api.o $(COMMON_OBJS)
	$(CC) -o $@ t/00util/test_qlinq_api.o $(COMMON_OBJS) $(LDFLAGS)

t/00util/fuzz_transport_wire: t/00util/fuzz_transport_wire.c src/common/transport_wire.c
	clang $(CFLAGS_COMMON) $(INCLUDES) -fsanitize=fuzzer,address,undefined \
		-o $@ t/00util/fuzz_transport_wire.c src/common/transport_wire.c

fuzz-wire: t/00util/fuzz_transport_wire
	ASAN_OPTIONS=detect_leaks=0 ./t/00util/fuzz_transport_wire -runs=10000

check-submodules:
	./scripts/check_submodules.sh

check-multipath-demo:
	@if [ "$${QLINQ_SKIP_PRIVILEGED:-0}" = 1 ]; then \
		echo "SKIP privileged multipath demo (QLINQ_SKIP_PRIVILEGED=1)"; \
	else \
		./examples/multipath_demo.sh; \
	fi

check-multipath-bw-reports:
	python3 examples/test_multipath_bw_demo.py

check-reports: check-transit-reports check-multipath-bw-reports

check-multipath-bw-demo: check-multipath-bw-reports
	@if [ "$${QLINQ_SKIP_PRIVILEGED:-0}" = 1 ]; then \
		echo "SKIP privileged bandwidth demo (QLINQ_SKIP_PRIVILEGED=1)"; \
	else \
		./examples/multipath_bw_demo --all-modes; \
	fi

check-sanitize:
	$(MAKE) clean
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
	$(MAKE) check CC=clang CFLAGS="$(SANITIZER_FLAGS)" \
		FEC_CFLAGS="$(SANITIZER_FLAGS)" FEC_NATIVE_CFLAGS= NANORQ_NATIVE_CFLAGS= \
		LDFLAGS="$(SANITIZER_FLAGS) $(LDFLAGS)"

soak: t/00util/test_operational t/00util/test_transport \
	t/00util/test_multipath_nack gencerts
	./scripts/operational_soak.sh

release-check: check-submodules
	$(MAKE) clean
	$(MAKE) check
	$(MAKE) fuzz-wire
	$(MAKE) check-sanitize
	$(MAKE) clean
	$(MAKE) all examples/data_multipath_benchmark gencerts
	$(MAKE) check-multipath-demo
	@echo "=== RELEASE CHECK OK ==="

benchmark: t/00util/test_benchmark
	./t/00util/test_benchmark

benchmark-rateless: t/00util/test_rateless_benchmark
	./t/00util/test_rateless_benchmark

CHECK_BINARIES = t/00util/test_xfer_file t/00util/test_xfer_protocol t/00util/test_fec t/00util/test_tun_json t/00util/test_tun_names \
	t/00util/test_rx_cadence t/00util/test_rx_cadence_backlog \
	t/00util/test_rx_cadence_real \
	t/00util/test_crypto_backend \
	t/00util/test_qlinq_policy \
	t/00util/test_egress_errors t/00util/test_transport_bind t/00util/test_transport_poll \
	t/00util/test_interleaved_receive t/00util/test_publication_limits \
	t/00util/test_directional_subscriptions \
	t/00util/test_qlinq_event_overflow t/00util/test_qlinq_compat \
	t/00util/test_qlinq_reconnect t/00util/test_qlinq_delivery \
	t/00util/test_qlinq_event_ownership t/00util/test_generic_ports \
	t/00util/test_stream_budget t/00util/test_transport \
	t/00util/test_reliable_bidirectional t/00util/test_tund \
	t/00util/test_data_uds t/00util/test_transport_wire \
	t/00util/test_transport_components t/00util/test_udp_gso_prefix t/00util/test_udp_receive t/00util/test_udp_gro t/00util/test_ifmon \
	t/00util/test_multipath t/00util/test_multipath_failover \
	t/00util/test_multipath_feedback \
	t/00util/test_multipath_publication \
	t/00util/test_multipath_nack t/00util/test_operational t/00util/test_tls

t/00util/test_multipath_failover: t/00util/test_multipath_failover.o $(filter-out src/common/transport_udp.o,$(COMMON_OBJS))
	$(CC) -o $@ $^ $(LDFLAGS)

# The feedback fixture delegates native operations except during its explicit
# scheduler checks. Keep the production library and native dependency intact.
t/00util/transport_quicly_feedback.o: src/common/transport_quicly.c Makefile
	$(CC) $(CFLAGS_COMMON) $(DEPFLAGS) $(INCLUDES) $(CFLAGS) \
		-Dquicly_get_path_stats=test_quicly_get_path_stats \
		-Dquicly_get_path_health=test_quicly_get_path_health \
		-Dquicly_is_path_available=test_quicly_is_path_available \
		-Dquicly_send_on_path=test_quicly_send_on_path -c $< -o $@

t/00util/test_multipath_feedback: t/00util/test_multipath_feedback.o t/00util/transport_quicly_feedback.o $(filter-out src/common/transport_quicly.o,$(COMMON_OBJS))
	$(CC) -o $@ $^ $(LDFLAGS)

# These fixtures include the public service implementation to observe its
# private wait state without adding production test hooks.
t/00util/test_rx_cadence.o t/00util/test_rx_cadence_real.o: src/common/qlinq.c
t/00util/test_rx_cadence_backlog.o: t/00util/test_transport_poll.c

t/00util/test_rx_cadence: t/00util/test_rx_cadence.o $(filter-out src/common/qlinq.o,$(COMMON_OBJS))
	$(CC) -o $@ $^ $(LDFLAGS)

t/00util/test_rx_cadence_backlog: t/00util/test_rx_cadence_backlog.o $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

t/00util/transport_egress_cadence.o: src/common/transport_egress.c Makefile
	$(CC) $(CFLAGS_COMMON) $(DEPFLAGS) $(INCLUDES) $(CFLAGS) \
		-Dtransport_udp_send_batch=test_cadence_udp_send_batch -c $< -o $@

t/00util/test_rx_cadence_real: t/00util/test_rx_cadence_real.o t/00util/transport_egress_cadence.o $(filter-out src/common/qlinq.o src/common/transport_egress.o,$(COMMON_OBJS))
	$(CC) -o $@ $^ $(LDFLAGS)

check: all $(CHECK_BINARIES) t/00util/test_flexicast_transport t/00util/test_qlinq_api gencerts check-reports
	prove -I. -v t/*.t

clean: 
	rm -f qlinqd qlinq-app qlinq-cast qlinq-tund libqlinq.a t/00util/test_fec t/00util/test_transport t/00util/test_flexicast_transport t/00util/test_tund t/00util/test_data_uds t/00util/test_transport_wire t/00util/test_transport_components t/00util/test_qlinq_api t/00util/fuzz_transport_wire t/00util/test_multipath t/00util/test_multipath_nack t/00util/test_operational t/00util/test_tls t/00util/test_benchmark t/00util/test_rateless_benchmark t/00util/test_tc_benchmark examples/data_multipath_benchmark
	find src deps t examples -name "*.o" -delete
	find src t examples -name "*.d" -delete
	rm -f $(QUICLY_OBJS:.o=.d) $(NANORQ_OBJS:.o=.d) \
		$(PATHFLOW_OBJS:.o=.d) deps/nanors/rs.d \
		deps/nanors/deps/obl/oblas_common.d \
		deps/nanors/deps/obl/oblas_lite.d

check-flexicast-netns: t/00util/test_flexicast_transport gencerts
	./t/netns_flexicast_ssm.sh

# Check certificate lifetime on every invocation, including existing fixtures.
# Grouped targets keep each certificate/key pair together under parallel make.
FORCE:

t/assets/server.crt t/assets/server.key &: FORCE
	sh scripts/gencert.sh t/assets/server.crt t/assets/server.key 365 -subj "/CN=localhost"

t/assets/verified.crt t/assets/verified.key &: FORCE
	sh scripts/gencert.sh t/assets/verified.crt t/assets/verified.key 7 \
		-subj "/CN=localhost" -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
		-addext "basicConstraints=critical,CA:TRUE" \
		-addext "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign" \
		-addext "extendedKeyUsage=serverAuth,clientAuth"

t/assets/verified-v6.crt t/assets/verified-v6.key &: FORCE
	sh scripts/gencert.sh t/assets/verified-v6.crt t/assets/verified-v6.key 7 \
		-subj "/CN=localhost" -addext "subjectAltName=IP:::1,DNS:localhost" \
		-addext "basicConstraints=critical,CA:TRUE" \
		-addext "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign" \
		-addext "extendedKeyUsage=serverAuth,clientAuth"

t/assets/untrusted.crt t/assets/untrusted.key &: FORCE
	sh scripts/gencert.sh t/assets/untrusted.crt t/assets/untrusted.key 7 \
		-subj "/CN=untrusted" -addext "basicConstraints=critical,CA:TRUE"

t/assets/unsafe.key: t/assets/verified.key
	cp $< $@
	chmod 0644 $@

gencerts: t/assets/server.crt t/assets/server.key t/assets/verified.crt t/assets/verified.key t/assets/verified-v6.crt t/assets/verified-v6.key t/assets/untrusted.crt t/assets/untrusted.key t/assets/unsafe.key

FORMAT_SOURCES := $(shell find src examples t/00util -type f \
	\( -name '*.c' -o -name '*.h' \))

indent:
	clang-format -style=file -i $(FORMAT_SOURCES)

.PHONY: all clean check check-flexicast-netns benchmark fuzz-wire check-submodules FORCE \
	check-multipath-demo check-multipath-bw-demo check-multipath-bw-reports check-reports check-transit-reports check-transit-smoke check-sanitize soak release-check indent gencerts

.PHONY: install-tun check-tun-tool check-tun-real package-tun

-include $(shell find src t examples -name "*.d" -print 2>/dev/null) \
         $(QUICLY_OBJS:.o=.d) $(NANORQ_OBJS:.o=.d) \
         $(PATHFLOW_OBJS:.o=.d) deps/nanors/rs.d \
         deps/nanors/deps/obl/oblas_common.d \
         deps/nanors/deps/obl/oblas_lite.d
