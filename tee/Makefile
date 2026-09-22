app
*.o
*.so
App/Enclave_u.c
App/Enclave_u.h
Enclave/Enclave_t.c
Enclave/Enclave_t.h
Enclave/Enclave_private_test.pem

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_DEBUG ?= 1

CC := gcc
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
SGX_SIGN := $(SGX_SDK)/bin/x64/sgx_sign
SGX_LIBDIR := $(SGX_SDK)/lib64

COMMON_FLAGS := -m64 -O2 -Wall -Wextra -std=c11

APP_FLAGS := $(COMMON_FLAGS) -I$(SGX_SDK)/include -IApp -IInclude
APP_LIBS := -L$(SGX_LIBDIR) -lsgx_urts -lpthread

ENCLAVE_FLAGS := $(COMMON_FLAGS) -nostdinc -fvisibility=hidden -fpie \
	-fstack-protector -I$(SGX_SDK)/include \
	-I$(SGX_SDK)/include/tlibc -IEnclave -IInclude

ENCLAVE_LIBS := -m64 -Wl,--no-undefined -nostdlib -nodefaultlibs \
	-nostartfiles -L$(SGX_LIBDIR) \
	-Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcrypto -lsgx_tservice \
	-Wl,--end-group -Wl,-Bstatic -Wl,-Bsymbolic \
	-Wl,--no-undefined -Wl,-pie,-eenclave_entry \
	-Wl,--export-dynamic -Wl,--defsym,__ImageBase=0 \
	-Wl,--gc-sections -Wl,--version-script=Enclave/Enclave.lds

APP_OBJECTS := App/App.o App/Enclave_u.o
ENCLAVE_OBJECTS := Enclave/Enclave.o Enclave/Enclave_t.o

.PHONY: all clean run

all: app Enclave/enclave.signed.so

App/Enclave_u.c App/Enclave_u.h: Enclave/Enclave.edl
	$(SGX_EDGER8R) --untrusted $< --search-path Enclave \
		--search-path $(SGX_SDK)/include --untrusted-dir App

Enclave/Enclave_t.c Enclave/Enclave_t.h: Enclave/Enclave.edl
	$(SGX_EDGER8R) --trusted $< --search-path Enclave \
		--search-path $(SGX_SDK)/include --trusted-dir Enclave

App/App.o: App/App.c App/Enclave_u.h Include/abac_tee_protocol.h
	$(CC) $(APP_FLAGS) -c $< -o $@

App/Enclave_u.o: App/Enclave_u.c App/Enclave_u.h
	$(CC) $(APP_FLAGS) -c $< -o $@

app: $(APP_OBJECTS)
	$(CC) $(COMMON_FLAGS) $^ -o $@ $(APP_LIBS)

Enclave/Enclave.o: Enclave/Enclave.c Enclave/Enclave_t.h \
	Include/abac_tee_protocol.h
	$(CC) $(ENCLAVE_FLAGS) -c $< -o $@

Enclave/Enclave_t.o: Enclave/Enclave_t.c Enclave/Enclave_t.h
	$(CC) $(ENCLAVE_FLAGS) -c $< -o $@

Enclave/enclave.so: $(ENCLAVE_OBJECTS)
	$(CC) $^ -o $@ $(ENCLAVE_LIBS)

Enclave/Enclave_private_test.pem:
	openssl genrsa -3 -out $@ 3072

Enclave/enclave.signed.so: Enclave/enclave.so \
	Enclave/Enclave_private_test.pem Enclave/Enclave.config.xml
	$(SGX_SIGN) sign -key Enclave/Enclave_private_test.pem \
		-enclave Enclave/enclave.so -out $@ \
		-config Enclave/Enclave.config.xml

run: all
	./app

clean:
	rm -f app $(APP_OBJECTS) $(ENCLAVE_OBJECTS) \
		App/Enclave_u.c App/Enclave_u.h \
		Enclave/Enclave_t.c Enclave/Enclave_t.h \
		Enclave/enclave.so Enclave/enclave.signed.so
