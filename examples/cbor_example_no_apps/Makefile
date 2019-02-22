CONTIKI_PROJECT = cbor-test
all: $(CONTIKI_PROJECT)

#CURVE_PARAMS = SECP256R1
#APPS += cbor
#APPS += ecc
MODULES += os/services/cbor

CFLAGS += -DHW_AES
CFLAGS += -DHW_ECC
CFLAGS += -DHW_SHA
CFLAGS += -DHW_CCM
# CONTIKI_WITH_IPSEC = 1
#CFLAGS += -DCONTIKI_WITH_IPSEC
#CFLAGS = -g
CFLAGS += -DWITH_DTLS
CFLAGS += -DDTLS_PSK
CONTIKI = ../..
include $(CONTIKI)/Makefile.include



client:
	sudo make cbor-test.upload PORT=/dev/serial/by-id/usb-Silicon_Labs_Zolertia_Firefly_platform_ZOL-B001-A20000600-if00-port0
	#sudo ../../tools/sky/serialdump-linux -b115200 /dev/serial/by-id/usb-Silicon_Labs_Zolertia_Firefly_platform_ZOL-B001-A20000584-if00-port0

login0:
	sudo make TARGET=zoul BOARD=firefly PORT=/dev/ttyUSB0 login

