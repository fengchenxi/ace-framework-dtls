CONTIKI_PROJECT = example-ipso-objects

CONTIKI_SOURCEFILES += serial-protocol.c example-ipso-temperature.c

PLATFORMS_EXCLUDE = sky

all: $(CONTIKI_PROJECT)

MODULES += os/net/app-layer/coap
MODULES += os/services/lwm2m
MODULES += os/services/ipso-objects


CONTIKI=../..
include $(CONTIKI)/Makefile.identify-target
MODULES_REL += $(TARGET)

include $(CONTIKI)/Makefile.include

client:
	sudo make PORT=/dev/serial/by-id/usb-Silicon_Labs_Zolertia_Firefly_platform_ZOL-B001-A20000711-if00-port0 MAKE_WITH_DTLS=1 MAKE_COAP_DTLS_KEYSTORE=MAKE_COAP_DTLS_KEYSTORE_SIMPLE example-ipso-objects.upload

server:
	sudo make PORT=/dev/serial/by-id/usb-Silicon_Labs_Zolertia_Firefly_platform_ZOL-B001-A20000600-if00-port0 MAKE_WITH_DTLS=1 MAKE_COAP_DTLS_KEYSTORE=MAKE_COAP_DTLS_KEYSTORE_SIMPLE example-server.upload
