CONTIKI_PROJECT = coap-example-client
# coap-example-observe-client is outdated but will be ported at a later point
all: $(CONTIKI_PROJECT)

# Do not try to build on Sky because of code size limitation
PLATFORMS_EXCLUDE = sky

# Include the CoAP implementation
MODULES += os/net/app-layer/coap
MODULES += os/services/cbor
#MODULES += os/sys/powertrace
MODULES +=  os/services/ace
#MODULES += os/services/powertrace
#MODULES += os/services/rpl-border-router
#MODULES_REL += ./ace

MODULES_REL += ./resources

#WITH_DTLS=1
#DTLS_ECC=0
#DTLS_PSK=1
#ACE_INFO=1
#DISABLE_PRINTF = 0
#DISABLE_PRINTF_INSIDE =0

CONTIKI=../..
include $(CONTIKI)/Makefile.include


client-dtls1:
	sudo make TARGET=zoul BOARD=firefly-reva PORT=/dev/serial/by-id/usb-Silicon_Labs_Zolertia_Firefly_platform_ZOL-B001-A200001803-if00-port0 MAKE_WITH_DTLS=1 \ MAKE_COAP_DTLS_KEYSTORE=MAKE_COAP_DTLS_KEYSTORE_SIMPLE coap-example-client.upload

client-dtls:
	sudo make TARGET=zoul BOARD=firefly-reva PORT=/dev/serial/by-id/usb-Silicon_Labs_Zolertia_Firefly_platform_ZOL-B001-A200001803-if00-port0 MAKE_WITH_DTLS=1  coap-example-client.upload

client:
	sudo make coap-example-client.upload PORT=/dev/serial/by-id/usb-Silicon_Labs_Zolertia_Firefly_platform_ZOL-B001-A200001803-if00-port0

as-dtls1:
	sudo make PORT=/dev/serial/by-id/usb-Silicon_Labs_Zolertia_Firefly_platform_ZOL-B001-A20000600-if00-port0 MAKE_WITH_DTLS=1 MAKE_COAP_DTLS_KEYSTORE=MAKE_COAP_DTLS_KEYSTORE_SIMPLE authorization-server.upload

as:
	sudo make authorization-server.upload PORT=/dev/serial/by-id/usb-Silicon_Labs_Zolertia_Firefly_platform_ZOL-B001-A20000600-if00-port0

as-dtls:
	sudo make PORT=/dev/serial/by-id/usb-Silicon_Labs_Zolertia_Firefly_platform_ZOL-B001-A20000600-if00-port0 MAKE_WITH_DTLS=1  authorization-server.upload

rs1:
	sudo make resource-server.upload PORT=/dev/serial/by-id/usb-Silicon_Labs_Zolertia_Firefly_platform_ZOL-B001-A200001609-if00-port0

rs-dtls:
	sudo make PORT=/dev/serial/by-id/usb-Silicon_Labs_Zolertia_Firefly_platform_ZOL-B001-A200001609-if00-port0 MAKE_WITH_DTLS=1  resource-server.upload

rs-dtls1:
	sudo make PORT=/dev/serial/by-id/usb-Silicon_Labs_Zolertia_Firefly_platform_ZOL-B001-A200001609-if00-port0 MAKE_WITH_DTLS=1 MAKE_COAP_DTLS_KEYSTORE=MAKE_COAP_DTLS_KEYSTORE_SIMPLE resource-server.upload
	
login0:
	sudo make TARGET=zoul BOARD=firefly PORT=/dev/ttyUSB0 login

login1:
	sudo make TARGET=zoul BOARD=firefly PORT=/dev/ttyUSB1 login

login2:
	sudo make TARGET=zoul BOARD=firefly PORT=/dev/ttyUSB2 login


