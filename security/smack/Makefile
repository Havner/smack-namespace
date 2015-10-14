#
# Makefile for the SMACK LSM
#

obj-$(CONFIG_SECURITY_SMACK) := smack.o

smack-y := smack_lsm.o smack_access.o smackfs.o
smack-$(CONFIG_SECURITY_SMACK_NETFILTER) += smack_netfilter.o
smack-$(CONFIG_SECURITY_SMACK_NS) += smack_ns.o

CFLAGS_smack.o		+= -DDEBUG -g -O1
CFLAGS_smack_lsm.o	+= -DDEBUG -g -O1
CFLAGS_smack_access.o	+= -DDEBUG -g -O1
CFLAGS_smackfs.o	+= -DDEBUG -g -O1
CFLAGS_smack_ns.o	+= -DDEBUG -g -O1
