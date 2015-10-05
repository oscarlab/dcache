#
# Makefile for the directory cache optimizations.
#
#

obj-$(CONFIG_DCACHE_FAST)			+= dcache.o namei.o
obj-$(CONFIG_DCACHE_AGGRESSIVE_NEGATIVE)	+= negative.o
obj-$(CONFIG_DCACHE_COMPLETENESS)		+= completeness.o
obj-$(CONFIG_DCACHE_FAST_DEEP_DENTRIES)		+= deep.o

obj-$(CONFIG_PATH_SIGNATURE_JELKINS_OLD)	+= jelkins-old.o
obj-$(CONFIG_PATH_SIGNATURE_JELKINS_LOOKUP3)	+= jelkins-lookup3.o
obj-$(CONFIG_PATH_SIGNATURE_JELKINS_SPOOKY)	+= jelkins-spooky.o
obj-$(CONFIG_PATH_SIGNATURE_MHASH)		+= mhash.o
obj-$(CONFIG_PATH_SIGNATURE_MHASH64)		+= mhash64.o
obj-$(CONFIG_PATH_SIGNATURE_MHASH_AVX2)		+= mhash-avx2.o mhash-avx2-wrapper.o
obj-$(CONFIG_PATH_SIGNATURE_AES_KHASH)		+= aes-khash.o aesni.o
