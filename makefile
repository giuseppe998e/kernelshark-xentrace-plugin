CC = gcc
CFLAGS = -fPIC -shared -Os -s
CINCLD = -I $(LIBDIR)/kernel-shark-v2.beta/src -I $(LIBDIR)/xen -I $(LIBDIR)/xentrace-parser/out

CP = cp
RM = rm -f
MKD = mkdir

LIBDIR = ./lib
SRCDIR = ./src
OUTDIR = ./out

#---
.PHONY: build
build: make-xtp $(OUTDIR)/ks-xentrace.so

$(OUTDIR)/%.so: $(SRCDIR)/%.c
	@$(MKD) -p $(dir $@)
	@$(CC) $(CFLAGS) $(CINCLD) $< $(LIBDIR)/xentrace-parser/out/xentrace-parser.o -o $@

#---
.PHONY: make-xtp
make-xtp:
	@$(MAKE) -C $(LIBDIR)/xentrace-parser

#---
.PHONY: clean
clean:
	@$(MAKE) -C $(LIBDIR)/xentrace-parser clean
	@$(RM) -r $(OUTDIR)