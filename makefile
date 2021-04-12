CC = gcc
CFLAGS = -fPIC -s
CINCLD = -I. -I/usr/local/include/kernelshark -I$(LIBDIR)/kernel-shark-v2.beta -I/usr/include/xen -I$(LIBDIR)/xen -I$(LIBDIR)/xentrace-parser/out

CP = cp
RM = rm -f
MKD = mkdir

LIBDIR = ./lib
SRCDIR = ./src
OBJDIR = ./obj
OUTDIR = ./out

SOURCES := $(wildcard $(SRCDIR)/*.c $(SRCDIR)/events/*.c)
OBJECTS := $(subst $(SRCDIR), $(OBJDIR), $(SOURCES:.c=.o))

#---
.PHONY: build
build: make-xtp $(OUTDIR)/ks-xentrace.so

$(OUTDIR)/%.so: $(OBJECTS)
	@$(MKD) -p $(dir $@)
	@$(CC) $(CFLAGS) -shared $(CINCLD) $^ $(LIBDIR)/xentrace-parser/out/xentrace-parser.o -o $@

.PRECIOUS: $(OBJDIR)/%.o
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@$(MKD) -p $(dir $@)
	@$(CC) $(CFLAGS) -c $(CINCLD) $< -o $@

#---
.PHONY: make-xtp
make-xtp:
	@$(MAKE) -C $(LIBDIR)/xentrace-parser CFLAGS="$(CFLAGS)"

#---
.PHONY: clean
clean:
	@$(MAKE) -C $(LIBDIR)/xentrace-parser clean
	@$(RM) -r $(OBJDIR) $(OUTDIR)
