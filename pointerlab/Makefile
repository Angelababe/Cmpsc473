TARGET = pointer
OBJS += pointer.o
OBJS += test.o
LIBS += -lm

CC = gcc
CFLAGS += -MMD -MP # dependency tracking flags
CFLAGS += -I./
CFLAGS += -Wall -Werror -Wconversion
LDFLAGS += $(LIBS)

all: CFLAGS += -g -O2 # release flags
all: $(TARGET)

release: clean all

debug: CFLAGS += -g -Og -D_GLIBC_DEBUG # debug flags
debug: clean $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

DEPS = $(OBJS:%.o=%.d)
-include $(DEPS)

clean:
	-@rm $(TARGET) $(OBJS) $(DEPS) 2> /dev/null || true
	-@rm -r sandbox 2> /dev/null || true

test:
	@chmod +x grade.py
	@./grade.py
