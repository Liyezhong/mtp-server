
CFLAGS = -MMD -O2 -Wall -g -fPIC
CFLAGS += -Iinclude

export PATH CC CXX RM

all: libusbhost.a

LIB_OBJS= usbhost.o

libusbhost.a: $(LIB_OBJS)
	$(AR) crT $@ $?

-include $(OBJS:%.o=%.d)

clean:
	$(RM) *~ *.o *.d *.gcno *.gcda *.gcov *.a

install:
	@echo Nothing to be made.
