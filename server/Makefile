TARGET := mtp-server

CXXFLAGS = -MMD -O2 -Wall -g -std=c++11
CXXFLAGS += -I. -I../include
CXXFLAGS += -DMTP_DEVICE -DMTP_HOST

LDFLAGS = -fPIC
LIBS := -lpthread

PATH:=$(PATH):/home/arthur/project/buildroot-2015.05/output/host/usr/bin

CC   := mips-linux-gnu-gcc
CXX  := mips-linux-gnu-g++
AR   := mips-linux-gnu-ar

RM   :=rm -f

export PATH CC CXX AR RM

all: $(TARGET)

OBJS= server.o

$(TARGET): $(OBJS) ../src/libmtp.a ../libusbhost/libusbhost.a
	$(CXX) -o $@ $^ $(LDFLAGS) $(LIBS) 

-include $(OBJS:%.o=%.d)

../src/libmtp.a::
	make -C ../src
	
../libusbhost/libusbhost.a::
	make -C ../libusbhost

clean:
	$(RM) *~ *.o *.d *.gcno *.gcda *.gcov *.a $(TARGET)
	make -C ../src clean
	make -C ../libusbhost clean

install:
	@echo Nothing to be made.
