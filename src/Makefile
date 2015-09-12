TARGET := libmtp.a

CXXFLAGS = -MMD -O2 -Wall -g -std=c++11
CXXFLAGS += -I../include
CXXFLAGS += -I../libusbhost/include
CXXFLAGS += -DMTP_DEVICE -DMTP_HOST

all: $(TARGET)

LIB_OBJS= \
	MtpStorage.o \
	MtpServer.o \
	MtpObjectInfo.o \
	MtpResponsePacket.o \
	MtpStringBuffer.o \
	MtpEventPacket.o \
	MtpDeviceInfo.o \
	MtpPacket.o \
	MtpUtils.o \
	MtpProperty.o \
	MtpDevice.o \
	MtpRequestPacket.o \
	MtpDataPacket.o \
	MtpStorageInfo.o \
	MtpDebug.o

$(TARGET): $(LIB_OBJS)
	$(AR) crT $@ $?

-include $(OBJS:%.o=%.d)

clean:
	$(RM) *~ *.o *.d *.gcno *.gcda *.gcov $(TARGET)

install:
	@echo Nothing to be made.
