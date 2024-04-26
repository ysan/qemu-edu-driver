CC		:=	g++
CFLAGS	:=	-Wall -static
INCDIR	:=	-I./
LIBDIR	:=
LIBS	:=

TARGET	:=	rw
SRCS	:=	rw.cpp
OBJS	:=	$(SRCS:%.cpp=%.o)


.PHONY: all
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(INCDIR) $(LIBDIR) $(LIBS)

%.o: %.cpp
	$(CC) -c $< $(CFLAGS) $(INCDIR)

.PHONY: clean
clean:
	rm -f $(TARGET) $(OBJS)
