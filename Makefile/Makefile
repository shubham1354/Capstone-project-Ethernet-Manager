#Define the compiler
CC = gcc

#Define the compiler flags
  CFLAGS
  = -Wall

#Define the executable name
      EXEC
  = ethmngr

#Define the source files
    SRCS
  = config.c main.c pal.c uil.c

#Define the object files
      OBJS
  = $(SRCS
      :.c =.o)

#Default target
        all : $(EXEC)

#Rule to link the object files and create the executable
                $(EXEC)
  : $(OBJS) @sudo $(CC) $(CFLAGS)
    - o $(EXEC) $(OBJS)

#Rule to compile the source files into object files
        %.o : %.c @$(CC) $(CFLAGS)
    - c $
    < -o $ @

#Clean up the build files
        clean : @rm
        - f $(OBJS) $(EXEC)

#Run the program(optional)
              run
  : @sudo./ $(EXEC)
