TOOLS := flops dry

all: $(TOOLS) emqbit/emqbit-bench/cfft emqbit/emqbit-bench/bench

flops: flops.c
	$(CC) $(CFLAGS) $< -o $@ -Wall

dry: dry.c
	$(CC) $(CFLAGS) -O3 -c $< -o dry1.o -Wall
	$(CC) $(CFLAGS) -O3 -DPASS2 $< dry1.o -o $@ -Wall

emqbit/emqbit-bench/cfft emqbit/emqbit-bench/bench:
	$(MAKE) -C emqbit/emqbit-bench/

clean::
	rm -f $(TOOLS) *.o
