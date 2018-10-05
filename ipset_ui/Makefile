
all::	ipset_ui.a

ipset_ui.a: ipset_ui.o
	ar r $@ $^
ipset_ui.o: ipset_ui.c
	$(CC) -c -g -O2 -Wall -o $@ $^

test::	ipset_ui

ipset_ui: ipset_ui.c
	$(CC) -DIPSET_LIB_TEST=1 -g -O0 -Wall -o $@ $^ -lipset

clean::
	rm -f ipset_ui.a ipset_ui.o ipset_ui
