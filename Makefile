
ipsetdir: ipsetdir.c ipset_ui/ipset_ui.a
	gcc -g -O0 -Wall -o $@ $^ ipset_ui/ipset_ui.a -lipset

ipset_ui/ipset_ui.a::
	make -C ipset_ui

clean:
	rm -r ipsetdir
	make -C ipset_ui clean
