
ipsetdir: ipsetdir.c
	gcc -g -O0 -Wall -o $@ $^ -lipsetshared
