all:
	gcc pam_tarpit.c -std=c99 -liptc -lip4tc -lip6tc -lpam -shared -fPIC -o pam_tarpit.so
clean:
	rm *.so
