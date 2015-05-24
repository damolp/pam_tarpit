all:
	gcc pam_tarpit.c  -lpam -shared -fPIC -o pam_tarpit.so
clean:
	rm *.so