all:
	make -C server
	cp -f server/mtp-server .

clean:
	make -C server clean
	$(RM) mtp-server
