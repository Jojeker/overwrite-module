set pagination off
target remote :1337


tb *0x00403bd4
commands 
	p/s $x0
	set $x0 = "/tmp/ubi_modem_header.out.mod"
	p/s $x0
	c
end


tb *0x00402c58
commands
	set $fd = (int) open("/tmp/ubi_modem.out.mod", 0)
	set $mem = (void*) malloc(1024 * 1024 * 20)

	# Read both header and body (20MiB upper bound)
	call (int) read($fd, $mem, 1024 * 1024 * 20)

	p/x $x1
	p/x $fd
	p/x $mem

	set $x1 = $mem
	c	
end

tb *0x402cb4
commands
	# Only offset the pointer for the rest

	# Read both header and body (20MiB upper bound)
	set $x1 = $mem+0x200
	c
end

c
