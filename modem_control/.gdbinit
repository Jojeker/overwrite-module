
set pagination off
target remote :1337

b *0x00402a7c

# b *0x404828
b *0x00403bd4
tb *0x402cb4
commands
    call (int) open("/tmp/ubi_modem.out.mod", 0)
    call (void*) malloc(1024 * 1024 * 20)
    call (int) read($1, $2, 19926864)
    set $x1 = $2+0x200
    c
end
c
