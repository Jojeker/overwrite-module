
target remote :1337
# b *0x4044ec
# b *0x40424c
# b *0x405080
# b *0x4046a0
b *0x404828
tb *0x402cb4
commands
    call (int) open("/tmp/ubi_modem.out.mod", 0)
    call (void*) malloc(1024 * 1024 * 15)
    call (int) read($1, $2, 14683984)
    set $x1 = $2+0x200
    c
end
c
