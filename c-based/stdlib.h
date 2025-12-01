#ifndef STDLIBLUL
#define STDLIBLUL

#define DIE 0x0

/*
void *memset(void *str, int c, int n)
{
	for(int i=0; i<n; i++){
		((char*)str)[i] = (char)c;
	}
}

void *memcpy(void *dest, const void *src, int n)
{
    for (int i = 0; i < n; i++)
    {
        ((char*)dest)[i] = ((char*)src)[i];
    }
}

int memcmp(const void *s1, const void *s2, unsigned int n) {
    const char *p1 = (const char *)s1;
    const char *p2 = (const char *)s2;

    for (unsigned int i = 0; i < n; i++) {
        if (p1[i] != p2[i]) {
            return p1[i] - p2[i];
        }
    }
    return 0;
}

int strlen(const char *s) {
    const char *p = s;
    while (*p) ++p;
    return (int)(p - s);
}

void* memsearch(const void* haystack, unsigned int haystack_len, const void* needle, unsigned int needle_len) {
    if (needle_len == 0 || haystack_len < needle_len) {
        return 0;
    }

    const char* haystack_bytes = (const char*)haystack;
    const char* needle_bytes = (const char*)needle;

    for (unsigned int i = 0; i <= haystack_len - needle_len; ++i) {
        if (haystack_bytes[i] == needle_bytes[0]) {
            if (memcmp(&haystack_bytes[i], needle_bytes, needle_len) == 0) {
                return (void*)&haystack_bytes[i];
            }
        }
    }

    return 0;
}

static void byte_to_hex(unsigned char byte, char *hex_string) {
    const char hex_digits[] = "0123456789ABCDEF\x00";
    unsigned char high_nibble = (byte >> 4) & 0x0F;
    unsigned char low_nibble = byte & 0x0F;
    hex_string[0] = hex_digits[high_nibble];
    hex_string[1] = hex_digits[low_nibble];
    //logprintf1(hex_string);
}
*/
[[maybe_unused]] static void die(){
	__asm__ __volatile__ (
	"movw r12, %[die]\n\t"       // Move DIE address into r1
	"bx r12\n\t"                 // Branch to DIE
	:                           // No output operands
	: [die] "i" (DIE)  // Input operandsb
	: "r12"                // Clobbered registers
	);
}
#endif
