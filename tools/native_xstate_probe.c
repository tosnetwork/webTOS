// Native x86-64 xstate enumeration probe used by the M9 differential gate.
//
// Build: cc -O2 -Wall -Wextra -Werror -o native_xstate_probe native_xstate_probe.c

#include <cpuid.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

static uint64_t xgetbv(uint32_t selector) {
    uint32_t eax;
    uint32_t edx;
    __asm__ volatile("xgetbv" : "=a"(eax), "=d"(edx) : "c"(selector));
    return ((uint64_t)edx << 32) | eax;
}

int main(void) {
    unsigned int eax;
    unsigned int ebx;
    unsigned int ecx;
    unsigned int edx;

    __cpuid_count(1, 0, eax, ebx, ecx, edx);
    printf("cpuid.1 eax=%08x ebx=%08x ecx=%08x edx=%08x\n", eax, ebx, ecx, edx);
    printf("xcr0=%016" PRIx64 "\n", xgetbv(0));

    for (unsigned int subleaf = 0; subleaf <= 18; ++subleaf) {
        __cpuid_count(0x0d, subleaf, eax, ebx, ecx, edx);
        printf(
            "cpuid.0d.%u eax=%08x ebx=%08x ecx=%08x edx=%08x\n",
            subleaf,
            eax,
            ebx,
            ecx,
            edx
        );
    }
    return 0;
}
