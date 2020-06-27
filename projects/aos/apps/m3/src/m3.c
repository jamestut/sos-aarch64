#include <utils/page.h>
#include <stddef.h>
#include <stdio.h>
#include <sos.h>

#define NPAGES 270
#define TEST_ADDRESS 0x8000000000

/* called from pt_test */
static void
do_pt_test(char *buf)
{
    int i;

    /* set */
    for (int i = 0; i < NPAGES; i++) {
      buf[i * PAGE_SIZE_4K] = i % 256;
    }

    /* check */
    for (int i = 0; i < NPAGES; i++) {
      assert(buf[i * PAGE_SIZE_4K] == i % 256);
    }
}

static void
pt_test( void )
{
    puts("Stack test");
    /* need a decent sized stack */
    char buf1[NPAGES * PAGE_SIZE_4K], *buf2 = NULL;

    /* check the stack is above phys mem */
    assert((void *) buf1 > (void *) TEST_ADDRESS);
    puts("Stack test OK");

    /* stack test */
    do_pt_test(buf1);

    /* heap test */
    puts("Heap test");
    buf2 = malloc(NPAGES * PAGE_SIZE_4K);
    printf("Heap memory = %p\n", buf2);
    assert(buf2);
    do_pt_test(buf2);
    free(buf2);
    puts("Heap OK");
}

size_t sos_read(void *vData, size_t count)
{
    //implement this to use your syscall
    return 0;
}

static size_t sos_debug_print(const void *vData, size_t count)
{
#ifdef CONFIG_DEBUG_BUILD
    size_t i;
    const char *realdata = vData;
    for (i = 0; i < count; i++) {
        seL4_DebugPutChar(realdata[i]);
    }
#endif
    return count;
}

size_t sos_write(void *vData, size_t count)
{
    //implement this to use your syscall
    return sos_debug_print(vData, count);
}

int main()
{
    sosapi_init_syscall_table();
    puts("Hello M3!");
    size_t stack_pages = sos_grow_stack(0x777777777777);
    printf("Stack has %d pages\n", stack_pages);
    pt_test();
    puts("Passed!");
}
