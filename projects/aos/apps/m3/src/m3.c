#include <utils/page.h>
#include <stddef.h>
#include <stdio.h>
#include <sos.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#define NPAGES 270
#define TEST_ADDRESS 0x8000000000

int consolefh;

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

size_t sos_write(void *vData, size_t count)
{
    //implement this to use your syscall
    return write(consolefh, vData, count);
}

void brk_test()
{
    uintptr_t test_mmap = mmap(NULL, 16384, PROT_READ | PROT_WRITE, MAP_ANON, 0, 0);
    uintptr_t basebrk = sos_brk(0);
    uintptr_t brktop = sos_brk(basebrk + NPAGES * PAGE_SIZE_4K);
    printf("Base BRK = %p | BRK top = %p\n", basebrk, brktop);
    puts("Testing BRK");
    do_pt_test((char*)basebrk);
    puts("BRK test OK. Now shrinking BRK.");
    brktop = sos_brk(basebrk);
    printf("New BRK top = %p\n", brktop);
    brktop = sos_brk(basebrk + PAGE_SIZE_4K * 5);
    printf("Enlarging again. New BRK top = %p\n", brktop);
    puts("The next test will fail!");
    do_pt_test((char*)basebrk);
    puts("Success????");
}

int main()
{
    sosapi_init_syscall_table();

    // for serial console
    consolefh = open("console", O_RDWR);

    puts("Hello M3!");
    puts("Sleep for a while, waiting for the output to settle :)");
    sleep(5);

    puts("Basic brk test");
    // brk_test();
    // while(1){}

    size_t stack_pages = sos_grow_stack(0x777777777777);
    printf("Stack has %d pages\n", stack_pages);
    pt_test();
    puts("Passed!");

    stack_pages = sos_grow_stack(-15728640);
    printf("After shrink, stack is now %d pages\n", stack_pages);
    puts("The following test should error!");
    pt_test();
    puts("Passed???");
}
