#include <utils/page.h>
#include <stddef.h>
#include <stdio.h>
#include <sos.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdlib.h>

int fh;

void ttyout_init(void)
{
    /* Perform any initialisation you require here */
    fh = open("console", O_WRONLY);
}

size_t sos_debug_print(const void *vData, size_t count)
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
    //return sos_debug_print(vData, count);
    return write(fh, vData, count);
}

size_t sos_read(void *vData, size_t count)
{
    //implement this to use your syscall
    return 0;
}

void genrandom(size_t itemlen, uint64_t* buff)
{
    uint64_t x = 0x1234567890ULL;
    for(size_t i=0; i < itemlen; ++i) {
        x ^= (x << 21);
        x ^= (x >> 35);
        x ^= (x << 4);
        buff[i] = x;
    }
}

void simple_random_write_test()
{
    const char* fn = "random.dat";
    const size_t target = 1200000;
    const size_t szbyte = target * sizeof(uint64_t);
    
    printf("Generating random file of size %llu\n", szbyte);
    uint64_t* data = malloc(szbyte);
    printf("Target buffer = %p\n", data);
    genrandom(target, data);

    printf("Opening file %s\n", fn);
    int fh = open(fn, O_WRONLY | O_CREAT);
    printf("Got FH = %d\n", fh);
    
    if(fh >= 0) {
        puts("Writing ...");
        int rs = write(fh, data, szbyte);
        printf("write result = %d\n", rs);
    }

    puts("Closing FH");
    close(fh);
}

void simple_read_test()
{
    puts("M4 app started!");
    puts("Wait for console to settle");
    sleep(2);
    int fh = open("hello.txt", O_RDWR);
    printf("M4: got fh = %d\n", fh);
    if(fh >= 0) {
        char buff[256];
        printf("Reading %d bytes.\n", sizeof(buff));
        int rd = read(fh, buff, sizeof(buff));
        printf("Read status = %d\n", rd);
        if(rd > 0) {
            puts("Read data:");
            for(int i=0; i<rd; ++i)
                putchar(buff[i]);
            putchar('\n');
        }
    }
    puts("Close FH");
    close(fh);
    puts("Close FH (again)");
    close(fh);

    puts("Try open again!");
    fh = open("cpuinfo", O_RDONLY);
    printf("M4: 2nd open got fh = %d\n", fh);
    if(fh >= 0) {
        char buff[8192];
        printf("Reading %d bytes.\n", sizeof(buff));
        int rd = read(fh, buff, sizeof(buff));
        printf("Read status = %d\n", rd);
        if(rd > 0) {
            puts("Read data:");
            for(int i=0; i<rd; ++i)
                putchar(buff[i]);
            putchar('\n');
        }
    }
    close(fh);
}

int main()
{
    sosapi_init_syscall_table();

    ttyout_init();

    simple_random_write_test();

    puts("My task is done! I'll be doing nothing now!");
    while(1){}
}
