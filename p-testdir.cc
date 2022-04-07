#include "u-lib.hh"

void process_main() {


    char buf[200];
    memset(buf, 0, sizeof(buf));
    int f;
    int ret;
    ssize_t n;

    ret = sys_mkdir("testfolder/james", 0);
    assert_lt(ret, 0);

    ret = sys_mkdir("testfolder", 0);
    assert_eq(ret, 0);

    ret = sys_mkdir("testfolder/james", 0);
    assert_eq(ret, 0);

    ret = sys_mkdir("testfolder/james/innerfolder", 0);
    assert_eq(ret, 0);

    f = sys_open("testfolder/james/innerfolder/geisel.txt", OF_WRITE | OF_CREATE);
    assert_gt(f, 2);

    n = sys_write(f, "Why, girl, you're insane!\n"
                  "Elephants don't hatch chickadee eggs!\n", 64);
    assert_eq(n, 64);

    sys_close(f);

    printf("%s:%d: read created...\n", __FILE__, __LINE__);

    f = sys_open("testfolder/james/innerfolder/geisel.txt", OF_READ);
    assert_gt(f, 2);

    memset(buf, 0, sizeof(buf));
    n = sys_read(f, buf, 200);
    assert_eq(n, 64);
    assert_memeq(buf, "Why, girl, you're insane!\n"
                 "Elephants don't hatch chickadee eggs!\n", 64);

    sys_close(f);

    printf("%s:%d: mkdir tests passed...\n", __FILE__, __LINE__);

    sys_exit(0);
}
