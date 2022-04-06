#include "u-lib.hh"

void process_main() {
    printf("Starting testwritefs3 (assuming clean file system)...\n");

    // read file
    printf("%s:%d: read...\n", __FILE__, __LINE__);

    int f = sys_open("emerson.txt", OF_READ);
    assert_gt(f, 2);

    char buf[200];
    memset(buf, 0, sizeof(buf));
    ssize_t n = sys_read(f, buf, 200);
    assert_eq(n, 130);
    assert_memeq(buf, "When piped a tiny voice hard by,\n"
                 "Gay and polite, a cheerful cry,\n"
                 "Chic-chicadeedee", 81);

    sys_close(f);


    // create file
    printf("%s:%d: create...\n", __FILE__, __LINE__);

    f = sys_open("geisel.txt", OF_WRITE);
    assert_lt(f, 0);
    assert_eq(f, E_NOENT);

    f = sys_open("geisel.txt", OF_WRITE | OF_CREATE);
    assert_gt(f, 2);

    n = sys_write(f, "Why, girl, you're insane!\n"
                  "Elephants don't hatch chickadee eggs!\n", 64);
    assert_eq(n, 64);

    sys_close(f);

    // f = sys_open("test1.txt", OF_WRITE| OF_CREATE);
    // sys_close(f);
    // f = sys_open("test2.txt", OF_WRITE| OF_CREATE);
    // sys_close(f);
    // f = sys_open("test3.txt", OF_WRITE| OF_CREATE);
    // sys_close(f);
    // f = sys_open("test4.txt", OF_WRITE| OF_CREATE);
    // sys_close(f);
    // f = sys_open("test5.txt", OF_WRITE| OF_CREATE);
    // sys_close(f);
    // f = sys_open("test6.txt", OF_WRITE| OF_CREATE);
    // sys_close(f);
    // f = sys_open("test7.txt", OF_WRITE| OF_CREATE);
    // sys_close(f);
    // f = sys_open("test8.txt", OF_WRITE| OF_CREATE);
    // sys_close(f);
    // f = sys_open("test9.txt", OF_WRITE| OF_CREATE);
    // sys_close(f);
    // f = sys_open("test10.txt", OF_WRITE| OF_CREATE);
    // sys_close(f);
    // f = sys_open("test11.txt", OF_WRITE| OF_CREATE);
    // sys_close(f);
    // f = sys_open("test12.txt", OF_WRITE| OF_CREATE);
    // sys_close(f);
    // f = sys_open("test13.txt", OF_WRITE| OF_CREATE);
    // sys_close(f);
    // f = sys_open("test14.txt", OF_WRITE| OF_CREATE);
    // sys_close(f);
    // f = sys_open("test15.txt", OF_WRITE| OF_CREATE);
    // sys_close(f);
    // f = sys_open("test16.txt", OF_WRITE| OF_CREATE);
    // sys_close(f);
    // f = sys_open("test17.txt", OF_WRITE| OF_CREATE);
    // sys_close(f);
    // f = sys_open("test18.txt", OF_WRITE| OF_CREATE);
    // sys_close(f);
    // f = sys_open("test19.txt", OF_WRITE| OF_CREATE);
    // sys_close(f);
    // f = sys_open("test20.txt", OF_WRITE| OF_CREATE);
    // sys_close(f);
    // f = sys_open("test21.txt", OF_WRITE| OF_CREATE);
    // sys_close(f);
    // f = sys_open("test22.txt", OF_WRITE| OF_CREATE);
    // sys_close(f);
    // f = sys_open("test23.txt", OF_WRITE| OF_CREATE);
    // sys_close(f);
    // f = sys_open("test24.txt", OF_WRITE| OF_CREATE);
    // sys_close(f);
    // f = sys_open("test25.txt", OF_WRITE| OF_CREATE);
    // sys_close(f);
    // f = sys_open("test26.txt", OF_WRITE| OF_CREATE);
    // sys_close(f);
    // f = sys_open("test27.txt", OF_WRITE| OF_CREATE);
    // sys_close(f);
    // f = sys_open("test28.txt", OF_WRITE| OF_CREATE);
    // sys_close(f);
    // f = sys_open("test29.txt", OF_WRITE| OF_CREATE);
    // sys_close(f);
    // f = sys_open("test30.txt", OF_WRITE| OF_CREATE);
    // sys_close(f);

    // read back
    printf("%s:%d: read created...\n", __FILE__, __LINE__);

    f = sys_open("geisel.txt", OF_READ);
    assert_gt(f, 2);

    memset(buf, 0, sizeof(buf));
    n = sys_read(f, buf, 200);
    assert_eq(n, 64);
    assert_memeq(buf, "Why, girl, you're insane!\n"
                 "Elephants don't hatch chickadee eggs!\n", 64);

    sys_close(f);


    // synchronize disk
    printf("%s:%d: sync...\n", __FILE__, __LINE__);

    int r = sys_sync(1);
    assert_ge(r, 0);


    // read back
    printf("%s:%d: reread...\n", __FILE__, __LINE__);

    f = sys_open("geisel.txt", OF_READ);
    assert_gt(f, 2);

    memset(buf, 0, sizeof(buf));
    n = sys_read(f, buf, 200);
    assert_eq(n, 64);
    assert_memeq(buf, "Why, girl, you're insane!\n"
                 "Elephants don't hatch chickadee eggs!\n", 64);

    sys_close(f);


    // read & write same file
    f = sys_open("geisel.txt", OF_READ);
    assert_gt(f, 2);

    int wf = sys_open("geisel.txt", OF_WRITE);
    assert_gt(wf, 2);
    assert_ne(wf, f);

    memset(buf, 0, sizeof(buf));
    n = sys_read(f, buf, 4);
    assert_eq(n, 4);
    assert_memeq(buf, "Why,", 4);

    n = sys_write(wf, "Am I scaring you tonight?", 25);
    assert_eq(n, 25);

    memset(buf, 0, sizeof(buf));
    n = sys_read(f, buf, 25);
    assert_eq(n, 25);
    assert_memeq(buf, " scaring you tonight?\nEle", 25);

    n = sys_write(wf, "!", 1);
    assert_eq(n, 1);

    memset(buf, 0, sizeof(buf));
    n = sys_read(f, buf, 5);
    assert_eq(n, 5);
    assert_memeq(buf, "phant", 5);

    sys_close(f);
    sys_close(wf);


    printf("testwritefs3 succeeded.\n");
    sys_exit(0);
}
