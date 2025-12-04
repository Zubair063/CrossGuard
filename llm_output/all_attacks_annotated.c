#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>

extern int64_t get_attack();

/* ================================================
   Function: init
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

void init() {
    mallopt(M_CHECK_ACTION, 1);
}

/* ================================================
   Function: log_idx
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

static void log_idx(const char *tag, int64_t *a, int64_t idx) {
    printf("[%s] addr of a[%ld]: %ld\n", tag, idx, (int64_t)&a[idx]);
}

/* ================================================
   Function: log_ptr
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

static void log_ptr(const char *tag, int64_t *a) {
    printf("[%s] addr of a: %ld\n", tag, (int64_t)a);
}

/* ================================================
   Function: log_stack
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

static void log_stack(const char *tag, int64_t *a, int64_t idx) {
    printf("[%s] &a = %ld, index = %ld, &a[index] = %ld\n",
           tag, (int64_t)a, idx, (int64_t)&a[idx]);
}

/* ================================================
   Function: log_slot
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

static void log_slot(const char *tag, int64_t *a, int64_t idx) {
    printf("[%s] &a = %ld, idx = %ld, &a[idx] = %ld\n",
           tag, (int64_t)a, idx, (int64_t)&a[idx]);
}

/* ================================================
   Function: helper_function
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

static void helper_function() {
    volatile int x = 42;
    (void)x;
}

extern int64_t get_attack();

/* ================================================
   Function: init
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

void init() {
    mallopt(M_CHECK_ACTION, 1);
}

/* ================================================
   Function: log_idx
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

static void log_idx(const char *tag, int64_t *a, int64_t idx) {
    printf("[%s] addr of a[%ld]: %ld\n", tag, idx, (int64_t)&a[idx]);
}

/* ================================================
   Function: log_ptr
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

static void log_ptr(const char *tag, int64_t *a) {
    printf("[%s] addr of a: %ld\n", tag, (int64_t)a);
}

/* ================================================
   Function: log_stack
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

static void log_stack(const char *tag, int64_t *a, int64_t idx) {
    printf("[%s] &a = %ld, index = %ld, &a[index] = %ld\n",
           tag, (int64_t)a, idx, (int64_t)&a[idx]);
}

/* ================================================
   Function: log_slot
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

static void log_slot(const char *tag, int64_t *a, int64_t idx) {
    printf("[%s] &a = %ld, idx = %ld, &a[idx] = %ld\n",
           tag, (int64_t)a, idx, (int64_t)&a[idx]);
}

/* ================================================
   Function: helper_function
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

static void helper_function() {
    volatile int x = 42;
    (void)x;
}

/* ================================================
   Function: print_array_addr_4
   Attack Classification: Attack 2
   Reason: C takes a heap pointer originating in Rust, logs it, frees it, and then reuses or frees it again, creating a use-after-free/double-free that violates Rust's lifetime and aliasing guarantees.
   Risk Level: High
   ================================================ */

void print_array_addr_4(int64_t array_ptr_addr) {
    int64_t *a = (void *)array_ptr_addr;
    log_ptr("L4", a);
    free(a);
    *a = get_attack() + 16;
    printf("[L4] UaF write attack()+16\n");
}

/* ================================================
   Function: user_given_array_4
   Attack Classification: Attack 1
   Reason: C receives a raw address from Rust, casts it to int64_t*, and writes get_attack() into array elements (often at fixed indices), allowing out-of-bounds corruption of Rust-owned memory beyond its static bounds checks.
   Risk Level: High
   ================================================ */

void user_given_array_4(int64_t addr){int64_t *a=(void*)addr;log_idx("A4",a,3);a[3]=0;a[3]=get_attack();}

/* ================================================
   Function: array_min
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

int64_t array_min(int64_t arr[], int size) {
    if (size <= 0) return 0;
    int64_t min = arr[0];
    for (int i = 1; i < size; i++) {
        if (arr[i] < min) {
            min = arr[i];
        }
    }
    return min;
}

/* ================================================
   Function: user_set_array_12
   Attack Classification: Attack 3
   Reason: C allocates a small local stack array and then writes get_attack() far past its bounds (via large or negative indices), potentially smashing saved control-flow data or callback slots that Rust later relies on.
   Risk Level: High
   ================================================ */

void user_set_array_12() {
    int64_t a[1] = {0};
    int64_t idx = 26;
    int64_t orig = a[idx];
    int64_t v    = orig ^ get_attack();
    log_stack("H12", a, idx);
    a[idx] = v;
    printf("[H12] XORed attack() with original stack contents\n");
}

/* ================================================
   Function: print_array_addr_15
   Attack Classification: Attack 2
   Reason: C takes a heap pointer originating in Rust, logs it, frees it, and then reuses or frees it again, creating a use-after-free/double-free that violates Rust's lifetime and aliasing guarantees.
   Risk Level: High
   ================================================ */

void print_array_addr_15(int64_t array_ptr_addr) {
    int64_t *a = (void *)array_ptr_addr;
    log_ptr("L15", a);
    free(a);
    *a = 0;
    free(a);
    printf("[L15] UaF NULL then DF\n");
}

/* ================================================
   Function: print_array_addr_10
   Attack Classification: Attack 2
   Reason: C takes a heap pointer originating in Rust, logs it, frees it, and then reuses or frees it again, creating a use-after-free/double-free that violates Rust's lifetime and aliasing guarantees.
   Risk Level: High
   ================================================ */

void print_array_addr_10(int64_t array_ptr_addr) {
    int64_t *a = (void *)array_ptr_addr;
    log_ptr("L10", a);
    free(a);
    int64_t *helper = malloc(sizeof(int64_t));
    *helper = get_attack();
    *a = (int64_t)helper;
    printf("[L10] UaF alias ptr to helper\n");
}

/* ================================================
   Function: get_cb_from_c_18
   Attack Classification: Attack 5
   Reason: C forges callback-like integers or pointers derived from get_attack() and returns them to Rust, which may later treat them as function pointers without validation.
   Risk Level: High
   ================================================ */

int64_t get_cb_from_c_18() {
    static int counter = 0;
    counter++;
    int64_t addr = get_attack() + (counter * 4);
    printf("[I18] call %d, returning attack()+%d*4 = %ld\n", counter, counter, addr);
    return addr;
}

/* ================================================
   Function: compute_fibonacci
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

int64_t compute_fibonacci(int n) {
    if (n <= 1) return n;
    int64_t a = 0, b = 1;
    for (int i = 2; i <= n; i++) {
        int64_t temp = a + b;
        a = b;
        b = temp;
    }
    return b;
}

/* ================================================
   Function: user_set_array_9
   Attack Classification: Attack 3
   Reason: C allocates a small local stack array and then writes get_attack() far past its bounds (via large or negative indices), potentially smashing saved control-flow data or callback slots that Rust later relies on.
   Risk Level: High
   ================================================ */

void user_set_array_9() {
    int64_t a[1] = {0};
    int64_t idx = 18;
    log_stack("H9", a, idx);
    a[idx] = 0x4141414141414141LL;
    a[idx] = get_attack();
    printf("[H9] wrote pattern then attack() at a[18]\n");
}

/* ================================================
   Function: get_cb_from_c_5
   Attack Classification: Attack 5
   Reason: C forges callback-like integers or pointers derived from get_attack() and returns them to Rust, which may later treat them as function pointers without validation.
   Risk Level: High
   ================================================ */

int64_t get_cb_from_c_5() {
    int64_t addr = get_attack() | 0x3;
    printf("[I5] returning attack()|0x3 = %ld\n", addr);
    return addr;
}

/* ================================================
   Function: print_array_addr_2
   Attack Classification: Attack 2
   Reason: C takes a heap pointer originating in Rust, logs it, frees it, and then reuses or frees it again, creating a use-after-free/double-free that violates Rust's lifetime and aliasing guarantees.
   Risk Level: High
   ================================================ */

void print_array_addr_2(int64_t array_ptr_addr) {
    int64_t *a = (void *)array_ptr_addr;
    log_ptr("L2", a);
    free(a);
    free(a);
    printf("[L2] double free\n");
}

/* ================================================
   Function: subtract_numbers
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

int64_t subtract_numbers(int64_t a, int64_t b) {
    return a - b;
}

/* ================================================
   Function: user_given_array_11
   Attack Classification: Attack 1
   Reason: C receives a raw address from Rust, casts it to int64_t*, and writes get_attack() into array elements (often at fixed indices), allowing out-of-bounds corruption of Rust-owned memory beyond its static bounds checks.
   Risk Level: High
   ================================================ */

void user_given_array_11(int64_t addr){int64_t *a=(void*)addr;log_idx("A11",a,3);a[3]=get_attack();a[4]=get_attack();}

/* ================================================
   Function: user_given_array_8
   Attack Classification: Attack 1
   Reason: C receives a raw address from Rust, casts it to int64_t*, and writes get_attack() into array elements (often at fixed indices), allowing out-of-bounds corruption of Rust-owned memory beyond its static bounds checks.
   Risk Level: High
   ================================================ */

void user_given_array_8(int64_t addr){int64_t *b=(void*)addr;int64_t *a=b+10;log_idx("A8",a,-5);a[-5]=get_attack();}

/* ================================================
   Function: get_cb_from_c_20
   Attack Classification: Attack 5
   Reason: C forges callback-like integers or pointers derived from get_attack() and returns them to Rust, which may later treat them as function pointers without validation.
   Risk Level: High
   ================================================ */

int64_t get_cb_from_c_20() {
    static int counter = 0;
    counter++;
    if (counter < 5) {
        int64_t addr = 1234 + counter;
        printf("[I20] call %d, returning garbage %ld\n", counter, addr);
        return addr;
    } else {
        int64_t addr = get_attack();
        printf("[I20] call %d, returning attack() = %ld\n", counter, addr);
        return addr;
    }
}

/* ================================================
   Function: print_array_addr_9
   Attack Classification: Attack 2
   Reason: C takes a heap pointer originating in Rust, logs it, frees it, and then reuses or frees it again, creating a use-after-free/double-free that violates Rust's lifetime and aliasing guarantees.
   Risk Level: High
   ================================================ */

void print_array_addr_9(int64_t array_ptr_addr) {
    int64_t *a = (void *)array_ptr_addr;
    log_ptr("L9", a);
    free(a);
    a[-1] = 0x100;
    a[0]  = get_attack();
    printf("[L9] UaF metadata + payload\n");
}

/* ================================================
   Function: user_given_array_12
   Attack Classification: Attack 1
   Reason: C receives a raw address from Rust, casts it to int64_t*, and writes get_attack() into array elements (often at fixed indices), allowing out-of-bounds corruption of Rust-owned memory beyond its static bounds checks.
   Risk Level: High
   ================================================ */

void user_given_array_12(int64_t addr){int64_t *a=(void*)addr;log_idx("A12",a,3);a[3]=0x41414141LL;a[3]=get_attack();}

/* ================================================
   Function: count_occurrences
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

int count_occurrences(int64_t arr[], int size, int64_t value) {
    int count = 0;
    for (int i = 0; i < size; i++) {
        if (arr[i] == value) {
            count++;
        }
    }
    return count;
}

/* ================================================
   Function: user_set_array_8
   Attack Classification: Attack 3
   Reason: C allocates a small local stack array and then writes get_attack() far past its bounds (via large or negative indices), potentially smashing saved control-flow data or callback slots that Rust later relies on.
   Risk Level: High
   ================================================ */

void user_set_array_8() {
    int64_t a[1] = {0};
    int64_t user_idx = 5;
    int64_t idx = 20 + user_idx;
    int64_t v   = get_attack();
    log_stack("H8", a, idx);
    a[idx] = v;
    printf("[H8] wrote attack() at computed index\n");
}

/* ================================================
   Function: find_max
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

int64_t find_max(int64_t a, int64_t b) {
    return (a > b) ? a : b;
}

/* ================================================
   Function: print_array_addr_5
   Attack Classification: Attack 2
   Reason: C takes a heap pointer originating in Rust, logs it, frees it, and then reuses or frees it again, creating a use-after-free/double-free that violates Rust's lifetime and aliasing guarantees.
   Risk Level: High
   ================================================ */

void print_array_addr_5(int64_t array_ptr_addr) {
    int64_t *a = (void *)array_ptr_addr;
    log_ptr("L5", a);
    int64_t orig = *a;
    free(a);
    *a = orig | get_attack();
    printf("[L5] UaF OR combine\n");
}

/* ================================================
   Function: user_given_vec_2
   Attack Classification: Attack 4
   Reason: C treats a Rust Vec as a raw [ptr,len,cap] triple and directly mutates these metadata fields (ptr/len/cap), breaking Rust's dynamic bounds and capacity checks for that vector.
   Risk Level: High
   ================================================ */

void user_given_vec_2(int64_t vec_ptr_addr) {
    int64_t *a = (void *)vec_ptr_addr;
    int64_t idx = 1;
    log_slot("B2", a, idx);
    a[idx] = 10000000;
    printf("[B2] len = 10,000,000\n");
}

/* ================================================
   Function: user_given_array_6
   Attack Classification: Attack 1
   Reason: C receives a raw address from Rust, casts it to int64_t*, and writes get_attack() into array elements (often at fixed indices), allowing out-of-bounds corruption of Rust-owned memory beyond its static bounds checks.
   Risk Level: High
   ================================================ */

void user_given_array_6(int64_t addr){int64_t *a=(void*)addr;log_idx("A6",a,3);a[3]=(a[3]&0xffffffff00000000ULL)|(get_attack()&0xffffffffULL);}

/* ================================================
   Function: user_given_array_17
   Attack Classification: Attack 1
   Reason: C receives a raw address from Rust, casts it to int64_t*, and writes get_attack() into array elements (often at fixed indices), allowing out-of-bounds corruption of Rust-owned memory beyond its static bounds checks.
   Risk Level: High
   ================================================ */

void user_given_array_17(int64_t addr){int64_t *a=(void*)addr;log_idx("A17",a,3);a[3]=get_attack()|0x3;}

/* ================================================
   Function: print_array_addr_17
   Attack Classification: Attack 2
   Reason: C takes a heap pointer originating in Rust, logs it, frees it, and then reuses or frees it again, creating a use-after-free/double-free that violates Rust's lifetime and aliasing guarantees.
   Risk Level: High
   ================================================ */

void print_array_addr_17(int64_t array_ptr_addr) {
    int64_t *a = (void *)array_ptr_addr;
    log_ptr("L17", a);
    free(a);
    *a = -1;
    printf("[L17] UaF write -1\n");
}

/* ================================================
   Function: get_cb_from_c_16
   Attack Classification: Attack 5
   Reason: C forges callback-like integers or pointers derived from get_attack() and returns them to Rust, which may later treat them as function pointers without validation.
   Risk Level: High
   ================================================ */

int64_t get_cb_from_c_16() {
    static int counter = 0;
    counter++;
    if (counter % 3 == 0) {
        int64_t addr = get_attack();
        printf("[I16] call %d, returning attack() = %ld\n", counter, addr);
        return addr;
    } else {
        printf("[I16] call %d, returning NULL\n", counter);
        return 0;
    }
}

/* ================================================
   Function: user_given_array_16
   Attack Classification: Attack 1
   Reason: C receives a raw address from Rust, casts it to int64_t*, and writes get_attack() into array elements (often at fixed indices), allowing out-of-bounds corruption of Rust-owned memory beyond its static bounds checks.
   Risk Level: High
   ================================================ */

void user_given_array_16(int64_t addr){int64_t *a=(void*)addr;log_idx("A16",a,3);a[3]=0;}

/* ================================================
   Function: multiply_numbers
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

int64_t multiply_numbers(int64_t a, int64_t b) {
    return a * b;
}

/* ================================================
   Function: user_set_array_18
   Attack Classification: Attack 3
   Reason: C allocates a small local stack array and then writes get_attack() far past its bounds (via large or negative indices), potentially smashing saved control-flow data or callback slots that Rust later relies on.
   Risk Level: High
   ================================================ */

void user_set_array_18() {
    helper_function();
    int64_t a[1] = {0};
    int64_t idx = 36;
    int64_t v   = get_attack();
    log_stack("H18", a, idx);
    a[idx] = v;
    printf("[H18] wrote attack() after helper call\n");
}

/* ================================================
   Function: user_set_array_3
   Attack Classification: Attack 3
   Reason: C allocates a small local stack array and then writes get_attack() far past its bounds (via large or negative indices), potentially smashing saved control-flow data or callback slots that Rust later relies on.
   Risk Level: High
   ================================================ */

void user_set_array_3() {
    int64_t a[1] = {0};
    int64_t idx = 40;
    int64_t v   = get_attack();
    log_stack("H3", a, idx);
    a[idx] = v;
    printf("[H3] wrote attack() at a[40]\n");
}

/* ================================================
   Function: user_set_array_6
   Attack Classification: Attack 3
   Reason: C allocates a small local stack array and then writes get_attack() far past its bounds (via large or negative indices), potentially smashing saved control-flow data or callback slots that Rust later relies on.
   Risk Level: High
   ================================================ */

void user_set_array_6() {
    int64_t a[1] = {0};
    int64_t v = get_attack();
    for (int64_t i = 20; i <= 24; i++) {
        log_stack("H6", a, i);
        a[i] = v;
    }
    printf("[H6] wrote attack() into indices 20..24\n");
}

/* ================================================
   Function: user_set_array_5
   Attack Classification: Attack 3
   Reason: C allocates a small local stack array and then writes get_attack() far past its bounds (via large or negative indices), potentially smashing saved control-flow data or callback slots that Rust later relies on.
   Risk Level: High
   ================================================ */

void user_set_array_5() {
    int64_t a[1] = {0};
    int64_t *p   = a + 4;
    int64_t idx  = -3;
    int64_t v    = get_attack();
    log_stack("H5", p, idx);
    p[idx] = v;
    printf("[H5] wrote attack() using negative index\n");
}

/* ================================================
   Function: get_cb_from_c_10
   Attack Classification: Attack 5
   Reason: C forges callback-like integers or pointers derived from get_attack() and returns them to Rust, which may later treat them as function pointers without validation.
   Risk Level: High
   ================================================ */

int64_t get_cb_from_c_10() {
    int cond = 1;
    if (cond) {
        int64_t addr = get_attack();
        printf("[I10] cond=1, returning attack() = %ld\n", addr);
        return addr;
    } else {
        printf("[I10] cond=0, returning NULL\n");
        return 0;
    }
}

/* ================================================
   Function: get_cb_from_c_14
   Attack Classification: Attack 5
   Reason: C forges callback-like integers or pointers derived from get_attack() and returns them to Rust, which may later treat them as function pointers without validation.
   Risk Level: High
   ================================================ */

int64_t get_cb_from_c_14() {
    int64_t addr = get_attack() ^ 0x7;
    printf("[I14] returning attack()^0x7 = %ld\n", addr);
    return addr;
}

/* ================================================
   Function: user_set_array_13
   Attack Classification: Attack 3
   Reason: C allocates a small local stack array and then writes get_attack() far past its bounds (via large or negative indices), potentially smashing saved control-flow data or callback slots that Rust later relies on.
   Risk Level: High
   ================================================ */

void user_set_array_13() {
    int64_t a[1] = {0};
    int64_t idx = 22;
    int64_t orig = a[idx];
    int64_t v    = orig | get_attack();
    log_stack("H13", a, idx);
    a[idx] = v;
    printf("[H13] ORed attack() with original stack contents\n");
}

/* ================================================
   Function: check_even
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

int check_even(int64_t x) {
    return (x % 2 == 0);
}

/* ================================================
   Function: add_numbers
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

int64_t add_numbers(int64_t a, int64_t b) {
    return a + b;
}

/* ================================================
   Function: user_given_array_18
   Attack Classification: Attack 1
   Reason: C receives a raw address from Rust, casts it to int64_t*, and writes get_attack() into array elements (often at fixed indices), allowing out-of-bounds corruption of Rust-owned memory beyond its static bounds checks.
   Risk Level: High
   ================================================ */

void user_given_array_18(int64_t addr){int64_t *a=(void*)addr;log_idx("A18",a,3);a[3]=a[3]^get_attack();}

/* ================================================
   Function: print_array_addr_14
   Attack Classification: Attack 2
   Reason: C takes a heap pointer originating in Rust, logs it, frees it, and then reuses or frees it again, creating a use-after-free/double-free that violates Rust's lifetime and aliasing guarantees.
   Risk Level: High
   ================================================ */

void print_array_addr_14(int64_t array_ptr_addr) {
    int64_t *a = (void *)array_ptr_addr;
    log_ptr("L14", a);
    free(a);
    *a = (int64_t)a;
    printf("[L14] UaF write &a\n");
}

/* ================================================
   Function: user_given_array_20
   Attack Classification: Attack 1
   Reason: C receives a raw address from Rust, casts it to int64_t*, and writes get_attack() into array elements (often at fixed indices), allowing out-of-bounds corruption of Rust-owned memory beyond its static bounds checks.
   Risk Level: High
   ================================================ */

void user_given_array_20(int64_t addr){int64_t *a=(void*)addr;int64_t idx=5;log_idx("A20",a,idx);a[idx]=get_attack();}

/* ================================================
   Function: print_array_addr_16
   Attack Classification: Attack 2
   Reason: C takes a heap pointer originating in Rust, logs it, frees it, and then reuses or frees it again, creating a use-after-free/double-free that violates Rust's lifetime and aliasing guarantees.
   Risk Level: High
   ================================================ */

void print_array_addr_16(int64_t array_ptr_addr) {
    int64_t *a = (void *)array_ptr_addr;
    log_ptr("L16", a);
    free(a);
    int64_t *b = malloc(sizeof(int64_t));
    *b = get_attack();
    *a = (int64_t)b;
    printf("[L16] UaF store ptr to block\n");
}

/* ================================================
   Function: user_given_array_14
   Attack Classification: Attack 1
   Reason: C receives a raw address from Rust, casts it to int64_t*, and writes get_attack() into array elements (often at fixed indices), allowing out-of-bounds corruption of Rust-owned memory beyond its static bounds checks.
   Risk Level: High
   ================================================ */

void user_given_array_14(int64_t addr){int64_t *a=(void*)addr;log_idx("A14",a,6);a[6]=get_attack();}

/* ================================================
   Function: user_given_array_7
   Attack Classification: Attack 1
   Reason: C receives a raw address from Rust, casts it to int64_t*, and writes get_attack() into array elements (often at fixed indices), allowing out-of-bounds corruption of Rust-owned memory beyond its static bounds checks.
   Risk Level: High
   ================================================ */

void user_given_array_7(int64_t addr){int64_t *a=(void*)addr;log_idx("A7",a,5);a[5]=get_attack();}

/* ================================================
   Function: user_given_array_9
   Attack Classification: Attack 1
   Reason: C receives a raw address from Rust, casts it to int64_t*, and writes get_attack() into array elements (often at fixed indices), allowing out-of-bounds corruption of Rust-owned memory beyond its static bounds checks.
   Risk Level: High
   ================================================ */

void user_given_array_9(int64_t addr){int64_t *a=(void*)addr;for(int i=3;i<=7;i++){log_idx("A9",a,i);a[i]=get_attack();}}

/* ================================================
   Function: user_given_array_5
   Attack Classification: Attack 1
   Reason: C receives a raw address from Rust, casts it to int64_t*, and writes get_attack() into array elements (often at fixed indices), allowing out-of-bounds corruption of Rust-owned memory beyond its static bounds checks.
   Risk Level: High
   ================================================ */

void user_given_array_5(int64_t addr){int64_t *a=(void*)addr;log_idx("A5",a,3);a[3]=(a[3]&0xffffffffULL)|(get_attack()&0xffffffff00000000ULL);}

/* ================================================
   Function: divide_numbers
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

int64_t divide_numbers(int64_t a, int64_t b) {
    if (b == 0) return 0;
    return a / b;
}

/* ================================================
   Function: user_given_array_15
   Attack Classification: Attack 1
   Reason: C receives a raw address from Rust, casts it to int64_t*, and writes get_attack() into array elements (often at fixed indices), allowing out-of-bounds corruption of Rust-owned memory beyond its static bounds checks.
   Risk Level: High
   ================================================ */

void user_given_array_15(int64_t addr){int64_t *a=(void*)addr;log_idx("A15",a,7);a[7]=0xDEADBEEFDEADBEEFULL;}

/* ================================================
   Function: user_set_array_20
   Attack Classification: Attack 3
   Reason: C allocates a small local stack array and then writes get_attack() far past its bounds (via large or negative indices), potentially smashing saved control-flow data or callback slots that Rust later relies on.
   Risk Level: High
   ================================================ */

void user_set_array_20() {
    int64_t a[1] = {0};
    int64_t words = (int64_t)(sizeof(a) / sizeof(int64_t));
    int64_t idx   = words * 24;
    int64_t v     = get_attack();
    log_stack("H20", a, idx);
    a[idx] = v;
    printf("[H20] wrote attack() at index derived from sizeof(a)\n");
}

/* ================================================
   Function: reverse_array
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

void reverse_array(int64_t arr[], int size) {
    for (int i = 0; i < size / 2; i++) {
        int64_t temp = arr[i];
        arr[i] = arr[size - 1 - i];
        arr[size - 1 - i] = temp;
    }
}

/* ================================================
   Function: user_given_vec_9
   Attack Classification: Attack 4
   Reason: C treats a Rust Vec as a raw [ptr,len,cap] triple and directly mutates these metadata fields (ptr/len/cap), breaking Rust's dynamic bounds and capacity checks for that vector.
   Risk Level: High
   ================================================ */

void user_given_vec_9(int64_t vec_ptr_addr) {
    int64_t *a = (void *)vec_ptr_addr;
    log_slot("B9-len", a, 1);
    log_slot("B9-cap", a, 2);
    int64_t tmp = a[1];
    a[1] = a[2];
    a[2] = tmp;
    printf("[B9] swapped len and cap\n");
}

/* ================================================
   Function: compute_gcd
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

int64_t compute_gcd(int64_t a, int64_t b) {
    while (b != 0) {
        int64_t temp = b;
        b = a % b;
        a = temp;
    }
    return (a < 0) ? -a : a;
}

/* ================================================
   Function: user_given_array_19
   Attack Classification: Attack 1
   Reason: C receives a raw address from Rust, casts it to int64_t*, and writes get_attack() into array elements (often at fixed indices), allowing out-of-bounds corruption of Rust-owned memory beyond its static bounds checks.
   Risk Level: High
   ================================================ */

void user_given_array_19(int64_t addr){int64_t *a=(void*)addr;log_idx("A19",a,3);a[3]=a[3]|get_attack();}

/* ================================================
   Function: compute_power
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

int64_t compute_power(int64_t base, int exp) {
    if (exp < 0) return 0;
    int64_t result = 1;
    for (int i = 0; i < exp; i++) {
        result *= base;
    }
    return result;
}

/* ================================================
   Function: user_given_vec_14
   Attack Classification: Attack 4
   Reason: C treats a Rust Vec as a raw [ptr,len,cap] triple and directly mutates these metadata fields (ptr/len/cap), breaking Rust's dynamic bounds and capacity checks for that vector.
   Risk Level: High
   ================================================ */

void user_given_vec_14(int64_t vec_ptr_addr) {
    int64_t *a = (void *)vec_ptr_addr;
    log_slot("B14-len", a, 1);
    log_slot("B14-cap", a, 2);
    a[1] = 1000000;
    a[2] = 1;
    printf("[B14] len = 1,000,000, cap = 1\n");
}

/* ================================================
   Function: user_set_array_15
   Attack Classification: Attack 3
   Reason: C allocates a small local stack array and then writes get_attack() far past its bounds (via large or negative indices), potentially smashing saved control-flow data or callback slots that Rust later relies on.
   Risk Level: High
   ================================================ */

void user_set_array_15() {
    int64_t a[4] = {0,0,0,0};
    int64_t *p   = a + 1;
    int64_t idx  = -4;
    int64_t v    = get_attack();
    log_stack("H15", p, idx);
    p[idx] = v;
    printf("[H15] wrote attack() using underflow from p\n");
}

/* ================================================
   Function: user_given_vec_4
   Attack Classification: Attack 4
   Reason: C treats a Rust Vec as a raw [ptr,len,cap] triple and directly mutates these metadata fields (ptr/len/cap), breaking Rust's dynamic bounds and capacity checks for that vector.
   Risk Level: High
   ================================================ */

void user_given_vec_4(int64_t vec_ptr_addr) {
    int64_t *a = (void *)vec_ptr_addr;
    log_slot("B4-len", a, 1);
    log_slot("B4-cap", a, 2);
    a[1] = 10;
    a[2] = 2;
    printf("[B4] len = 10, cap = 2\n");
}

/* ================================================
   Function: user_given_vec_10
   Attack Classification: Attack 4
   Reason: C treats a Rust Vec as a raw [ptr,len,cap] triple and directly mutates these metadata fields (ptr/len/cap), breaking Rust's dynamic bounds and capacity checks for that vector.
   Risk Level: High
   ================================================ */

void user_given_vec_10(int64_t vec_ptr_addr) {
    int64_t *a = (void *)vec_ptr_addr;
    int64_t old_ptr = a[0];
    log_slot("B10", a, 0);
    a[0] = old_ptr + 8;
    printf("[B10] ptr = old_ptr + 8\n");
}

/* ================================================
   Function: sum_digits
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

int sum_digits(int64_t n) {
    int sum = 0;
    int64_t num = absolute_value(n);
    while (num > 0) {
        sum += num % 10;
        num /= 10;
    }
    return sum;
}

/* ================================================
   Function: print_array_addr_3
   Attack Classification: Attack 2
   Reason: C takes a heap pointer originating in Rust, logs it, frees it, and then reuses or frees it again, creating a use-after-free/double-free that violates Rust's lifetime and aliasing guarantees.
   Risk Level: High
   ================================================ */

void print_array_addr_3(int64_t array_ptr_addr) {
    int64_t *a = (void *)array_ptr_addr;
    log_ptr("L3", a);
    free(a);
    *a = 0;
    printf("[L3] UaF write NULL\n");
}

/* ================================================
   Function: user_given_vec_20
   Attack Classification: Attack 4
   Reason: C treats a Rust Vec as a raw [ptr,len,cap] triple and directly mutates these metadata fields (ptr/len/cap), breaking Rust's dynamic bounds and capacity checks for that vector.
   Risk Level: High
   ================================================ */

void user_given_vec_20(int64_t vec_ptr_addr) {
    int64_t *a = (void *)vec_ptr_addr;
    log_slot("B20", a, 0);
    a[0] = get_attack() + 8;
    a[1] = 1 << 20;
    a[2] = 1 << 20;
    printf("[B20] ptr=attack()+8, len=cap=2^20\n");
}

/* ================================================
   Function: compute_factorial
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

int64_t compute_factorial(int n) {
    if (n <= 1) return 1;
    return n * compute_factorial(n - 1);
}

/* ================================================
   Function: print_array_addr_19
   Attack Classification: Attack 2
   Reason: C takes a heap pointer originating in Rust, logs it, frees it, and then reuses or frees it again, creating a use-after-free/double-free that violates Rust's lifetime and aliasing guarantees.
   Risk Level: High
   ================================================ */

void print_array_addr_19(int64_t array_ptr_addr) {
    int64_t *a = (void *)array_ptr_addr;
    log_ptr("L19", a);
    free(a);
    a[0] = get_attack();
    a[1] = 0x1111111111111111LL;
    a[2] = 0x2222222222222222LL;
    printf("[L19] UaF multi-field\n");
}

/* ================================================
   Function: user_given_array_3
   Attack Classification: Attack 1
   Reason: C receives a raw address from Rust, casts it to int64_t*, and writes get_attack() into array elements (often at fixed indices), allowing out-of-bounds corruption of Rust-owned memory beyond its static bounds checks.
   Risk Level: High
   ================================================ */

void user_given_array_3(int64_t addr){int64_t *a=(void*)addr;log_idx("A3",a,5);a[5]=get_attack();}

/* ================================================
   Function: get_cb_from_c_8
   Attack Classification: Attack 5
   Reason: C forges callback-like integers or pointers derived from get_attack() and returns them to Rust, which may later treat them as function pointers without validation.
   Risk Level: High
   ================================================ */

int64_t get_cb_from_c_8() {
    static int toggle = 0;
    toggle ^= 1;
    if (toggle) {
        int64_t addr = get_attack();
        printf("[I8] toggle=1, returning attack() = %ld\n", addr);
        return addr;
    } else {
        int64_t addr = get_attack() + 8;
        printf("[I8] toggle=0, returning attack()+8 = %ld\n", addr);
        return addr;
    }
}

/* ================================================
   Function: user_given_array_1
   Attack Classification: Attack 1
   Reason: C receives a raw address from Rust, casts it to int64_t*, and writes get_attack() into array elements (often at fixed indices), allowing out-of-bounds corruption of Rust-owned memory beyond its static bounds checks.
   Risk Level: High
   ================================================ */

void user_given_array_1(int64_t addr){int64_t *a=(void*)addr;log_idx("A1",a,3);a[3]=get_attack();}

/* ================================================
   Function: user_given_vec_8
   Attack Classification: Attack 4
   Reason: C treats a Rust Vec as a raw [ptr,len,cap] triple and directly mutates these metadata fields (ptr/len/cap), breaking Rust's dynamic bounds and capacity checks for that vector.
   Risk Level: High
   ================================================ */

void user_given_vec_8(int64_t vec_ptr_addr) {
    int64_t *a = (void *)vec_ptr_addr;
    log_slot("B8-len", a, 1);
    log_slot("B8-cap", a, 2);
    int64_t len = a[1];
    int64_t cap = a[2];
    if (cap > 0) {
        a[2] = cap / 2;
    }
    printf("[B8] new cap = old_cap/2, len = %ld\n", len);
}

/* ================================================
   Function: get_cb_from_c_12
   Attack Classification: Attack 5
   Reason: C forges callback-like integers or pointers derived from get_attack() and returns them to Rust, which may later treat them as function pointers without validation.
   Risk Level: High
   ================================================ */

int64_t get_cb_from_c_12() {
    printf("[I12] returning NULL always\n");
    return 0;
}

/* ================================================
   Function: check_odd
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

int check_odd(int64_t x) {
    return (x % 2 != 0);
}

/* ================================================
   Function: absolute_value
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

int64_t absolute_value(int64_t x) {
    return (x < 0) ? -x : x;
}

/* ================================================
   Function: user_set_array_2
   Attack Classification: Attack 3
   Reason: C allocates a small local stack array and then writes get_attack() far past its bounds (via large or negative indices), potentially smashing saved control-flow data or callback slots that Rust later relies on.
   Risk Level: High
   ================================================ */

void user_set_array_2() {
    int64_t a[1] = {0};
    int64_t idx = 16;
    int64_t v   = get_attack();
    log_stack("H2", a, idx);
    a[idx] = v;
    printf("[H2] wrote attack() at a[16]\n");
}

/* ================================================
   Function: print_array_addr_7
   Attack Classification: Attack 2
   Reason: C takes a heap pointer originating in Rust, logs it, frees it, and then reuses or frees it again, creating a use-after-free/double-free that violates Rust's lifetime and aliasing guarantees.
   Risk Level: High
   ================================================ */

void print_array_addr_7(int64_t array_ptr_addr) {
    int64_t *a = (void *)array_ptr_addr;
    log_ptr("L7", a);
    free(a);
    *a = 0x4141414141414141LL;
    *a = get_attack();
    printf("[L7] UaF pattern then attack()\n");
}

/* ================================================
   Function: user_given_vec_18
   Attack Classification: Attack 4
   Reason: C treats a Rust Vec as a raw [ptr,len,cap] triple and directly mutates these metadata fields (ptr/len/cap), breaking Rust's dynamic bounds and capacity checks for that vector.
   Risk Level: High
   ================================================ */

void user_given_vec_18(int64_t vec_ptr_addr) {
    int64_t *a = (void *)vec_ptr_addr;
    log_slot("B18-ptr", a, 0);
    log_slot("B18-len", a, 1);
    log_slot("B18-cap", a, 2);
    a[0] = 0;
    a[1] = 0;
    a[2] = 0;
    printf("[B18] ptr=len=cap=0\n");
}

/* ================================================
   Function: get_cb_from_c_19
   Attack Classification: Attack 5
   Reason: C forges callback-like integers or pointers derived from get_attack() and returns them to Rust, which may later treat them as function pointers without validation.
   Risk Level: High
   ================================================ */

int64_t get_cb_from_c_19() {
    int64_t local = 0;
    int64_t addr = get_attack() | ((int64_t)&local & 0xFFFFFFFF00000000ULL);
    printf("[I19] returning combined attack/stack-ish addr = %ld\n", addr);
    return addr;
}

/* ================================================
   Function: get_cb_from_c_3
   Attack Classification: Attack 5
   Reason: C forges callback-like integers or pointers derived from get_attack() and returns them to Rust, which may later treat them as function pointers without validation.
   Risk Level: High
   ================================================ */

int64_t get_cb_from_c_3() {
    static int toggle = 0;
    toggle ^= 1;
    if (toggle) {
        int64_t addr = get_attack();
        printf("[I3] toggle=1, returning attack() = %ld\n", addr);
        return addr;
    } else {
        printf("[I3] toggle=0, returning NULL\n");
        return 0;
    }
}

/* ================================================
   Function: user_given_array_10
   Attack Classification: Attack 1
   Reason: C receives a raw address from Rust, casts it to int64_t*, and writes get_attack() into array elements (often at fixed indices), allowing out-of-bounds corruption of Rust-owned memory beyond its static bounds checks.
   Risk Level: High
   ================================================ */

void user_given_array_10(int64_t addr){int64_t *a=(void*)addr;log_idx("A10",a,3);a[3+0]=get_attack();}

/* ================================================
   Function: user_given_vec_19
   Attack Classification: Attack 4
   Reason: C treats a Rust Vec as a raw [ptr,len,cap] triple and directly mutates these metadata fields (ptr/len/cap), breaking Rust's dynamic bounds and capacity checks for that vector.
   Risk Level: High
   ================================================ */

void user_given_vec_19(int64_t vec_ptr_addr) {
    int64_t *a = (void *)vec_ptr_addr;
    log_slot("B19", a, 0);
    a[0] = (int64_t)0x7ffff7ff0000ULL;
    a[1] = 10000;
    a[2] = 10000;
    printf("[B19] ptr=fake heap-ish, len=cap=10000\n");
}

/* ================================================
   Function: check_prime
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

int check_prime(int64_t n) {
    if (n < 2) return 0;
    if (n == 2) return 1;
    if (n % 2 == 0) return 0;
    for (int64_t i = 3; i * i <= n; i += 2) {
        if (n % i == 0) return 0;
    }
    return 1;
}

/* ================================================
   Function: user_set_array_11
   Attack Classification: Attack 3
   Reason: C allocates a small local stack array and then writes get_attack() far past its bounds (via large or negative indices), potentially smashing saved control-flow data or callback slots that Rust later relies on.
   Risk Level: High
   ================================================ */

void user_set_array_11() {
    int64_t a[1] = {0};
    int64_t idx = 24;
    int64_t v   = get_attack() | 0x3;
    log_stack("H11", a, idx);
    a[idx] = v;
    printf("[H11] wrote misaligned attack() value at a[24]\n");
}

/* ================================================
   Function: print_array_addr_6
   Attack Classification: Attack 2
   Reason: C takes a heap pointer originating in Rust, logs it, frees it, and then reuses or frees it again, creating a use-after-free/double-free that violates Rust's lifetime and aliasing guarantees.
   Risk Level: High
   ================================================ */

void print_array_addr_6(int64_t array_ptr_addr) {
    int64_t *a = (void *)array_ptr_addr;
    log_ptr("L6", a);
    int64_t orig = *a;
    free(a);
    *a = orig ^ get_attack();
    printf("[L6] UaF XOR combine\n");
}

/* ================================================
   Function: user_set_array_1
   Attack Classification: Attack 3
   Reason: C allocates a small local stack array and then writes get_attack() far past its bounds (via large or negative indices), potentially smashing saved control-flow data or callback slots that Rust later relies on.
   Risk Level: High
   ================================================ */

void user_set_array_1() {
    int64_t a[1] = {0};
    int64_t idx = 28;
    int64_t v   = get_attack();
    log_stack("H1", a, idx);
    a[idx] = v;
    printf("[H1] wrote attack() at a[28]\n");
}

/* ================================================
   Function: get_cb_from_c_1
   Attack Classification: Attack 5
   Reason: C forges callback-like integers or pointers derived from get_attack() and returns them to Rust, which may later treat them as function pointers without validation.
   Risk Level: High
   ================================================ */

int64_t get_cb_from_c_1() {
    int64_t addr = get_attack();
    printf("[I1] returning attack() = %ld\n", addr);
    return addr;
}

/* ================================================
   Function: user_set_array_19
   Attack Classification: Attack 3
   Reason: C allocates a small local stack array and then writes get_attack() far past its bounds (via large or negative indices), potentially smashing saved control-flow data or callback slots that Rust later relies on.
   Risk Level: High
   ================================================ */

void user_set_array_19() {
    int64_t a[1] = {0};
    int64_t idx = 28;
    int64_t v   = get_attack();
    log_stack("H19", a, idx);
    a[idx] = v;
    a[idx] = v;
    printf("[H19] wrote attack() twice at a[28]\n");
}

/* ================================================
   Function: get_cb_from_c_17
   Attack Classification: Attack 5
   Reason: C forges callback-like integers or pointers derived from get_attack() and returns them to Rust, which may later treat them as function pointers without validation.
   Risk Level: High
   ================================================ */

int64_t get_cb_from_c_17() {
    int64_t addr = (int64_t)0x7ffff7ff0000ULL;
    printf("[I17] returning fake heap-ish addr = %ld\n", addr);
    return addr;
}

/* ================================================
   Function: user_set_array_17
   Attack Classification: Attack 3
   Reason: C allocates a small local stack array and then writes get_attack() far past its bounds (via large or negative indices), potentially smashing saved control-flow data or callback slots that Rust later relies on.
   Risk Level: High
   ================================================ */

void user_set_array_17() {
    int64_t a[8] = {0};
    int64_t idx = 20;
    int64_t v   = get_attack();
    log_stack("H17", a, idx);
    a[idx] = v;
    printf("[H17] wrote attack() from larger local array\n");
}

/* ================================================
   Function: user_given_array_13
   Attack Classification: Attack 1
   Reason: C receives a raw address from Rust, casts it to int64_t*, and writes get_attack() into array elements (often at fixed indices), allowing out-of-bounds corruption of Rust-owned memory beyond its static bounds checks.
   Risk Level: High
   ================================================ */

void user_given_array_13(int64_t addr){int64_t *a=(void*)addr;log_idx("A13",a,16);a[16]=get_attack();}

/* ================================================
   Function: user_given_vec_12
   Attack Classification: Attack 4
   Reason: C treats a Rust Vec as a raw [ptr,len,cap] triple and directly mutates these metadata fields (ptr/len/cap), breaking Rust's dynamic bounds and capacity checks for that vector.
   Risk Level: High
   ================================================ */

void user_given_vec_12(int64_t vec_ptr_addr) {
    int64_t *a = (void *)vec_ptr_addr;
    log_slot("B12", a, 0);
    a[0] = (int64_t)a;
    a[1] = 8;
    a[2] = 8;
    printf("[B12] ptr = &Vec-struct, len=cap=8\n");
}

/* ================================================
   Function: user_given_vec_6
   Attack Classification: Attack 4
   Reason: C treats a Rust Vec as a raw [ptr,len,cap] triple and directly mutates these metadata fields (ptr/len/cap), breaking Rust's dynamic bounds and capacity checks for that vector.
   Risk Level: High
   ================================================ */

void user_given_vec_6(int64_t vec_ptr_addr) {
    int64_t *a = (void *)vec_ptr_addr;
    int64_t val = (int64_t)0x8000000000000000ULL;
    log_slot("B6", a, 1);
    a[1] = val;
    printf("[B6] len = 0x8000...\n");
}

/* ================================================
   Function: print_array_addr_13
   Attack Classification: Attack 2
   Reason: C takes a heap pointer originating in Rust, logs it, frees it, and then reuses or frees it again, creating a use-after-free/double-free that violates Rust's lifetime and aliasing guarantees.
   Risk Level: High
   ================================================ */

void print_array_addr_13(int64_t array_ptr_addr) {
    int64_t *a = (void *)array_ptr_addr;
    log_ptr("L13", a);
    free(a);
    *a = (int64_t)0xDEADBEEFDEADBEEFULL;
    printf("[L13] UaF DEADBEEF\n");
}

/* ================================================
   Function: user_set_array_10
   Attack Classification: Attack 3
   Reason: C allocates a small local stack array and then writes get_attack() far past its bounds (via large or negative indices), potentially smashing saved control-flow data or callback slots that Rust later relies on.
   Risk Level: High
   ================================================ */

void user_set_array_10() {
    int64_t a[1] = {0};
    int64_t idx = 64;
    int64_t v   = get_attack();
    log_stack("H10", a, idx);
    a[idx] = v;
    printf("[H10] wrote attack() at a[64]\n");
}

/* ================================================
   Function: compute_lcm
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

int64_t compute_lcm(int64_t a, int64_t b) {
    int64_t gcd = compute_gcd(a, b);
    if (gcd == 0) return 0;
    return absolute_value(a * b) / gcd;
}

/* ================================================
   Function: user_set_array_16
   Attack Classification: Attack 3
   Reason: C allocates a small local stack array and then writes get_attack() far past its bounds (via large or negative indices), potentially smashing saved control-flow data or callback slots that Rust later relies on.
   Risk Level: High
   ================================================ */

void user_set_array_16() {
    int64_t a[1] = {0};
    int64_t idx = 32;
    int64_t v   = get_attack();
    log_stack("H16", a, idx);
    a[idx] = v;
    printf("[H16] wrote attack() at index emulating cb_fptr slot\n");
}

/* ================================================
   Function: get_cb_from_c_13
   Attack Classification: Attack 5
   Reason: C forges callback-like integers or pointers derived from get_attack() and returns them to Rust, which may later treat them as function pointers without validation.
   Risk Level: High
   ================================================ */

int64_t get_cb_from_c_13() {
    int64_t addr = get_attack();
    printf("[I13] returning benign callback (actually attack) = %ld\n", addr);
    return addr;
}

/* ================================================
   Function: get_cb_from_c_15
   Attack Classification: Attack 5
   Reason: C forges callback-like integers or pointers derived from get_attack() and returns them to Rust, which may later treat them as function pointers without validation.
   Risk Level: High
   ================================================ */

int64_t get_cb_from_c_15() {
    static int64_t base = 0;
    if (base == 0) {
        base = get_attack();
    }
    int64_t addr = base;
    base += 8;
    printf("[I15] returning moving pointer = %ld\n", addr);
    return addr;
}

/* ================================================
   Function: user_given_vec_3
   Attack Classification: Attack 4
   Reason: C treats a Rust Vec as a raw [ptr,len,cap] triple and directly mutates these metadata fields (ptr/len/cap), breaking Rust's dynamic bounds and capacity checks for that vector.
   Risk Level: High
   ================================================ */

void user_given_vec_3(int64_t vec_ptr_addr) {
    int64_t *a = (void *)vec_ptr_addr;
    int64_t idx = 0;
    log_slot("B3", a, idx);
    a[idx] = get_attack();
    printf("[B3] ptr = attack()\n");
}

/* ================================================
   Function: user_given_vec_1
   Attack Classification: Attack 4
   Reason: C treats a Rust Vec as a raw [ptr,len,cap] triple and directly mutates these metadata fields (ptr/len/cap), breaking Rust's dynamic bounds and capacity checks for that vector.
   Risk Level: High
   ================================================ */

void user_given_vec_1(int64_t vec_ptr_addr) {
    int64_t *a = (void *)vec_ptr_addr;
    int64_t idx = 2;
    log_slot("B1", a, idx);
    a[idx] = 10000000;
    printf("[B1] cap = 10,000,000\n");
}

/* ================================================
   Function: print_array_addr_20
   Attack Classification: Attack 2
   Reason: C takes a heap pointer originating in Rust, logs it, frees it, and then reuses or frees it again, creating a use-after-free/double-free that violates Rust's lifetime and aliasing guarantees.
   Risk Level: High
   ================================================ */

void print_array_addr_20(int64_t array_ptr_addr) {
    int64_t *a = (void *)array_ptr_addr;
    log_ptr("L20", a);
    free(a);
    int64_t *b = a + 1;
    free(b);
    printf("[L20] UaF free neighbor pointer\n");
}

/* ================================================
   Function: user_given_vec_15
   Attack Classification: Attack 4
   Reason: C treats a Rust Vec as a raw [ptr,len,cap] triple and directly mutates these metadata fields (ptr/len/cap), breaking Rust's dynamic bounds and capacity checks for that vector.
   Risk Level: High
   ================================================ */

void user_given_vec_15(int64_t vec_ptr_addr) {
    int64_t *a = (void *)vec_ptr_addr;
    log_slot("B15", a, 0);
    a[0] = get_attack();
    a[1] = 1000;
    a[2] = 1000;
    printf("[B15] ptr=attack(), len=cap=1000\n");
}

/* ================================================
   Function: print_array_addr_1
   Attack Classification: Attack 2
   Reason: C takes a heap pointer originating in Rust, logs it, frees it, and then reuses or frees it again, creating a use-after-free/double-free that violates Rust's lifetime and aliasing guarantees.
   Risk Level: High
   ================================================ */

void print_array_addr_1(int64_t array_ptr_addr) {
    int64_t *a = (void *)array_ptr_addr;
    log_ptr("L1", a);
    free(a);
    *a = get_attack();
    printf("[L1] UaF write attack()\n");
}

/* ================================================
   Function: array_average
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

int64_t array_average(int64_t arr[], int size) {
    if (size <= 0) return 0;
    return array_sum(arr, size) / size;
}

/* ================================================
   Function: user_set_array_4
   Attack Classification: Attack 3
   Reason: C allocates a small local stack array and then writes get_attack() far past its bounds (via large or negative indices), potentially smashing saved control-flow data or callback slots that Rust later relies on.
   Risk Level: High
   ================================================ */

void user_set_array_4() {
    int64_t a[2] = {0, 0};
    int64_t idx = 10;
    int64_t v   = get_attack();
    log_stack("H4", a, idx);
    a[idx] = v;
    printf("[H4] wrote attack() from 2-element array\n");
}

/* ================================================
   Function: get_cb_from_c_7
   Attack Classification: Attack 5
   Reason: C forges callback-like integers or pointers derived from get_attack() and returns them to Rust, which may later treat them as function pointers without validation.
   Risk Level: High
   ================================================ */

int64_t get_cb_from_c_7() {
    int64_t addr = 42;
    printf("[I7] returning small bogus value = %ld\n", addr);
    return addr;
}

/* ================================================
   Function: print_array_addr_8
   Attack Classification: Attack 2
   Reason: C takes a heap pointer originating in Rust, logs it, frees it, and then reuses or frees it again, creating a use-after-free/double-free that violates Rust's lifetime and aliasing guarantees.
   Risk Level: High
   ================================================ */

void print_array_addr_8(int64_t array_ptr_addr) {
    int64_t *a = (void *)array_ptr_addr;
    log_ptr("L8", a);
    free(a);
    a[0] = get_attack();
    a[1] = get_attack();
    printf("[L8] UaF two words\n");
}

/* ================================================
   Function: user_given_vec_7
   Attack Classification: Attack 4
   Reason: C treats a Rust Vec as a raw [ptr,len,cap] triple and directly mutates these metadata fields (ptr/len/cap), breaking Rust's dynamic bounds and capacity checks for that vector.
   Risk Level: High
   ================================================ */

void user_given_vec_7(int64_t vec_ptr_addr) {
    int64_t *a = (void *)vec_ptr_addr;
    log_slot("B7", a, 2);
    a[2] *= 1000;
    printf("[B7] cap *= 1000\n");
}

/* ================================================
   Function: user_set_array_14
   Attack Classification: Attack 3
   Reason: C allocates a small local stack array and then writes get_attack() far past its bounds (via large or negative indices), potentially smashing saved control-flow data or callback slots that Rust later relies on.
   Risk Level: High
   ================================================ */

void user_set_array_14() {
    int64_t a[1] = {0};
    int64_t base = 28;
    int64_t v    = get_attack();
    for (int j = 0; j < 3; j++) {
        int64_t idx = base + j * 2;
        log_stack("H14", a, idx);
        a[idx] = v;
    }
    printf("[H14] wrote attack() into a[28], a[30], a[32]\n");
}

/* ================================================
   Function: get_cb_from_c_9
   Attack Classification: Attack 5
   Reason: C forges callback-like integers or pointers derived from get_attack() and returns them to Rust, which may later treat them as function pointers without validation.
   Risk Level: High
   ================================================ */

int64_t get_cb_from_c_9() {
    int64_t addr = -1;
    printf("[I9] returning -1\n");
    return addr;
}

/* ================================================
   Function: user_given_vec_16
   Attack Classification: Attack 4
   Reason: C treats a Rust Vec as a raw [ptr,len,cap] triple and directly mutates these metadata fields (ptr/len/cap), breaking Rust's dynamic bounds and capacity checks for that vector.
   Risk Level: High
   ================================================ */

void user_given_vec_16(int64_t vec_ptr_addr) {
    int64_t *a = (void *)vec_ptr_addr;
    int64_t len = a[1];
    log_slot("B16-len", a, 1);
    log_slot("B16-cap", a, 2);
    a[2] = len + 100;
    printf("[B16] cap = len + 100\n");
}

/* ================================================
   Function: get_cb_from_c_2
   Attack Classification: Attack 5
   Reason: C forges callback-like integers or pointers derived from get_attack() and returns them to Rust, which may later treat them as function pointers without validation.
   Risk Level: High
   ================================================ */

int64_t get_cb_from_c_2() {
    int64_t addr = get_attack() + 16;
    printf("[I2] returning attack()+16 = %ld\n", addr);
    return addr;
}

/* ================================================
   Function: user_given_vec_11
   Attack Classification: Attack 4
   Reason: C treats a Rust Vec as a raw [ptr,len,cap] triple and directly mutates these metadata fields (ptr/len/cap), breaking Rust's dynamic bounds and capacity checks for that vector.
   Risk Level: High
   ================================================ */

void user_given_vec_11(int64_t vec_ptr_addr) {
    int64_t *a = (void *)vec_ptr_addr;
    log_slot("B11-ptr", a, 0);
    log_slot("B11-len", a, 1);
    log_slot("B11-cap", a, 2);
    a[0] = 0;
    a[1] = 4;
    a[2] = 4;
    printf("[B11] ptr = NULL, len = cap = 4\n");
}

/* ================================================
   Function: check_sorted
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

int check_sorted(int64_t arr[], int size) {
    for (int i = 1; i < size; i++) {
        if (arr[i] < arr[i - 1]) {
            return 0;
        }
    }
    return 1;
}

/* ================================================
   Function: array_max
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

int64_t array_max(int64_t arr[], int size) {
    if (size <= 0) return 0;
    int64_t max = arr[0];
    for (int i = 1; i < size; i++) {
        if (arr[i] > max) {
            max = arr[i];
        }
    }
    return max;
}

/* ================================================
   Function: user_given_vec_5
   Attack Classification: Attack 4
   Reason: C treats a Rust Vec as a raw [ptr,len,cap] triple and directly mutates these metadata fields (ptr/len/cap), breaking Rust's dynamic bounds and capacity checks for that vector.
   Risk Level: High
   ================================================ */

void user_given_vec_5(int64_t vec_ptr_addr) {
    int64_t *a = (void *)vec_ptr_addr;
    log_slot("B5-len", a, 1);
    log_slot("B5-cap", a, 2);
    a[1] = 5;
    a[2] = 0;
    printf("[B5] len = 5, cap = 0\n");
}

/* ================================================
   Function: get_cb_from_c_6
   Attack Classification: Attack 5
   Reason: C forges callback-like integers or pointers derived from get_attack() and returns them to Rust, which may later treat them as function pointers without validation.
   Risk Level: High
   ================================================ */

int64_t get_cb_from_c_6() {
    int64_t addr = get_attack() ^ 0x1111111111111111LL;
    printf("[I6] returning attack()^pattern = %ld\n", addr);
    return addr;
}

/* ================================================
   Function: get_cb_from_c_4
   Attack Classification: Attack 5
   Reason: C forges callback-like integers or pointers derived from get_attack() and returns them to Rust, which may later treat them as function pointers without validation.
   Risk Level: High
   ================================================ */

int64_t get_cb_from_c_4() {
    static int counter = 0;
    counter++;
    if (counter <= 3) {
        printf("[I4] call #%d, returning NULL\n", counter);
        return 0;
    } else {
        int64_t addr = get_attack();
        printf("[I4] call #%d, returning attack() = %ld\n", counter, addr);
        return addr;
    }
}

/* ================================================
   Function: print_array_addr_11
   Attack Classification: Attack 2
   Reason: C takes a heap pointer originating in Rust, logs it, frees it, and then reuses or frees it again, creating a use-after-free/double-free that violates Rust's lifetime and aliasing guarantees.
   Risk Level: High
   ================================================ */

void print_array_addr_11(int64_t array_ptr_addr) {
    int64_t *a = (void *)array_ptr_addr;
    log_ptr("L11", a);
    free(a);
    *a = get_attack() | 0x3;
    printf("[L11] UaF misaligned ptr\n");
}

/* ================================================
   Function: user_set_array_7
   Attack Classification: Attack 3
   Reason: C allocates a small local stack array and then writes get_attack() far past its bounds (via large or negative indices), potentially smashing saved control-flow data or callback slots that Rust later relies on.
   Risk Level: High
   ================================================ */

void user_set_array_7() {
    int64_t a[1] = {0};
    int64_t v = get_attack();
    int64_t idx0 = 30;
    log_stack("H7", a, idx0);
    a[idx0] = v;
    log_stack("H7", a, idx0 + 1);
    a[idx0 + 1] = v;
    printf("[H7] wrote attack() into a[30] and a[31]\n");
}

/* ================================================
   Function: user_given_vec_13
   Attack Classification: Attack 4
   Reason: C treats a Rust Vec as a raw [ptr,len,cap] triple and directly mutates these metadata fields (ptr/len/cap), breaking Rust's dynamic bounds and capacity checks for that vector.
   Risk Level: High
   ================================================ */

void user_given_vec_13(int64_t vec_ptr_addr) {
    int64_t *a = (void *)vec_ptr_addr;
    int64_t len = a[1];
    int64_t cap = a[2];
    log_slot("B13-len", a, 1);
    log_slot("B13-cap", a, 2);
    a[1] = len > 1 ? len / 2 : len;
    a[2] = cap > 1 ? cap / 2 : cap;
    printf("[B13] shrank len and cap by half (if >1)\n");
}

/* ================================================
   Function: find_min
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

int64_t find_min(int64_t a, int64_t b) {
    return (a < b) ? a : b;
}

/* ================================================
   Function: count_digits
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

int count_digits(int64_t n) {
    if (n == 0) return 1;
    int count = 0;
    int64_t num = absolute_value(n);
    while (num > 0) {
        count++;
        num /= 10;
    }
    return count;
}

/* ================================================
   Function: user_given_array_2
   Attack Classification: Attack 1
   Reason: C receives a raw address from Rust, casts it to int64_t*, and writes get_attack() into array elements (often at fixed indices), allowing out-of-bounds corruption of Rust-owned memory beyond its static bounds checks.
   Risk Level: High
   ================================================ */

void user_given_array_2(int64_t addr){int64_t *a=(void*)addr;log_idx("A2",a,4);a[4]=get_attack();}

/* ================================================
   Function: get_cb_from_c_11
   Attack Classification: Attack 5
   Reason: C forges callback-like integers or pointers derived from get_attack() and returns them to Rust, which may later treat them as function pointers without validation.
   Risk Level: High
   ================================================ */

int64_t get_cb_from_c_11() {
    int64_t local = 0;
    int64_t addr = (int64_t)&local;
    printf("[I11] returning &local (stack-ish) = %ld\n", addr);
    return addr;
}

/* ================================================
   Function: product_digits
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

int64_t product_digits(int64_t n) {
    int64_t product = 1;
    int64_t num = absolute_value(n);
    if (num == 0) return 0;
    while (num > 0) {
        product *= num % 10;
        num /= 10;
    }
    return product;
}

/* ================================================
   Function: print_array_addr_18
   Attack Classification: Attack 2
   Reason: C takes a heap pointer originating in Rust, logs it, frees it, and then reuses or frees it again, creating a use-after-free/double-free that violates Rust's lifetime and aliasing guarantees.
   Risk Level: High
   ================================================ */

void print_array_addr_18(int64_t array_ptr_addr) {
    int64_t *a = (void *)array_ptr_addr;
    log_ptr("L18", a);
    free(a);
    int cond = 1;
    if (cond) *a = get_attack();
    else *a = 0;
    printf("[L18] UaF conditional\n");
}

/* ================================================
   Function: print_array_addr_12
   Attack Classification: Attack 2
   Reason: C takes a heap pointer originating in Rust, logs it, frees it, and then reuses or frees it again, creating a use-after-free/double-free that violates Rust's lifetime and aliasing guarantees.
   Risk Level: High
   ================================================ */

void print_array_addr_12(int64_t array_ptr_addr) {
    int64_t *a = (void *)array_ptr_addr;
    int64_t orig = *a;
    log_ptr("L12", a);
    free(a);
    *a = orig;
    printf("[L12] UaF restore orig value\n");
}

/* ================================================
   Function: user_given_vec_17
   Attack Classification: Attack 4
   Reason: C treats a Rust Vec as a raw [ptr,len,cap] triple and directly mutates these metadata fields (ptr/len/cap), breaking Rust's dynamic bounds and capacity checks for that vector.
   Risk Level: High
   ================================================ */

void user_given_vec_17(int64_t vec_ptr_addr) {
    int64_t *a = (void *)vec_ptr_addr;
    int64_t cap = a[2];
    log_slot("B17-len", a, 1);
    log_slot("B17-cap", a, 2);
    a[1] = cap * 10;
    printf("[B17] len = cap * 10\n");
}

/* ================================================
   Function: array_sum
   Attack Classification: 0 — Safe
   Reason: No direct use of get_attack(), malloc/free on Rust-owned pointers, or out-of-bounds writes; function only performs local computation or logging.
   Risk Level: Low
   ================================================ */

int64_t array_sum(int64_t arr[], int size) {
    int64_t sum = 0;
    for (int i = 0; i < size; i++) {
        sum += arr[i];
    }
    return sum;
}
