extern "C" {

#[no_mangle]
/* ================================================
   Function: get_attack
   Attack Classification: 0 — Safe
   Reason: No direct unsafe FFI boundary misuse detected; function uses only safe Rust operations (pure computation, printing, or simple struct construction) without manipulating raw pointers from C.
   Risk Level: Low
   ================================================ */

extern "C" fn get_attack() -> i64 {

pub const MAX_LENGTH: usize = 3;

#[repr(C)]
pub struct Data {

#[no_mangle]
#[inline(never)]

#[no_mangle]
#[inline(never)]

#[no_mangle]
#[inline(never)]

extern "C" fn get_attack() -> i64 {

pub const MAX_LENGTH: usize = 3;

#[repr(C)]
pub struct Data {

#[no_mangle]
#[inline(never)]

#[no_mangle]
#[inline(never)]

#[no_mangle]
#[inline(never)]

pub fn vec_average(vec: &[i64]) -> i64 {
    if vec.is_empty() {
        0
    } else {
        vec_sum(vec) / vec.len() as i64
    }
}

/* ================================================
   Function: check_even
   Attack Classification: 0 — Safe
   Reason: No direct unsafe FFI boundary misuse detected; function uses only safe Rust operations (pure computation, printing, or simple struct construction) without manipulating raw pointers from C.
   Risk Level: Low
   ================================================ */

pub fn check_even(x: i64) -> bool {
    x % 2 == 0
}

/* ================================================
   Function: divide_numbers
   Attack Classification: 0 — Safe
   Reason: No direct unsafe FFI boundary misuse detected; function uses only safe Rust operations (pure computation, printing, or simple struct construction) without manipulating raw pointers from C.
   Risk Level: Low
   ================================================ */

pub fn divide_numbers(a: i64, b: i64) -> i64 {
    if b == 0 {
        0
    } else {
        a / b
    }
}

/* ================================================
   Function: count_digits
   Attack Classification: 0 — Safe
   Reason: No direct unsafe FFI boundary misuse detected; function uses only safe Rust operations (pure computation, printing, or simple struct construction) without manipulating raw pointers from C.
   Risk Level: Low
   ================================================ */

pub fn count_digits(n: i64) -> usize {
    if n == 0 {
        return 1;
    }
    let mut count = 0;
    let mut num = n.abs();
    while num > 0 {
        count += 1;
        num /= 10;
    }
    count
}

/* ================================================
   Function: compute_power
   Attack Classification: 0 — Safe
   Reason: No direct unsafe FFI boundary misuse detected; function uses only safe Rust operations (pure computation, printing, or simple struct construction) without manipulating raw pointers from C.
   Risk Level: Low
   ================================================ */

pub fn compute_power(base: i64, exp: i32) -> i64 {
    if exp < 0 {
        return 0;
    }
    let mut result = 1i64;
    for _ in 0..exp {
        result *= base;
    }
    result
}

/* ================================================
   Function: find_min
   Attack Classification: 0 — Safe
   Reason: No direct unsafe FFI boundary misuse detected; function uses only safe Rust operations (pure computation, printing, or simple struct construction) without manipulating raw pointers from C.
   Risk Level: Low
   ================================================ */

pub fn find_min(a: i64, b: i64) -> i64 {
    if a < b { a } else { b }
}

/* ================================================
   Function: product_digits
   Attack Classification: 0 — Safe
   Reason: No direct unsafe FFI boundary misuse detected; function uses only safe Rust operations (pure computation, printing, or simple struct construction) without manipulating raw pointers from C.
   Risk Level: Low
   ================================================ */

pub fn product_digits(n: i64) -> i64 {
    let mut product = 1i64;
    let mut num = n.abs();
    if num == 0 {
        return 0;
    }
    while num > 0 {
        product *= num % 10;
        num /= 10;
    }
    product
}

/* ================================================
   Function: multiply_numbers
   Attack Classification: 0 — Safe
   Reason: No direct unsafe FFI boundary misuse detected; function uses only safe Rust operations (pure computation, printing, or simple struct construction) without manipulating raw pointers from C.
   Risk Level: Low
   ================================================ */

pub fn multiply_numbers(a: i64, b: i64) -> i64 {
    a * b
}

/* ================================================
   Function: reverse_vec
   Attack Classification: 0 — Safe
   Reason: No direct unsafe FFI boundary misuse detected; function uses only safe Rust operations (pure computation, printing, or simple struct construction) without manipulating raw pointers from C.
   Risk Level: Low
   ================================================ */

pub fn reverse_vec(vec: &[i64]) -> Vec<i64> {
    vec.iter().rev().copied().collect()
}

/* ================================================
   Function: find_max
   Attack Classification: 0 — Safe
   Reason: No direct unsafe FFI boundary misuse detected; function uses only safe Rust operations (pure computation, printing, or simple struct construction) without manipulating raw pointers from C.
   Risk Level: Low
   ================================================ */

pub fn find_max(a: i64, b: i64) -> i64 {
    if a > b { a } else { b }
}

/* ================================================
   Function: compute_lcm
   Attack Classification: 0 — Safe
   Reason: No direct unsafe FFI boundary misuse detected; function uses only safe Rust operations (pure computation, printing, or simple struct construction) without manipulating raw pointers from C.
   Risk Level: Low
   ================================================ */

pub fn compute_lcm(a: i64, b: i64) -> i64 {
    let gcd = compute_gcd(a, b);
    if gcd == 0 {
        0
    } else {
        (a.abs() * b.abs()) / gcd
    }
}

/* ================================================
   Function: sum_digits
   Attack Classification: 0 — Safe
   Reason: No direct unsafe FFI boundary misuse detected; function uses only safe Rust operations (pure computation, printing, or simple struct construction) without manipulating raw pointers from C.
   Risk Level: Low
   ================================================ */

pub fn sum_digits(n: i64) -> i32 {
    let mut sum = 0i32;
    let mut num = n.abs();
    while num > 0 {
        sum += (num % 10) as i32;
        num /= 10;
    }
    sum
}

/* ================================================
   Function: check_sorted
   Attack Classification: 0 — Safe
   Reason: No direct unsafe FFI boundary misuse detected; function uses only safe Rust operations (pure computation, printing, or simple struct construction) without manipulating raw pointers from C.
   Risk Level: Low
   ================================================ */

pub fn check_sorted(vec: &[i64]) -> bool {
    vec.windows(2).all(|w| w[0] <= w[1])
}

/* ================================================
   Function: check_prime
   Attack Classification: 0 — Safe
   Reason: No direct unsafe FFI boundary misuse detected; function uses only safe Rust operations (pure computation, printing, or simple struct construction) without manipulating raw pointers from C.
   Risk Level: Low
   ================================================ */

pub fn check_prime(n: i64) -> bool {
    if n < 2 {
        return false;
    }
    if n == 2 {
        return true;
    }
    if n % 2 == 0 {
        return false;
    }
    let mut i = 3i64;
    while i * i <= n {
        if n % i == 0 {
            return false;
        }
        i += 2;
    }
    true
}

/* ================================================
   Function: compute_factorial
   Attack Classification: 0 — Safe
   Reason: No direct unsafe FFI boundary misuse detected; function uses only safe Rust operations (pure computation, printing, or simple struct construction) without manipulating raw pointers from C.
   Risk Level: Low
   ================================================ */

pub fn compute_factorial(n: i32) -> i64 {
    if n <= 1 {
        1
    } else {
        n as i64 * compute_factorial(n - 1)
    }
}

/* ================================================
   Function: add_numbers
   Attack Classification: 0 — Safe
   Reason: No direct unsafe FFI boundary misuse detected; function uses only safe Rust operations (pure computation, printing, or simple struct construction) without manipulating raw pointers from C.
   Risk Level: Low
   ================================================ */

pub fn add_numbers(a: i64, b: i64) -> i64 {
    a + b
}

/* ================================================
   Function: vec_min
   Attack Classification: 0 — Safe
   Reason: No direct unsafe FFI boundary misuse detected; function uses only safe Rust operations (pure computation, printing, or simple struct construction) without manipulating raw pointers from C.
   Risk Level: Low
   ================================================ */

pub fn vec_min(vec: &[i64]) -> Option<i64> {
    vec.iter().min().copied()
}

/* ================================================
   Function: absolute_value
   Attack Classification: 0 — Safe
   Reason: No direct unsafe FFI boundary misuse detected; function uses only safe Rust operations (pure computation, printing, or simple struct construction) without manipulating raw pointers from C.
   Risk Level: Low
   ================================================ */

pub fn absolute_value(x: i64) -> i64 {
    if x < 0 { -x } else { x }
}

/* ================================================
   Function: compute_fibonacci
   Attack Classification: 0 — Safe
   Reason: No direct unsafe FFI boundary misuse detected; function uses only safe Rust operations (pure computation, printing, or simple struct construction) without manipulating raw pointers from C.
   Risk Level: Low
   ================================================ */

pub fn compute_fibonacci(n: i32) -> i64 {
    if n <= 1 {
        n as i64
    } else {
        let mut a = 0i64;
        let mut b = 1i64;
        for _ in 2..=n {
            let temp = a + b;
            a = b;
            b = temp;
        }
        b
    }
}

/* ================================================
   Function: vec_sum
   Attack Classification: 0 — Safe
   Reason: No direct unsafe FFI boundary misuse detected; function uses only safe Rust operations (pure computation, printing, or simple struct construction) without manipulating raw pointers from C.
   Risk Level: Low
   ================================================ */

pub fn vec_sum(vec: &[i64]) -> i64 {
    vec.iter().sum()
}

/* ================================================
   Function: vec_max
   Attack Classification: 0 — Safe
   Reason: No direct unsafe FFI boundary misuse detected; function uses only safe Rust operations (pure computation, printing, or simple struct construction) without manipulating raw pointers from C.
   Risk Level: Low
   ================================================ */

pub fn vec_max(vec: &[i64]) -> Option<i64> {
    vec.iter().max().copied()
}

/* ================================================
   Function: subtract_numbers
   Attack Classification: 0 — Safe
   Reason: No direct unsafe FFI boundary misuse detected; function uses only safe Rust operations (pure computation, printing, or simple struct construction) without manipulating raw pointers from C.
   Risk Level: Low
   ================================================ */

pub fn subtract_numbers(a: i64, b: i64) -> i64 {
    a - b
}

/* ================================================
   Function: check_odd
   Attack Classification: 0 — Safe
   Reason: No direct unsafe FFI boundary misuse detected; function uses only safe Rust operations (pure computation, printing, or simple struct construction) without manipulating raw pointers from C.
   Risk Level: Low
   ================================================ */

pub fn check_odd(x: i64) -> bool {
    x % 2 != 0
}

/* ================================================
   Function: compute_gcd
   Attack Classification: 0 — Safe
   Reason: No direct unsafe FFI boundary misuse detected; function uses only safe Rust operations (pure computation, printing, or simple struct construction) without manipulating raw pointers from C.
   Risk Level: Low
   ================================================ */

pub fn compute_gcd(a: i64, b: i64) -> i64 {
    let mut a = a.abs();
    let mut b = b.abs();
    while b != 0 {
        let temp = b;
        b = a % b;
        a = temp;
    }
    a
}

pub fn count_occurrences(vec: &[i64], value: i64) -> usize {
    vec.iter().filter(|&&x| x == value).count()

extern "C" {
    fn init();
    fn user_given_array_1(a: i64);
    fn user_given_array_2(a: i64);
    fn user_given_array_3(a: i64);
    fn user_given_array_4(a: i64);
    fn user_given_array_5(a: i64);
    fn user_given_array_6(a: i64);
    fn user_given_array_7(a: i64);
    fn user_given_array_8(a: i64);
    fn user_given_array_9(a: i64);
    fn user_given_array_10(a: i64);
    fn user_given_array_11(a: i64);
    fn user_given_array_12(a: i64);
    fn user_given_array_13(a: i64);
    fn user_given_array_14(a: i64);
    fn user_given_array_15(a: i64);
    fn user_given_array_16(a: i64);
    fn user_given_array_17(a: i64);
    fn user_given_array_18(a: i64);
    fn user_given_array_19(a: i64);
    fn user_given_array_20(a: i64);

    fn print_array_addr_1(addr: i64);
    fn print_array_addr_2(addr: i64);
    fn print_array_addr_3(addr: i64);
    fn print_array_addr_4(addr: i64);
    fn print_array_addr_5(addr: i64);
    fn print_array_addr_6(addr: i64);
    fn print_array_addr_7(addr: i64);
    fn print_array_addr_8(addr: i64);
    fn print_array_addr_9(addr: i64);
    fn print_array_addr_10(addr: i64);
    fn print_array_addr_11(addr: i64);
    fn print_array_addr_12(addr: i64);
    fn print_array_addr_13(addr: i64);
    fn print_array_addr_14(addr: i64);
    fn print_array_addr_15(addr: i64);
    fn print_array_addr_16(addr: i64);
    fn print_array_addr_17(addr: i64);
    fn print_array_addr_18(addr: i64);
    fn print_array_addr_19(addr: i64);
    fn print_array_addr_20(addr: i64);

    fn user_set_array_1();
    fn user_set_array_2();
    fn user_set_array_3();
    fn user_set_array_4();
    fn user_set_array_5();
    fn user_set_array_6();
    fn user_set_array_7();
    fn user_set_array_8();
    fn user_set_array_9();
    fn user_set_array_10();
    fn user_set_array_11();
    fn user_set_array_12();
    fn user_set_array_13();
    fn user_set_array_14();
    fn user_set_array_15();
    fn user_set_array_16();
    fn user_set_array_17();
    fn user_set_array_18();
    fn user_set_array_19();
    fn user_set_array_20();

    
    fn user_given_vec_1(addr: i64);
    fn user_given_vec_2(addr: i64);
    fn user_given_vec_3(addr: i64);
    fn user_given_vec_4(addr: i64);
    fn user_given_vec_5(addr: i64);
    fn user_given_vec_6(addr: i64);
    fn user_given_vec_7(addr: i64);
    fn user_given_vec_8(addr: i64);
    fn user_given_vec_9(addr: i64);
    fn user_given_vec_10(addr: i64);
    fn user_given_vec_11(addr: i64);
    fn user_given_vec_12(addr: i64);
    fn user_given_vec_13(addr: i64);
    fn user_given_vec_14(addr: i64);
    fn user_given_vec_15(addr: i64);
    fn user_given_vec_16(addr: i64);
    fn user_given_vec_17(addr: i64);
    fn user_given_vec_18(addr: i64);
    fn user_given_vec_19(addr: i64);
    fn user_given_vec_20(addr: i64);

    fn get_cb_from_c_1() -> i64;
    fn get_cb_from_c_2() -> i64;
    fn get_cb_from_c_3() -> i64;
    fn get_cb_from_c_4() -> i64;
    fn get_cb_from_c_5() -> i64;
    fn get_cb_from_c_6() -> i64;
    fn get_cb_from_c_7() -> i64;
    fn get_cb_from_c_8() -> i64;
    fn get_cb_from_c_9() -> i64;
    fn get_cb_from_c_10() -> i64;
    fn get_cb_from_c_11() -> i64;
    fn get_cb_from_c_12() -> i64;
    fn get_cb_from_c_13() -> i64;
    fn get_cb_from_c_14() -> i64;
    fn get_cb_from_c_15() -> i64;
    fn get_cb_from_c_16() -> i64;
    fn get_cb_from_c_17() -> i64;
    fn get_cb_from_c_18() -> i64;
    fn get_cb_from_c_19() -> i64;
    fn get_cb_from_c_20() -> i64;
}

#[no_mangle]
/* ================================================
   Function: get_attack
   Attack Classification: 0 — Safe
   Reason: No direct unsafe FFI boundary misuse detected; function uses only safe Rust operations (pure computation, printing, or simple struct construction) without manipulating raw pointers from C.
   Risk Level: Low
   ================================================ */

extern "C" fn get_attack() -> i64 {
    attack as i64
}

pub const MAX_LENGTH: usize = 3;

#[repr(C)]
pub struct Data {
    pub vals: [i64; MAX_LENGTH],
    pub cb: fn(&mut i64),
    pub vecs: Vec<i64>,
    pub cb2: fn(&mut i64),
}

#[no_mangle]
#[inline(never)]
/* ================================================
   Function: doubler
   Attack Classification: 0 — Safe
   Reason: No direct unsafe FFI boundary misuse detected; function uses only safe Rust operations (pure computation, printing, or simple struct construction) without manipulating raw pointers from C.
   Risk Level: Low
   ================================================ */

pub fn doubler(x: &mut i64) {
    println!("Not attacked! Adding two...");
    *x += 2;
}

#[no_mangle]
#[inline(never)]
/* ================================================
   Function: incrementer
   Attack Classification: 0 — Safe
   Reason: No direct unsafe FFI boundary misuse detected; function uses only safe Rust operations (pure computation, printing, or simple struct construction) without manipulating raw pointers from C.
   Risk Level: Low
   ================================================ */

pub fn incrementer(x: &mut i64) {
    println!("Not attacked! Adding one...");
    *x += 1;
}

#[no_mangle]
#[inline(never)]
/* ================================================
   Function: attack
   Attack Classification: 0 — Safe
   Reason: No direct unsafe FFI boundary misuse detected; function uses only safe Rust operations (pure computation, printing, or simple struct construction) without manipulating raw pointers from C.
   Risk Level: Low
   ================================================ */

pub fn attack() {
    println!("*** ATTACK TRIGGERED (combined harness) ***");
}

/* ================================================
   Function: make_data
   Attack Classification: 0 — Safe
   Reason: No direct unsafe FFI boundary misuse detected; function uses only safe Rust operations (pure computation, printing, or simple struct construction) without manipulating raw pointers from C.
   Risk Level: Low
   ================================================ */

fn make_data() -> Data {
    Data {
        vals: [1, 2, 3],
        cb: incrementer,
        vecs: vec![4, 5],
        cb2: doubler,
    }
}



/* ================================================
   Function: run_bounds_variant
   Attack Classification: Attack 1
   Reason: Drives the bounds-variant family by passing Rust-owned array addresses to C callbacks like user_given_array_N, which can perform out-of-bounds writes into &data.vals, bypassing Rust’s static bounds checks.
   Risk Level: High
   ================================================ */

fn run_bounds_variant(tag: &str, f: unsafe extern "C" fn(i64)) {
    let mut data = make_data();
    let addr = &data.vals as *const i64 as i64;

    println!("== {} ==", tag);
    println!("[{}] data.cb addr before = {}", tag, data.cb as *const fn(&mut i64) as i64);
    unsafe { f(addr) }
    println!("[{}] calling data.cb ...", tag);
    (data.cb)(&mut data.vals[0]);
    println!("[{}] updated vals[0] = {}", tag, data.vals[0]);
    println!();
}

/* ================================================
   Function: run_bounds_family
   Attack Classification: Attack 1
   Reason: Drives the bounds-variant family by passing Rust-owned array addresses to C callbacks like user_given_array_N, which can perform out-of-bounds writes into &data.vals, bypassing Rust’s static bounds checks.
   Risk Level: High
   ================================================ */

fn run_bounds_family() {
    run_bounds_variant("A1", user_given_array_1);
    run_bounds_variant("A2", user_given_array_2);
    run_bounds_variant("A3", user_given_array_3);
    run_bounds_variant("A4", user_given_array_4);
    run_bounds_variant("A5", user_given_array_5);
    run_bounds_variant("A6", user_given_array_6);
    run_bounds_variant("A7", user_given_array_7);
    run_bounds_variant("A8", user_given_array_8);
    run_bounds_variant("A9", user_given_array_9);
    run_bounds_variant("A10", user_given_array_10);
    run_bounds_variant("A11", user_given_array_11);
    run_bounds_variant("A12", user_given_array_12);
    run_bounds_variant("A13", user_given_array_13);
    run_bounds_variant("A14", user_given_array_14);
    run_bounds_variant("A15", user_given_array_15);
    run_bounds_variant("A16", user_given_array_16);
    run_bounds_variant("A17", user_given_array_17);
    run_bounds_variant("A18", user_given_array_18);
    run_bounds_variant("A19", user_given_array_19);
    run_bounds_variant("A20", user_given_array_20);
}



/* ================================================
   Function: run_lifetime_variant
   Attack Classification: Attack 2
   Reason: Constructs Rust-owned function pointers in a Box and hands their raw address to C; after C tampering/freeing, Rust calls fp_box, creating a potential lifetime / use-after-free violation at the FFI boundary.
   Risk Level: High
   ================================================ */

fn run_lifetime_variant(tag: &str, f: unsafe extern "C" fn(i64)) {
    let mut data = make_data();
    let fp_box: Box<fn(&mut i64)> = Box::new(doubler);
    let addr = &(*fp_box) as *const fn(&mut i64) as i64;

    println!("== {} ==", tag);
    println!("[{}] initial vals[0] = {}", tag, data.vals[0]);
    println!("[{}] fp_box addr = {}", tag, addr);

    unsafe { f(addr) }

    println!("[{}] calling fp_box after C freed/tampered...", tag);
    fp_box(&mut data.vals[0]);
    println!("[{}] final vals[0] = {}", tag, data.vals[0]);
    println!();
}

/* ================================================
   Function: run_lifetime_family
   Attack Classification: Attack 2
   Reason: Constructs Rust-owned function pointers in a Box and hands their raw address to C; after C tampering/freeing, Rust calls fp_box, creating a potential lifetime / use-after-free violation at the FFI boundary.
   Risk Level: High
   ================================================ */

fn run_lifetime_family() {
    run_lifetime_variant("L1", print_array_addr_1);
    run_lifetime_variant("L2", print_array_addr_2);
    run_lifetime_variant("L3", print_array_addr_3);
    run_lifetime_variant("L4", print_array_addr_4);
    run_lifetime_variant("L5", print_array_addr_5);
    run_lifetime_variant("L6", print_array_addr_6);
    run_lifetime_variant("L7", print_array_addr_7);
    run_lifetime_variant("L8", print_array_addr_8);
    run_lifetime_variant("L9", print_array_addr_9);
    run_lifetime_variant("L10", print_array_addr_10);
    run_lifetime_variant("L11", print_array_addr_11);
    run_lifetime_variant("L12", print_array_addr_12);
    run_lifetime_variant("L13", print_array_addr_13);
    run_lifetime_variant("L14", print_array_addr_14);
    run_lifetime_variant("L15", print_array_addr_15);
    run_lifetime_variant("L16", print_array_addr_16);
    run_lifetime_variant("L17", print_array_addr_17);
    run_lifetime_variant("L18", print_array_addr_18);
    run_lifetime_variant("L19", print_array_addr_19);
    run_lifetime_variant("L20", print_array_addr_20);
}



/* ================================================
   Function: run_hardening_variant
   Attack Classification: Attack 3
   Reason: Uses a local Rust function pointer (cb_fptr) while C performs stack-smashing writes via user_set_array_N; later indirect calls through cb_fptr model hardening/CFI bypass via corrupted stack-resident metadata.
   Risk Level: High
   ================================================ */

fn run_hardening_variant(tag: &str, f: unsafe extern "C" fn()) {
    let mut data = make_data();
    let cb_fptr: fn(&mut i64) = doubler;

    println!("== {} ==", tag);
    println!("[{}] initial vals[0] = {}", tag, data.vals[0]);
    println!("[{}] cb_fptr addr = {}", tag, cb_fptr as *const fn(&mut i64) as i64);

    unsafe { f() }

    println!("[{}] calling cb_fptr after C stack overflow...", tag);
    cb_fptr(&mut data.vals[0]);
    println!("[{}] final vals[0] = {}", tag, data.vals[0]);
    println!();
}

/* ================================================
   Function: run_hardening_family
   Attack Classification: Attack 3
   Reason: Uses a local Rust function pointer (cb_fptr) while C performs stack-smashing writes via user_set_array_N; later indirect calls through cb_fptr model hardening/CFI bypass via corrupted stack-resident metadata.
   Risk Level: High
   ================================================ */

fn run_hardening_family() {
    run_hardening_variant("H1", user_set_array_1);
    run_hardening_variant("H2", user_set_array_2);
    run_hardening_variant("H3", user_set_array_3);
    run_hardening_variant("H4", user_set_array_4);
    run_hardening_variant("H5", user_set_array_5);
    run_hardening_variant("H6", user_set_array_6);
    run_hardening_variant("H7", user_set_array_7);
    run_hardening_variant("H8", user_set_array_8);
    run_hardening_variant("H9", user_set_array_9);
    run_hardening_variant("H10", user_set_array_10);
    run_hardening_variant("H11", user_set_array_11);
    run_hardening_variant("H12", user_set_array_12);
    run_hardening_variant("H13", user_set_array_13);
    run_hardening_variant("H14", user_set_array_14);
    run_hardening_variant("H15", user_set_array_15);
    run_hardening_variant("H16", user_set_array_16);
    run_hardening_variant("H17", user_set_array_17);
    run_hardening_variant("H18", user_set_array_18);
    run_hardening_variant("H19", user_set_array_19);
    run_hardening_variant("H20", user_set_array_20);
}



/* ================================================
   Function: run_dynamic_variant
   Attack Classification: Attack 4
   Reason: Exposes &data.vecs as a raw pointer to C, which mutates Vec metadata through user_given_vec_N; subsequent safe indexing into data.vecs observes corrupted len/cap, modeling a dynamic-bounds (Vec metadata) attack.
   Risk Level: High
   ================================================ */

fn run_dynamic_variant(tag: &str, f: unsafe extern "C" fn(i64)) {
    let mut data = make_data();

    let doubler2_fp: Box<fn(&mut i64)> = Box::new(doubler);
    let doubler2_fp_addr = &(*doubler2_fp) as *const fn(&mut i64) as i64;

    let data_vecs_addr = &data.vecs as *const Vec<i64> as i64;

    println!("== {} ==", tag);
    println!("[{}] initial vals[0] = {}", tag, data.vals[0]);
    println!("[{}] vecs = {:?}, len = {}, cap = {}", tag, data.vecs, data.vecs.len(), data.vecs.capacity());
    println!("[{}] data_vecs_addr = {}", tag, data_vecs_addr);
    println!("[{}] doubler2_fp_addr = {}", tag, doubler2_fp_addr);

    unsafe { f(data_vecs_addr) }

    let data_vecs0_addr = &data.vecs[0] as *const i64 as i64;
    let vec_index = ((doubler2_fp_addr - data_vecs0_addr) / 8) as usize;
    let vec_val = get_attack();

    println!("[{}] addr of vecs[0] = {}", tag, data_vecs0_addr);
    println!("[{}] computed vec_index = {}", tag, vec_index);
    println!("[{}] writing vecs[vec_index] = get_attack() in safe Rust", tag);
    data.vecs[vec_index] = vec_val;

    println!("[{}] calling doubler2_fp after Vec metadata corruption...", tag);
    doubler2_fp(&mut data.vals[0]);
    println!("[{}] final vals[0] = {}", tag, data.vals[0]);
    println!();
}

/* ================================================
   Function: run_dynamic_family
   Attack Classification: Attack 4
   Reason: Exposes &data.vecs as a raw pointer to C, which mutates Vec metadata through user_given_vec_N; subsequent safe indexing into data.vecs observes corrupted len/cap, modeling a dynamic-bounds (Vec metadata) attack.
   Risk Level: High
   ================================================ */

fn run_dynamic_family() {
    run_dynamic_variant("B1", user_given_vec_1);
    run_dynamic_variant("B2", user_given_vec_2);
    run_dynamic_variant("B3", user_given_vec_3);
    run_dynamic_variant("B4", user_given_vec_4);
    run_dynamic_variant("B5", user_given_vec_5);
    run_dynamic_variant("B6", user_given_vec_6);
    run_dynamic_variant("B7", user_given_vec_7);
    run_dynamic_variant("B8", user_given_vec_8);
    run_dynamic_variant("B9", user_given_vec_9);
    run_dynamic_variant("B10", user_given_vec_10);
    run_dynamic_variant("B11", user_given_vec_11);
    run_dynamic_variant("B12", user_given_vec_12);
    run_dynamic_variant("B13", user_given_vec_13);
    run_dynamic_variant("B14", user_given_vec_14);
    run_dynamic_variant("B15", user_given_vec_15);
    run_dynamic_variant("B16", user_given_vec_16);
    run_dynamic_variant("B17", user_given_vec_17);
    run_dynamic_variant("B18", user_given_vec_18);
    run_dynamic_variant("B19", user_given_vec_19);
    run_dynamic_variant("B20", user_given_vec_20);
}


/* ================================================
   Function: run_intended_variant
   Attack Classification: Attack 5
   Reason: Obtains an integer callback address from C via get_cb_from_c_N and transmutes it into fn(&mut i64) without validation, modeling callback poisoning where forged addresses are treated as trusted function pointers in Rust.
   Risk Level: High
   ================================================ */

fn run_intended_variant(tag: &str, f: unsafe extern "C" fn() -> i64) {
    let mut data = make_data();

    let fp: fn(&mut i64) = unsafe {
        let c_addr: i64 = f();
        println!("[{}] C returned callback addr = {}", tag, c_addr);
        let ptr = c_addr as *const fn(&mut i64);
        std::mem::transmute::<*const fn(&mut i64), fn(&mut i64)>(ptr)
    };

    println!("== {} ==", tag);
    println!("[{}] initial vals[0] = {}", tag, data.vals[0]);
    println!("[{}] calling poisoned callback from C...", tag);
    fp(&mut data.vals[0]);
    println!("[{}] final vals[0] = {}", tag, data.vals[0]);
    println!();
}

/* ================================================
   Function: run_intended_family
   Attack Classification: Attack 5
   Reason: Obtains an integer callback address from C via get_cb_from_c_N and transmutes it into fn(&mut i64) without validation, modeling callback poisoning where forged addresses are treated as trusted function pointers in Rust.
   Risk Level: High
   ================================================ */

fn run_intended_family() {
    run_intended_variant("I1", get_cb_from_c_1);
    run_intended_variant("I2", get_cb_from_c_2);
    run_intended_variant("I3", get_cb_from_c_3);
    run_intended_variant("I4", get_cb_from_c_4);
    run_intended_variant("I5", get_cb_from_c_5);
    run_intended_variant("I6", get_cb_from_c_6);
    run_intended_variant("I7", get_cb_from_c_7);
    run_intended_variant("I8", get_cb_from_c_8);
    run_intended_variant("I9", get_cb_from_c_9);
    run_intended_variant("I10", get_cb_from_c_10);
    run_intended_variant("I11", get_cb_from_c_11);
    run_intended_variant("I12", get_cb_from_c_12);
    run_intended_variant("I13", get_cb_from_c_13);
    run_intended_variant("I14", get_cb_from_c_14);
    run_intended_variant("I15", get_cb_from_c_15);
    run_intended_variant("I16", get_cb_from_c_16);
    run_intended_variant("I17", get_cb_from_c_17);
    run_intended_variant("I18", get_cb_from_c_18);
    run_intended_variant("I19", get_cb_from_c_19);
    run_intended_variant("I20", get_cb_from_c_20);
}



/* ================================================
   Function: main
   Attack Classification: 0 — Safe
   Reason: No direct unsafe FFI boundary misuse detected; function uses only safe Rust operations (pure computation, printing, or simple struct construction) without manipulating raw pointers from C.
   Risk Level: Low
   ================================================ */

fn main() {
    unsafe { init() };

    println!("=== FAMILY 1: Bounds Check Bypass (20 variants) ===");
    run_bounds_family();

    println!("\n=== FAMILY 2: Lifetime Bypass (20 variants) ===");
    run_lifetime_family();

    println!("\n=== FAMILY 3: Hardening Bypass (20 variants) ===");
    run_hardening_family();

    println!("\n=== FAMILY 4: Dynamic Bounds (20 variants) ===");
    run_dynamic_family();

    println!("\n=== FAMILY 5: Intended Interaction (20 variants) ===");
    run_intended_family();

    println!("\nFinished all 100 variants.");
}



