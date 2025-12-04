#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>

extern int64_t get_attack();

void user_set_array() {

    
    int64_t a[1] = { 0 };

    
    
    
    int64_t array_index = 28; 
    int64_t array_value = get_attack(); 

    printf("addr of &a: %ld\n", (int64_t)&a);
    printf("array_value %ld\n", array_value);
    printf("addr of a[array_index] in user_given_array: %ld\n", (int64_t)&(a[array_index]));

    a[array_index] = array_value;
    printf("Done with user_set_array.\n");
}

void user_given_array(int64_t array_ptr_addr) {
    
    
    
    int64_t array_index = 3;
    int64_t array_value = get_attack(); 

    int64_t* a = (void *)array_ptr_addr;
    printf("addr of a[array_index] in user_given_array: %ld\n", (int64_t)&(a[array_index]));

    a[array_index] = array_value;
    printf("Done with user_given_array.\n");
}

void print_array_addr(int64_t array_ptr_addr) {
    int64_t* a = (void *)array_ptr_addr;
    printf("addr of a in print_array_addr: %ld\n", (int64_t)a);

    
    
    free(a);

    
    
    
    
    int64_t array_value = get_attack(); 
    *a = array_value;

    printf("Done with print_array_addr.\n");
}

int64_t get_cb_from_c() {
    
    int64_t call_back_addr = get_attack(); 

    return call_back_addr;
}

void init() {
    
    
    
    
    mallopt(M_CHECK_ACTION, 1);
}

void user_given_vec(int64_t vec_ptr_addr) {
    
    
    
    int64_t array_index = 2;
    int64_t array_value = 10000000; 

    int64_t* a = (void *)vec_ptr_addr;

    printf("addr of a[array_index] in user_given_slice: %ld\n", (int64_t)&(a[array_index]));

    a[array_index] = array_value;
    printf("Done with user_given_vec.\n");
}

