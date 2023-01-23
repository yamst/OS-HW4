/* REMOVE BEFORE SUBMISSION*/

#include "malloc_3.cpp"
#include <iostream>


void print_stats();

int main(){

    char *a = (char *)smalloc(32 + MINIMUM_SIZE_FOR_SPLIT + _size_meta_data());
    print_stats();
    char *b = (char *)srealloc(a, 32);
    print_stats();
    sfree(b);
    print_stats();
}


void print_stats(){
    std::cout << "free blocks: " << _num_free_blocks() << ", free bytes: " << _num_free_bytes() <<
    ", total blocks: " << _num_allocated_blocks() << ", total bytes: " << _num_allocated_bytes() << std::endl;
}