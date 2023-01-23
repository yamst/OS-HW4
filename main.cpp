/* REMOVE BEFORE SUBMISSION*/

#include "malloc_3.cpp"
#include <iostream>


void print_stats();

int main(){

    
    char *a = (char *)smalloc(128 + 32);
    char *b = (char *)smalloc(32);
    char *c = (char *)smalloc(32);
    
    print_stats();

    sfree(a);
    sfree(c);
    
    print_stats();

    char *new_b = (char *)srealloc(b, 64);
    
    print_stats();

    sfree(new_b);
    print_stats();

}


void print_stats(){
    std::cout << "free blocks: " << _num_free_blocks() << ", free bytes: " << _num_free_bytes() <<
    ", total blocks: " << _num_allocated_blocks() << ", total bytes: " << _num_allocated_bytes() << std::endl;
}