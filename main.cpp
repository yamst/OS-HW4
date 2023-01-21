/* REMOVE BEFORE SUBMISSION*/

#include "malloc_3.cpp"
#include <iostream>


void print_stats();

int main(){
	void * a = smalloc(100);
    print_stats();
	void*  b = smalloc(300);
    print_stats();

	sfree(a);
    print_stats();
	sfree(b);
    print_stats();
	void * c = smalloc(200);
    print_stats();
	void * d = smalloc(200);
    print_stats();

	std::cout << "b-a (should be 100+md): " << (char*)b-(char*)a 
	<< ".      d-c (should be 200+md): " << (char*)d-(char*)c << std::endl;
	std::cout << "size of meta: " <<  _size_meta_data() <<std::endl;
	
	
	return 0;
}


void print_stats(){
    std::cout << "free blocks: " << _num_free_blocks() << ", free bytes: " << _num_free_bytes() <<
    ", total blocks: " << _num_allocated_blocks() << ", total bytes: " << _num_allocated_bytes() << std::endl;
}