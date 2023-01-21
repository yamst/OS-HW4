/* REMOVE BEFORE SUBMISSION*/

#include "malloc_3.cpp"
#include <iostream>


void print_stats();

int main(){
	void *base = sbrk(0);
    char *a = (char *)smalloc(10);

    char *b = (char *)smalloc(10);

    char *c = (char *)smalloc(10);

    char *d = (char *)smalloc(10);

    char *e = (char *)smalloc(10);




    sfree(a);

    sfree(c);
 
    sfree(e);

	print_stats();

    char *new_a = (char *)smalloc(10);
    if (a!=new_a){
		std::cout << "oooops";
	}
    char *new_c = (char *)smalloc(10);
    if (c!=new_c){
		std::cout << "oooops";
	}
    char *new_e = (char *)smalloc(10);
    if (e!=new_e){
		std::cout << "oooops";
	}

    print_stats();

    sfree(new_a);

    sfree(b);

    sfree(new_c);

    sfree(d);

    sfree(new_e);
	print_stats();
	return 0;
}


void print_stats(){
    std::cout << "free blocks: " << _num_free_blocks() << ", free bytes: " << _num_free_bytes() <<
    ", total blocks: " << _num_allocated_blocks() << ", total bytes: " << _num_allocated_bytes() << std::endl;
}