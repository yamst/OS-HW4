#include <unistd.h>
#define P1_MAX_ALLOC 100000000


void* smalloc(size_t size){
    if ((size == 0) || (size > P1_MAX_ALLOC)){
        return NULL;
    }
    void* to_return = sbrk((intptr_t)size);
    if (to_return == (void*)-1){
        return NULL;
    }
    return to_return;
}