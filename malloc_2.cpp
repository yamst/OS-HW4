#include <unistd.h>
#include <assert.h>
#include <cstring>
#define P2_MAX_ALLOC 100000000

struct MallocMetadata {
    size_t m_size;
    bool m_is_free;
    MallocMetadata* m_next;
};


MallocMetadata* start_meta_data = NULL;
MallocMetadata* end_meta_data = NULL;
size_t free_blocks = 0;
size_t free_bytes = 0;
size_t allocated_blocks = 0;
size_t allocated_bytes = 0;






void* smalloc(size_t size);
void* scalloc(size_t num, size_t size);
void sfree(void* p);
void* srealloc(void* oldp, size_t size);

size_t _num_free_blocks();
size_t _num_free_bytes();
size_t _num_allocated_blocks();
size_t _num_allocated_bytes();
size_t _num_meta_data_bytes();
size_t _size_meta_data();


void* smalloc(size_t size){
    if (size == 0 || size > P2_MAX_ALLOC){
        return NULL;
    }
    MallocMetadata * current = start_meta_data;
    while (current != NULL){
        if((current -> m_is_free) && ((current -> m_size) >= size)){
            current -> m_is_free = false;
            free_blocks--;
            free_bytes  -= (current -> m_size);
            return (void*)(((char*)current) + sizeof(MallocMetadata)); 
        }
        current = current -> m_next;
    }
    MallocMetadata* new_block = (MallocMetadata*)sbrk((intptr_t)(size + sizeof(MallocMetadata)));
    if (new_block == (void*)-1){
        return NULL;
    }
    new_block -> m_is_free = false;
    new_block -> m_size = size;
    new_block -> m_next = NULL;
    if (end_meta_data != NULL){
        end_meta_data -> m_next = new_block;
    }   else    {
        assert(start_meta_data == NULL);
        start_meta_data = new_block;
    }
    end_meta_data = new_block;
    allocated_blocks ++;
    allocated_bytes += size;
    return (void*)((char*)new_block + sizeof(MallocMetadata));
}

void* scalloc(size_t num, size_t size){
    void* allocated = smalloc(num * size);
    if (allocated == NULL){
        return NULL;
    }
    std::memset(allocated, 0, num * size);
    return allocated;
}

void sfree(void* p){
    if (p == NULL){
        return;
    }
    MallocMetadata * to_free = (MallocMetadata *)((char*) p - sizeof(MallocMetadata));
    if (to_free -> m_is_free){
        return;
    }
    to_free -> m_is_free = true;
    free_blocks ++;
    free_bytes += to_free -> m_size;
}

void* srealloc(void* oldp, size_t size){
    if (size == 0 || size > P2_MAX_ALLOC){
        return NULL;
    }
    if (oldp == NULL){
        return smalloc(size);
    }
    MallocMetadata* old_meta = (MallocMetadata *)((char*) oldp - sizeof(MallocMetadata));
    assert(old_meta -> m_is_free == false);
    if (old_meta -> m_size >= size){
        return oldp;
    }
    void* to_return = smalloc(size);
    if (to_return != NULL){
        sfree(oldp);
        std::memmove(to_return, oldp, old_meta -> m_size);
    }
    return to_return;
}

size_t _num_free_blocks(){
    return free_blocks;
}

size_t _num_free_bytes(){
    return free_bytes;
}

size_t _num_allocated_blocks(){
    return allocated_blocks;
}

size_t _num_allocated_bytes(){
    return allocated_bytes;
}

size_t _num_meta_data_bytes(){
    return allocated_blocks * sizeof(MallocMetadata);
}

size_t _size_meta_data(){
    return sizeof(MallocMetadata);
}