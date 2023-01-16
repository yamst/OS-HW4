#include <unistd.h>
#include <assert.h>
#include <cstring>

#define P2_MAX_ALLOC 100000000
#define MINIMUM_SIZE_FOR_SPLIT 128

struct MallocMetadata {
    size_t m_size;
    bool m_is_free;
    MallocMetadata* m_next;
    MallocMetadata* m_prev;
    MallocMetadata* m_next_free;
    MallocMetadata* m_prev_free;
};


MallocMetadata* start_meta_data = NULL;
MallocMetadata* start_free_list = NULL;
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

void block_split(MallocMetadata* node, size_t size);













void* smalloc(size_t size){
    if (size == 0 || size > P2_MAX_ALLOC){
        return NULL;
    }
    MallocMetadata * current = start_meta_data;
    while (current != NULL){
        if((current -> m_is_free) && ((current -> m_size) >= size)){
            if ((current -> m_size) >= size + MINIMUM_SIZE_FOR_SPLIT + sizeof(MallocMetadata)){
                block_split(current, size);
                free_blocks++;
                free_bytes -= sizeof(MallocMetadata);
            }
            current -> m_is_free = false;
            free_blocks --;
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
    current = start_meta_data;

    if (current == NULL){
        start_meta_data = new_block;
        new_block -> m_next = NULL;
        new_block -> m_prev = NULL;
    }   else    {
        while ((current -> m_next != NULL) && 
        ((current -> m_size < size) || ((current -> m_size == size) && (current < new_block)))){
            current = current -> m_next;
        }
        assert(current != NULL);
        new_block -> m_next = current -> m_next;
        new_block -> m_prev = current;
        if (current -> m_next != NULL){
            current -> m_next -> m_prev = new_block;
        }
        current -> m_next = new_block;
    }
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





void insert_not_free(MallocMetadata* node){
    assert(node -> m_is_free == false);
    MallocMetadata* current = start_meta_data;
    if ((current == NULL) || (current -> m_size > node -> m_size) || ((current -> m_size == node -> m_size) && (current > node))){
        insert_node_after(node, NULL);
    }   else    {
        while ((current -> m_next != NULL) && ((current -> m_next -> m_size < node -> m_size) ||
        ((current -> m_next -> m_size == node -> m_size) && (current -> m_next < node)))){
            current = current -> m_next;
        }
        assert(current != NULL);
        insert_node_after(node, current);
    }  
    current = start_free_list;
    if(current)
    while (current){

    }

}



void insert_node_after(MallocMetadata* node, MallocMetadata* before){
    if (before == NULL){
        MallocMetadata* start = start_meta_data;
        start_meta_data = node;
        node -> m_prev = NULL;
        node -> m_next = start;
        if (start != NULL){
            start -> m_prev = node;
        }
    }  else    {
        node -> m_next = before -> m_next;
        node -> m_prev = before;
        if (current -> m_next != NULL){
            current -> m_next -> m_prev = node;
        }
        current -> m_next = node;
    }
}




    















void block_split(MallocMetadata* node, size_t size){
    assert(node != NULL);
    MallocMetadata* new_block = (MallocMetadata*)((char*)node + size + sizeof(MallocMetadata));
    new_block -> m_is_free = true;
    new_block -> m_size = ((node -> m_size) - size)- sizeof(MallocMetadata);
    assert(((node -> m_size) - size)- sizeof(MallocMetadata) >= MINIMUM_SIZE_FOR_SPLIT);
    new_block -> m_next = node -> m_next;
    new_block -> m_prev = node;
    if (node -> m_next != NULL){
        node -> m_next -> m_prev = new_block;
    }
    node -> m_next = new_block;
    node -> m_size = size;
}