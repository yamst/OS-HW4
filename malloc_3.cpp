#include <unistd.h>
#include <assert.h>
#include <cstring>

#define P2_MAX_ALLOC 100000000
#define MINIMUM_SIZE_FOR_SPLIT 128

/* next free and prev free in struct mallocmetadata are uninitialized for allocated blocks */

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


/* inserts an initilized allocated block to the sorted list*/
void _insert_in_sorted_list(MallocMetadata* node);

/* inserts @param node in the sorted list after @param before. if @param before is NULL then inserts at the beginning.*/
void _insert_in_sorted_list_after(MallocMetadata* node, MallocMetadata* before);

/* remove a node from the sorted list*/
void _remove_from_sorted_list(MallocMetadata* node);

/* puts a block whose size changed in the correct location in the sorted list*/
void _update_location_in_sorted_list(MallocMetadata* node);

/* allocates size out of free node and adds the rest as a free block to the list*/
void _free_block_split(MallocMetadata* node, size_t size)

/* finds the free block in the list that is nearest but before node. returns NULL if doesn't exist*/
MallocMetadata* _find_prior_free(MallocMetadata* node)

/* finds the free block in the list that is nearest but after node. returns NULL if doesn't exist*/
MallocMetadata* _find_subsequent_free(MallocMetadata* node);


/* takes a block (already in the list) and adds it to the free list - with coalescing. */
void _add_to_free_list_and_coalesce(MallocMetadata* node);




void* smalloc(size_t size){
    if (size == 0 || size > P2_MAX_ALLOC){
        return NULL;
    }
    MallocMetadata * current = start_meta_data;
    while (current != NULL){
        if((current -> m_is_free) && ((current -> m_size) >= size)){
            if ((current -> m_size) >= size + MINIMUM_SIZE_FOR_SPLIT + sizeof(MallocMetadata)){
                _free_block_split(current, size);
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
    //if reached this point, a new block needs to be created
    MallocMetadata* new_block = (MallocMetadata*)sbrk((intptr_t)(size + sizeof(MallocMetadata)));
    if (new_block == (void*)-1){
        return NULL;
    }
    new_block -> m_is_free = false;
    new_block -> m_size = size;
    _insert_in_sorted_list(new_block);
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
    _add_to_free_list_and_coalesce(to_free);
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
        std::memmove(to_return, oldp, old_meta -> m_size);
        sfree(oldp);
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



void _remove_from_sorted_list(MallocMetadata* node){
    if (start_meta_data == node){
        start_meta_data = node -> m_next;
    }
    if (node -> m_prev != NULL){
        node -> m_prev -> m_next = node -> m_next;
    }
    if (node -> m_next != NULL){
        node -> m_next -> m_prev = node -> m_prev;
    }
}

void _insert_in_sorted_list(MallocMetadata* node){
    MallocMetadata* current = start_meta_data;
    if ((current == NULL) || (current -> m_size > node -> m_size) || ((current -> m_size == node -> m_size) && (current > node))){
        _insert_in_sorted_list_after(node, NULL);
    }   else    {
        while ((current -> m_next != NULL) && ((current -> m_next -> m_size < node -> m_size) ||
        ((current -> m_next -> m_size == node -> m_size) && ((current -> m_next) < node)))){
            current = current -> m_next;
        }
        assert(current != NULL);
        _insert_in_sorted_list_after(node, current);
    }  
}

void _insert_in_sorted_list_after(MallocMetadata* node, MallocMetadata* before){
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

void _update_location_in_sorted_list(MallocMetadata* node){
    _remove_from_sorted_list(node);
    _insert_to_sorted_list(node);
}

void _free_block_split(MallocMetadata* node, size_t size){
    assert(node != NULL);
    assert(((node -> m_size) - size)- sizeof(MallocMetadata) >= MINIMUM_SIZE_FOR_SPLIT);
    assert(node -> m_is_free);

    MallocMetadata* new_block = (MallocMetadata*)((char*)node + sizeof(MallocMetadata) + size);
    new_block -> m_is_free = true;
    new_block -> m_size = ((node -> m_size) - size)- sizeof(MallocMetadata);

    if (start_free_list == node){
        start_free_list = new_block;
    }
    new_block -> m_next_free = node -> m_next_free;
    new_block -> m_prev_free = node -> m_prev_free;
    _insert_in_sorted_list(new_block);
    node -> m_is_free = false;
    node -> m_size = size;
    _update_location_in_sorted_list(node);
}

MallocMetadata* _find_prior_free(MallocMetadata* node){
    MallocMetadata* iter = start_free_list;
    if (iter == NULL || iter > node){
        return NULL;
    }
    assert(iter -> m_is_free);
    while (iter -> m_next_free != NULL && iter -> m_next_free > node){
        iter = iter -> m_next;
        assert(iter -> m_is_free);
    }
    return iter;
}

MallocMetadata* _find_subsequent_free(MallocMetadata* node){
    MallocMetadata* iter = start_free_list;
    while(iter != NULL && iter < node){
        assert(iter -> m_is_free);
        iter = iter -> m_next_free;
    }
    return iter;
}

void _add_to_free_list_and_coalesce(MallocMetadata* node){
    
    MallocMetadata* previous = _find_prior_free(node);
    MallocMetadata* next = _find_subsequent_free(node);
    node -> m_is_free = true;
    node -> m_next_free = next;
    node -> m_prev_free = previous;
    if (previous != NULL){
        previous -> m_next_free = node;
    }   else    {
        start_free_list = node;
    }
    if (next != NULL){
        next -> m_prev_free = node;
    }
    node = _merge_two_frees(previous, node);
    _merge_two_frees(node, next);


}


/* merges left and right if they are adjacent and non-NULL. returns the right data or new merged data*/
MallocMetadata* _merge_two_frees(MallocMetadata* left, MallocMetadata* right){
    if (left == NULL || right == NULL || ((void*) ((char*)left + sizeof(MallocMetadata) + left -> m_size) != (void*) right)){
        return right;
    }// if one of the nodes is not valid or nodes aren't adjacent
    free_blocks --;
    allocated_blocks--;
    free_bytes += sizeof(MallocMetadata);
    left -> m_size = ((left -> m_size) + sizeof(MallocMetadata) + (right -> m_size));
    left -> m_next_free = right -> m_next_free;
    if (right -> m_next_free != NULL){
        right -> m_next_free -> m_prev_free = left;
    }
    _remove_from_sorted_list(left);
    _remove_from_sorted_list(right);
    _insert_in_sorted_list(left);
    return left;
}