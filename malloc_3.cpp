#include <unistd.h>
#include <assert.h>
#include <cstring>

#define P2_MAX_ALLOC 100000000
#define MINIMUM_SIZE_FOR_SPLIT 128
#define BUFFER_OVERFLOW_EXIT_VAL 0xdeadbeef

/* next_free and prev_free in struct mallocmetadata are uninitialized for used blocks */
struct MallocMetadata {
    int m_cookie;
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
int cookie_value = rand();

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

#define getDataAdress(meta) (void*)(((char*)meta)+sizeof(MallocMetadata))




/*** FUNCTIONS FOR SORTED LIST OPERATIONS. DO NOT UPDATE ANY GLOBAL COUNTERS. ***/
/* inserts an initilized not-free block to the sorted list.*/
void _insert_in_sorted_list(MallocMetadata* node);
/* Helper function for _insert_in_sorted_list.
Inserts @param node in the sorted list after @param before. if @param before is NULL then inserts at the beginning.*/
void _insert_in_sorted_list_after(MallocMetadata* node, MallocMetadata* before);
/* remove a non-free node from the sorted list.*/
void _remove_from_sorted_list(MallocMetadata* node);
/* update size of block and puts it in the correct location in the sorted list.*/
void _update_block_size(MallocMetadata* node, size_t size);


/* splits @param node (assumed to be a free block) into two free blocks of sizes @param size and the rest. 
Updates global counters accordingly.*/
void _free_block_split(MallocMetadata* node, size_t size);

/* removes a block from free list and sets it as not free. Updates global counters accordingly.*/
void _unfree(MallocMetadata* node);

/* merges left and right if they are adjacent and non-NULL. returns the right meta data or new merged meta data.
Updates Global Counters Accordingly.*/
MallocMetadata* _merge_two_frees(MallocMetadata* left, MallocMetadata* right)

/* takes a block (already in the list) and adds it to the free list - with coalescing. Updates global counters accordingly. */
void _free_and_coalesce(MallocMetadata* node);


/* returns last free block in list, by adress order. returns NULL if free list is empty. */
MallocMetadata* _find_last_free();
/* finds the free block in the list that is nearest but before node. returns NULL if doesn't exist*/
MallocMetadata* _find_prior_free(MallocMetadata* node);
/* finds the free block in the list that is nearest but after node. returns NULL if doesn't exist*/
MallocMetadata* _find_subsequent_free(MallocMetadata* node);

/* verifies meta's cookie, assuming it isn't NULL. exits program if cookie is invalid.*/
bool testCookie(MallocMetadata* meta);


void* smalloc(size_t size){
    if (size == 0 || size > P2_MAX_ALLOC){
        return NULL;
    }
    MallocMetadata * current = start_meta_data;
    while (current != NULL && testCookie(current)){
        if((current -> m_is_free) && ((current -> m_size) >= size)){
            if ((current -> m_size) >= size + MINIMUM_SIZE_FOR_SPLIT + sizeof(MallocMetadata)){
                _free_block_split(current, size);
            }
            _unfree(current);
            return getDataAdress(current);
        }
        current = current -> m_next;
    } //loop will handle case where moving the program break isn't needed.
    
    MallocMetadata* last_free = _find_last_free();
    if ((last_free != NULL) &&testCookie(last_free) &&(sbrk(0) == (char*)last_free + sizeof(MallocMetadata)+(last_free -> m_size))){
        assert(size > last_free -> m_size);
        if (sbrk(size - (last_free -> m_size)) == (void*)-1){
            return NULL;
        }
        _unfree(last_free);
        allocated_bytes += (size - last_free -> m_size);
        _update_block_size(last_free, size);
        return getDataAdress(last_free);
    }//try to extend wilderness block
    MallocMetadata* new_block = (MallocMetadata*)sbrk((intptr_t)(size + sizeof(MallocMetadata)));
    if (new_block == (MallocMetadata*)(void*)-1){
        return NULL;
    }
    new_block -> m_is_free = false;
    new_block -> m_size = size;
    _insert_in_sorted_list(new_block);
    allocated_blocks ++;
    allocated_bytes += size;
    return getDataAdress(new_block);
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
    testCookie(to_free);
    if (to_free -> m_is_free){
        return;
    }
    free_and_coalesce(to_free);
}

void* srealloc(void* oldp, size_t size){
    if (size == 0 || size > P2_MAX_ALLOC){
        return NULL;
    }
    if (oldp == NULL){
        return smalloc(size);
    }
    MallocMetadata* old_meta = (MallocMetadata *)((char*) oldp - sizeof(MallocMetadata));
    testCookie(old_meta);
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



void _insert_in_sorted_list(MallocMetadata* node){
    testCookie(node);
    MallocMetadata* current = start_meta_data;
    if ((current == NULL) || (!testCookie(current)) || (current -> m_size > node -> m_size) ||
    ((current -> m_size == node -> m_size) && (current > node))){
        _insert_in_sorted_list_after(node, NULL);
    }   else    {
        while ((current -> m_next != NULL) && (testCookie(current -> m_next)) && ((current -> m_next -> m_size < node -> m_size)
        || ((current -> m_next -> m_size == node -> m_size) && ((current -> m_next) < node)))){
            current = current -> m_next;
        }
        assert(current != NULL && testCookie(current));
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
        if (before -> m_next != NULL){
            before -> m_next -> m_prev = node;
        }
        before -> m_next = node;
    }
}//no need to test cookies as they were tested by caller function

void _remove_from_sorted_list(MallocMetadata* node){
    testCookie(node);
    assert(node != NULL);
    if (start_meta_data == node){
        start_meta_data = node -> m_next;
    }
    if (node -> m_prev != NULL && testCookie(node -> m_prev)){
        node -> m_prev -> m_next = node -> m_next;
    }
    if (node -> m_next != NULL && testCookie(node -> m_next)){
        node -> m_next -> m_prev = node -> m_prev;
    }
}

void _update_block_size(MallocMetadata* node, size_t size){
    _remove_from_sorted_list(node);
    node -> m_size = size;
    _insert_to_sorted_list(node);
}


void _free_block_split(MallocMetadata* node, size_t size){
    testCookie(node);
    assert(node != NULL);
    assert(((node -> m_size) - size)- sizeof(MallocMetadata) >= MINIMUM_SIZE_FOR_SPLIT);
    assert(node -> m_is_free);

    MallocMetadata* new_block = (MallocMetadata*)((char*)node + sizeof(MallocMetadata) + size);
    new_block -> m_is_free = true;
    new_block -> m_size = ((node -> m_size) - size)- sizeof(MallocMetadata);

    new_block -> m_next_free = node -> m_next_free;
    new_block -> m_prev_free = node;
    
    if (node -> m_next_free != NULL && testCookie(node -> m_next_free)){
        node -> m_next_free -> m_prev_free = new_block;
    }
    node -> m_next_free = new_block;

    _update_block_size(node, size);
    _insert_in_sorted_list(new_block);
    free_blocks++;
    allocated_blocks++;
    free_bytes -= sizeof(MallocMetadata);
    allocted_bytes -= sizeof(MallocMetadata);
}

MallocMetadata* _find_prior_free(MallocMetadata* node){
    MallocMetadata* iter = start_free_list;
    if (iter == NULL || iter > node || (!testCookie(iter))){
        return NULL;
    }
    assert(iter -> m_is_free);
    while (iter -> m_next_free != NULL && testCookie(iter -> m_next_free) && iter -> m_next_free > node){
        iter = iter -> m_next;
        assert(iter -> m_is_free);
    }
    return iter;
}

MallocMetadata* _find_subsequent_free(MallocMetadata* node){
    MallocMetadata* iter = start_free_list;
    while(iter != NULL && testCookie(iter) && iter < node){
        assert(iter -> m_is_free);
        iter = iter -> m_next_free;
    }
    return iter;
}

void free_and_coalesce(MallocMetadata* node){
    testCookie(node);
    assert(!(node -> m_is_free));
    MallocMetadata* previous = _find_prior_free(node);
    MallocMetadata* next = _find_subsequent_free(node);

    node -> m_is_free = true;
    free_blocks ++;
    free_bytes += node -> m_size;

    node -> m_next_free = next;
    node -> m_prev_free = previous;
    if (previous != NULL && testCookie(previous)){
        previous -> m_next_free = node;
    }   else    {
        start_free_list = node;
    }
    if (next != NULL && testCookie(next)){
        next -> m_prev_free = node;
    }
    node = _merge_two_frees(previous, node);
    _merge_two_frees(node, next);
}


MallocMetadata* _merge_two_frees(MallocMetadata* left, MallocMetadata* right){
    if (left == NULL || right == NULL || ((void*) ((char*)left + sizeof(MallocMetadata) + (left -> m_size)) != (void*) right)){
        return right;
    }// if one of the nodes is not valid or nodes aren't adjacent
    assert(left -> m_is_free && right -> m_is_free);
    free_blocks --;
    allocated_blocks--;
    free_bytes += sizeof(MallocMetadata);
    allocated_bytes += sizeof(MallocMetadata);
    
    _remove_from_sorted_list(right);
    left -> m_next_free = right -> m_next_free;
    if (right -> m_next_free != NULL && testCookie(right -> m_next_free)){
        right -> m_next_free -> m_prev_free = left;
    }//right is fully deleted.
    _update_block_size(left, ((left -> m_size) + sizeof(MallocMetadata) + (right -> m_size)));
    return left;
}

MallocMetadata* find_last_free(){
    MallocMetadata* iter = start_free_list;
    if (iter == NULL || (!testCookie(iter))){
        return NULL;
    }
    while (iter -> m_next_free != NULL && testCookie(iter -> m_next_free)){
        iter = iter -> m_next_free;
    }
    return iter;
}

void _unfree(MallocMetadata* node){
    testCookie(node);
    assert(node != NULL);
    if (start_free_list == node){
        start_free_list = node -> m_next_free;
    }
    if (node -> m_prev_free != NULL && testCookie(node -> m_prev_free)){
        node -> m_prev_free -> m_next_free = node -> m_next_free;
    }
    if (node -> m_next_free != NULL && testCookie(node -> m_next_free)){
        node -> m_next_free -> m_prev_free = node -> m_prev_free;
    }
    node -> m_is_free = false;
    free_blocks --;
    free_bytes  -= (node -> m_size);
}

bool testCookie(MallocMetadata* meta) {
    if(meta -> m_cookie != cookie_value){
        exit(BUFFER_OVERFLOW_EXIT_VAL);
    }
    return true;
}