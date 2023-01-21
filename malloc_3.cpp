#include <unistd.h>
#include <assert.h>
#include <cstring>
#include <cstdlib>

#define P2_MAX_ALLOC 100000000
#define BUFFER_OVERFLOW_EXIT_VAL 0xdeadbeef

struct MallocMetadata {
    int m_cookie;
    size_t m_size;
    bool m_is_free;
    MallocMetadata* m_next;
    MallocMetadata* m_prev;
    MallocMetadata* m_next_free;
    MallocMetadata* m_prev_free;
};/* next_free and prev_free in struct mallocmetadata are uninitialized for used blocks */

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

MallocMetadata* start_meta_data = NULL;
MallocMetadata* start_free_list = NULL;
MallocMetadata* start_mmap_list = NULL;
MallocMetadata* end_mmap_list = NULL;
size_t free_blocks = 0;
size_t free_bytes = 0;
size_t allocated_blocks = 0;
size_t allocated_bytes = 0;
int cookie_value = rand();

#define getDataAdress(meta) (meta==NULL?NULL:(void*)(((char*)meta)+sizeof(MallocMetadata)))
#define MINIMUM_SIZE_FOR_MMAP 128*1024
#define MINIMUM_SIZE_FOR_SPLIT 128

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
MallocMetadata* _merge_two_frees(MallocMetadata* left, MallocMetadata* right);
/* takes a block (already in the list) and adds it to the free list - with coalescing. Updates global counters accordingly. */
void _free_and_coalesce(MallocMetadata* node);

/* returns last free block in list, by adress order. returns NULL if free list is empty. */
MallocMetadata* _find_last_free();
/* finds the free block in the list that is nearest but before node. returns NULL if doesn't exist*/
MallocMetadata* _find_prior_free(MallocMetadata* node);
/* finds the free block in the list that is nearest but after node. returns NULL if doesn't exist*/
MallocMetadata* _find_subsequent_free(MallocMetadata* node);

/* verifies meta's cookie, assuming it isn't NULL. exits program if cookie is invalid.*/
bool _testCookie(MallocMetadata* meta);
/* initializes a block with cookie, free status, and size*/
void _initialize_block(MallocMetadata* node, bool is_free, size_t size);

/* allocates a new block with mmap (including adding to list & updating counters) and returns its meta. NULL if failed*/
MallocMetadata* _mmap_allocate(size_t size);

void* smalloc(size_t size){
    if (size == 0 || size > P2_MAX_ALLOC){
        return NULL;
    }
    if (size >= MINIMUM_SIZE_FOR_MMAP) {
        return getDataAdress(_mmap_allocate(size));
    }// mmap for large allocations

    MallocMetadata * current = start_meta_data;
    while (current != NULL && _testCookie(current)){
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
    if ((last_free != NULL) &&_testCookie(last_free) &&(sbrk(0) == (char*)last_free + sizeof(MallocMetadata)+(last_free -> m_size))){
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
    _initialize_block(new_block, false, size);
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
    if (_testCookie(to_free) && to_free -> m_is_free){
        return;
    }
    if (to_free -> m_size >= MINIMUM_SIZE_FOR_MMAP) { // block is a mapped memory region
        allocated_blocks--;
        allocated_bytes -= to_free -> m_size;
        if (to_free -> m_prev != NULL && testCookie(to_free -> m_prev)) {
            to_free -> m_prev -> m_next = to_free -> m_next;
        }
        if (to_free -> m_next != NULL && testCookie(to_free -> m_next)) {
            to_free -> m_next -> m_prev = to_free -> m_prev;
        }
        if (start_mmap_list == to_free) {
            start_mmap_list = to_free -> m_next;
        }
        if (end_mmap_list == to_free) {
            end_mmap_list = to_free -> m_prev;
        }
        munmap((void*)to_free, sizeof(MallocMetadata) + to_free -> m_size);
    }   else    {
        _free_and_coalesce(to_free);
    }
}

void* srealloc(void* oldp, size_t size){
    if (size == 0 || size > P2_MAX_ALLOC){
        return NULL;
    }
    if (oldp == NULL){
        return smalloc(size);
    }

    //TO_FINISH






    MallocMetadata* old_meta = (MallocMetadata *)((char*) oldp - sizeof(MallocMetadata));
    _testCookie(old_meta);
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
    _testCookie(node);
    MallocMetadata* current = start_meta_data;
    if ((current == NULL) || (!_testCookie(current)) || (current -> m_size > node -> m_size) ||
    ((current -> m_size == node -> m_size) && (current > node))){
        _insert_in_sorted_list_after(node, NULL);
    }   else    {
        while ((current -> m_next != NULL) && (_testCookie(current -> m_next)) && ((current -> m_next -> m_size < node -> m_size)
        || ((current -> m_next -> m_size == node -> m_size) && ((current -> m_next) < node)))){
            current = current -> m_next;
        }
        assert(current != NULL && _testCookie(current));
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
    _testCookie(node);
    assert(node != NULL);
    if (start_meta_data == node){
        start_meta_data = node -> m_next;
    }
    if (node -> m_prev != NULL && _testCookie(node -> m_prev)){
        node -> m_prev -> m_next = node -> m_next;
    }
    if (node -> m_next != NULL && _testCookie(node -> m_next)){
        node -> m_next -> m_prev = node -> m_prev;
    }
}

void _update_block_size(MallocMetadata* node, size_t size){
    _remove_from_sorted_list(node);
    node -> m_size = size;
    _insert_in_sorted_list(node);
}

void _free_block_split(MallocMetadata* node, size_t size){
    _testCookie(node);
    assert(node != NULL);
    assert(((node -> m_size) - size)- sizeof(MallocMetadata) >= MINIMUM_SIZE_FOR_SPLIT);
    assert(node -> m_is_free);

    MallocMetadata* new_block = (MallocMetadata*)((char*)node + sizeof(MallocMetadata) + size);
    _initialize_block(new_block, true, ((node -> m_size) - size)- sizeof(MallocMetadata));

    new_block -> m_next_free = node -> m_next_free;
    new_block -> m_prev_free = node;
    
    if (node -> m_next_free != NULL && _testCookie(node -> m_next_free)){
        node -> m_next_free -> m_prev_free = new_block;
    }
    node -> m_next_free = new_block;

    _update_block_size(node, size);
    _insert_in_sorted_list(new_block);
    free_blocks++;
    allocated_blocks++;
    free_bytes -= sizeof(MallocMetadata);
    allocated_bytes -= sizeof(MallocMetadata);
}

MallocMetadata* _find_prior_free(MallocMetadata* node){
    MallocMetadata* iter = start_free_list;
    if (iter == NULL || iter > node || (!_testCookie(iter))){
        return NULL;
    }
    assert(iter -> m_is_free);
    while (iter -> m_next_free != NULL && _testCookie(iter -> m_next_free) && iter -> m_next_free > node){
        iter = iter -> m_next;
        assert(iter -> m_is_free);
    }
    return iter;
}

MallocMetadata* _find_subsequent_free(MallocMetadata* node){
    MallocMetadata* iter = start_free_list;
    while(iter != NULL && _testCookie(iter) && iter < node){
        assert(iter -> m_is_free);
        iter = iter -> m_next_free;
    }
    return iter;
}

void _free_and_coalesce(MallocMetadata* node){
    _testCookie(node);
    assert(!(node -> m_is_free));
    MallocMetadata* previous = _find_prior_free(node);
    MallocMetadata* next = _find_subsequent_free(node);

    node -> m_is_free = true;
    free_blocks ++;
    free_bytes += node -> m_size;

    node -> m_next_free = next;
    node -> m_prev_free = previous;
    if (previous != NULL && _testCookie(previous)){
        previous -> m_next_free = node;
    }   else    {
        start_free_list = node;
    }
    if (next != NULL && _testCookie(next)){
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
    if (right -> m_next_free != NULL && _testCookie(right -> m_next_free)){
        right -> m_next_free -> m_prev_free = left;
    }//right is fully deleted.
    _update_block_size(left, ((left -> m_size) + sizeof(MallocMetadata) + (right -> m_size)));
    return left;
}

MallocMetadata* _find_last_free(){
    MallocMetadata* iter = start_free_list;
    if (iter == NULL || (!_testCookie(iter))){
        return NULL;
    }
    while (iter -> m_next_free != NULL && _testCookie(iter -> m_next_free)){
        iter = iter -> m_next_free;
    }
    return iter;
}

void _unfree(MallocMetadata* node){
    _testCookie(node);
    assert(node != NULL);
    if (start_free_list == node){
        start_free_list = node -> m_next_free;
    }
    if (node -> m_prev_free != NULL && _testCookie(node -> m_prev_free)){
        node -> m_prev_free -> m_next_free = node -> m_next_free;
    }
    if (node -> m_next_free != NULL && _testCookie(node -> m_next_free)){
        node -> m_next_free -> m_prev_free = node -> m_prev_free;
    }
    node -> m_is_free = false;
    free_blocks --;
    free_bytes  -= (node -> m_size);
}

bool _testCookie(MallocMetadata* meta) {
    if(meta -> m_cookie != cookie_value){
        exit(BUFFER_OVERFLOW_EXIT_VAL);
    }
    return true;
}

void _initialize_block(MallocMetadata* node, bool is_free, size_t size){
    assert(node != NULL);
    node -> m_is_free = is_free;
    node -> m_size = size;
    node -> m_cookie = cookie_value;
}

MallocMetadata* _mmap_allocate(size_t size){
    MallocMetadata* new_block = (MallocMetadata*)mmap(NULL, size + sizeof(MallocMetadata),
    PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if ((void*)new_block == MAP_FAILED){
        return NULL;
    }
    _initialize_block(new_block, false, size);
    new_block -> m_prev = end_mmap_list;
    new_block -> m_next = NULL;
    if (end_mmap_list != NULL && testCookie(end_mmap_list)) {
        end_mmap_list -> m_next = new_block;
    }   else    {
        start_mmap_list = new_block;
    }
    end_mmap_list = new_block;
    allocated_blocks++;
    allocated_bytes += size;
}