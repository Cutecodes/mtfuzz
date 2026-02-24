#include "stream.h"
#include "khash.h"
#define likely(_x)   __builtin_expect(!!(_x), 1)
#define unlikely(_x)  __builtin_expect(!!(_x), 0)

#define PREALLOCED_BUF_SIZE 10000000
#define MAX_BUF_SIZE        100000000
#define PREALLOCED_STREAM_BUF_SIZE 65536

#ifdef SMART_STREAM
void init_CircularQueue(CircularQueue* q) {
    if (!q) {
        return;
    }
    q->front = 0;
    q->rear = -1;
    q->count = 0;
}

bool enqueue_CircularQueue(CircularQueue* q, uint64_t val) {
    if (!q) {
        return false;
    }
    q->rear = (q->rear + 1) % FIFO_MAX_SZIE;
    q->data[q->rear] = val;
    if (q->count == FIFO_MAX_SZIE) {
        q->front = (q->front + 1) % FIFO_MAX_SZIE;
    }else{
        q->count++;   
    }
    return true;
}

uint64_t* get_data__CircularQueue(CircularQueue* q, int *size){
   *size = q->count;
   if (q->count == FIFO_MAX_SZIE)
       memmove(&q->data[FIFO_MAX_SZIE], &q->data[0], (q->rear+1) * sizeof(uint64_t));
   return &q->data[q->front];
}
CircularQueue last_read_mmio;

#endif

KHASH_MAP_INIT_INT(64, struct mmio2stream*);
KHASH_MAP_INIT_INT(ptr, uint8_t**);

// file information
static uint16_t g_num_mmio = 0;
static uint16_t g_num_stream = 0;
static bool g_read_only = 1;
static struct stream_mem g_streams[MAX_STREAM_SIZE];
static struct mmio2stream g_m2s[MAX_MMIO_SIZE];


static khash_t(64) *kh_mmio_addr_to_mmio2stream = NULL;

static uint8_t* g_file_buffer = NULL;
static uint32_t g_file_buffer_size = 0;

// all mmio size
static uint32_t  cache_num = 0;
static uint8_t* cache_buffer[MAX_MMIO_SIZE];
static uint32_t cache_buffer_size[MAX_MMIO_SIZE];

uint16_t get_num_mmio() {
    return g_num_mmio;
}

uint16_t get_num_stream() {
    return g_num_stream;
}

struct mmio2stream* get_mmios() {
    return g_num_mmio? &g_m2s[0] : NULL;
}

struct stream_mem* get_streams() {
    return g_num_stream? &g_streams[0] : NULL;
}

static bool check_cache(uint16_t id, uint32_t len) {
    uint32_t buffsize;
    if (id < cache_num) {
        if (len > cache_buffer_size[id] && cache_buffer_size[id] != MAX_STREAM_LEN) {
            buffsize = cache_buffer_size[id];
            while (buffsize < len) {
                buffsize <<= 1;
            }
            if (buffsize > MAX_STREAM_LEN) {
                buffsize = MAX_STREAM_LEN;
            }
            cache_buffer[id] = realloc(cache_buffer[id], buffsize);
            cache_buffer_size[id] = buffsize;
            if (cache_buffer[id] == NULL) {
                 printf("[check cache] Failed to realloc\n");
                 return false;
            }
        }
                
    }else {
                
        buffsize = PREALLOCED_STREAM_BUF_SIZE;
        while (buffsize < len) {
            buffsize <<= 1;
        }
        if (buffsize > MAX_STREAM_LEN) {
            buffsize = MAX_STREAM_LEN;
        }
        cache_buffer[id] = malloc(buffsize);
        cache_buffer_size[id] = buffsize;
        if (cache_buffer[id] == NULL) {
            printf("[check cache] Failed to malloc\n");
            return false;
        }
        cache_num++;
    }
    return true;
}

bool init_streams(uint8_t* buffer, uint32_t len, bool read_only) {

    if (unlikely(!kh_mmio_addr_to_mmio2stream)) {
        kh_mmio_addr_to_mmio2stream = kh_init(64);
    };
    destory_streams();
    g_read_only = read_only;
    if (len < 4) {
        #ifdef DEBUG_STREAM
        printf("[build stream] build stream failed!!!file length is %d\n",len);
        #endif
        return false;
    };
    uint16_t num_mmio = *(uint16_t*)buffer;
    uint16_t num_stream = *(uint16_t*)(buffer+2);
    if (num_mmio==0 || num_stream ==0) {
        return false;
    }
    uint32_t len_header = 4 + num_mmio * sizeof(struct mmio2stream) + num_stream * sizeof(struct stream_file);
    if (len < len_header) {
        #ifdef DEBUG_STREAM
        printf("[build stream] build stream failed!!! num mmio: %d, num stream: %d, length of file header:%d, file length:%d\n",num_mmio,num_stream,len_header,len);
        #endif
        return false;
    }
    struct stream_file* streams = (struct stream_file*)&buffer[4 + num_mmio*sizeof(struct mmio2stream)];
    uint32_t len_data = 0;
    for(int i=0;i<num_stream;i++){
        #ifdef DEBUG_STREAM
        printf("[build stream] stream id: %d, stream length: %d\n",i,streams[i].len);
        #endif
        len_data += streams[i].len;
    }
    if (len < len_header + len_data) {
        #ifdef DEBUG_STREAM
        printf("[build stream] build stream failed!!! num mmio: %d, num stream: %d, length of file header:%d, length of stream_data:%d, file length:%d\n",num_mmio,num_stream,len_header,len_data, len);
        #endif
        return false;
    }
    
    g_num_mmio = num_mmio;
    g_num_stream = num_stream;
    g_read_only = read_only;
    
    struct mmio2stream* m2s = (struct mmio2stream*)&buffer[4];

    
    int kh_res;

    for (int i=0;i<g_num_mmio;i++){
        g_m2s[i] = m2s[i];
        #ifdef DEBUG_STREAM
        printf("[build stream] mmio addr: %016lx, size:%d, stream id:%d\n",g_m2s[i].mmio_addr, g_m2s[i].size, g_m2s[i].stream_id);
        #endif
        if(kh_get(64, kh_mmio_addr_to_mmio2stream, m2s[i].mmio_addr) == kh_end(kh_mmio_addr_to_mmio2stream)) {
            khiter_t k = kh_put(64, kh_mmio_addr_to_mmio2stream, m2s[i].mmio_addr, &kh_res);
            kh_value(kh_mmio_addr_to_mmio2stream, k) = &g_m2s[i];
        }
    }
    
    len_data = 0;
    for (int i=0;i<g_num_stream;i++) {
        
        g_streams[i].id = i;
        g_streams[i].size = streams[i].size;
        g_streams[i].len = streams[i].len;
        if (g_read_only) {
            // we use the data in buffer
            g_streams[i].data = &buffer[len_header+len_data];
        }else {
            
            if (!check_cache(i, g_streams[i].len)) {
                printf("[build stream] Get stream buffer failed!\n");
                exit(-1);
            }
            g_streams[i].data = cache_buffer[i];
            memcpy(g_streams[i].data, &buffer[len_header+len_data], g_streams[i].len);
        }
        len_data += g_streams[i].len;
        #ifdef DEBUG_STREAM
        printf("stream id: %d \n",i);
        for(int j=0;j<streams[i].len;j++){
            printf("%02x ",g_streams[i].data[j]);
        } 
        printf("\n");
        #endif
    }
    #ifdef DEBUG_STREAM
    printf("[build stream] build stream successfully!!! num mmio: %d, num stream: %d, length of file header:%d, length of stream_data:%d, file length:%d\n",num_mmio,num_stream,len_header,len_data, len);
    #endif
    return true;
    
};

struct stream_mem* get_stream_by_addr(uint64_t addr) {
    khiter_t k = kh_get(64, kh_mmio_addr_to_mmio2stream, addr);
    if( k != kh_end(kh_mmio_addr_to_mmio2stream)) {
         return &(g_streams[kh_value(kh_mmio_addr_to_mmio2stream, k)->stream_id]);
    }
    return NULL;
};

bool insert_stream(uint64_t addr, uint16_t size) {
    khiter_t k = kh_get(64, kh_mmio_addr_to_mmio2stream, addr);
    int kh_res;
    
    if( k != kh_end(kh_mmio_addr_to_mmio2stream)) {
         #ifdef DEBUG_STREAM
         printf("[insert stream] Stream %016lx already exists\n",addr);
         #endif
         return false;
    }else{
         g_m2s[g_num_mmio].mmio_addr = addr;
         g_m2s[g_num_mmio].size = size;
         g_m2s[g_num_mmio].stream_id = g_num_stream;
         k = kh_put(64, kh_mmio_addr_to_mmio2stream, addr, &kh_res);
         kh_value(kh_mmio_addr_to_mmio2stream, k) = &g_m2s[g_num_mmio];
         
         g_streams[g_num_stream].id = g_num_stream;
         g_streams[g_num_stream].size = size;
         g_streams[g_num_stream].len = 0;
         g_streams[g_num_stream].data = NULL;
         #ifdef DEBUG_STREAM
         printf("[insert stream] mmio addr: %016lx, size:%d, stream id:%d\n",g_m2s[g_num_mmio].mmio_addr, g_m2s[g_num_mmio].size, g_m2s[g_num_mmio].stream_id);
         #endif
         g_num_mmio += 1;
         g_num_stream += 1;
         return true;
    }
};

bool destory_streams() {

    
    if (likely(kh_mmio_addr_to_mmio2stream)) {
        kh_clear(64, kh_mmio_addr_to_mmio2stream);
    }
    
    /*
    if (!g_read_only){
        for (int i=0;i<g_num_stream;i++) {
            //if (g_streams[i].data)
              //  free(g_streams[i].data);
            g_streams[i].data = NULL;
        }
    }
    */
    g_num_mmio = 0;
    g_num_stream = 0;
    g_read_only = 1;
    return true;
};

uint8_t* get_file(uint32_t* len) {
    uint16_t num_mmio = g_num_mmio;
    uint16_t num_stream = g_num_stream;
    uint32_t len_header = 4 + num_mmio * sizeof(struct mmio2stream) + num_stream * sizeof(struct stream_file);
    uint32_t len_data = 0;

    for (int i=0;i<g_num_stream;i++){
        #ifdef DEBUG_STREAM
        printf("[get_file] stream id: %d, stream length: %d\n",i, g_streams[i].len);
        #endif
        len_data += g_streams[i].len;
    }
    
    *len = len_data + len_header;
    #ifdef DEBUG_STREAM
    printf("[get_file] num mmio: %d, num stream: %d, length of file header:%d, length of stream_data:%d, file length:%d\n",g_num_mmio,g_num_stream,len_header,len_data, *len);
    #endif
    if (!g_file_buffer) {
        g_file_buffer = malloc(PREALLOCED_BUF_SIZE);
        if (!g_file_buffer) {
            printf("[get_file] stream malloc failed!\n");
            exit(0);
        }
        g_file_buffer_size = PREALLOCED_BUF_SIZE;
    }
    
    if (*len > g_file_buffer_size) {
        while(*len > g_file_buffer_size) {
            g_file_buffer_size <<= 1;
        }
        g_file_buffer = realloc(g_file_buffer, g_file_buffer_size);
        
    }
    assert( g_file_buffer != NULL);

    
    *(uint16_t*)g_file_buffer = g_num_mmio;
    *(uint16_t*)(g_file_buffer+2) = g_num_stream;
    struct mmio2stream* m2s = (struct mmio2stream*)&g_file_buffer[4];
    struct stream_file* streams = (struct stream_file*)&g_file_buffer[4 + num_mmio * sizeof(struct mmio2stream)];
    len_data = 0;
     
    for (int i=0;i<g_num_mmio;i++){
        m2s[i] = g_m2s[i];
        #ifdef DEBUG_STREAM
        printf("[get_file] mmio addr: %016lx, size:%d, stream id:%d\n",m2s[i].mmio_addr, m2s[i].size, m2s[i].stream_id);
        #endif
    }
        
    for (int i=0;i<g_num_stream;i++) {
        streams[i].size = g_streams[i].size;
        streams[i].len = g_streams[i].len;        
        memcpy(&g_file_buffer[len_header+len_data], g_streams[i].data, g_streams[i].len);
        len_data += g_streams[i].len;
    }
    #ifdef DEBUG_STREAM
    for(int i=0;i<*len;i++){
        printf("%02x ",g_file_buffer[i]);
    } 
    printf("\n");
    #endif  
    return g_file_buffer;
       
}

bool stream_insert_region(uint64_t addr, uint32_t offset, uint32_t len, uint8_t* buffer) {

    if (unlikely(g_read_only)) {
        return false;
    }

    struct stream_mem* stream = get_stream_by_addr(addr);
    if (unlikely(!stream)) {
        return false;
    }

    if (offset > stream->len) {
        return false;
    }

    if (offset + len > MAX_STREAM_LEN){
        len = MAX_STREAM_LEN - offset;
    }   
    uint32_t new_len = len + stream->len;
    if (new_len > MAX_STREAM_LEN) {
        new_len = MAX_STREAM_LEN;
    }
    if (!check_cache(stream->id, new_len)) {
        printf("[stream_insert_region] Get stream buffer failed!\n");
        exit(-1);
    }
    stream->data = cache_buffer[stream->id];
    #ifdef DEBUG_STREAM
    printf("length:%d before:",stream->len);
    for(int i=0;i<stream->len;i++){
        printf("%02x ",stream->data[i]);
    } 
    printf("\n");
    #endif 
    memmove(&(stream->data[offset+len]), &(stream->data[offset]), new_len - offset - len);
    memcpy(&(stream->data[offset]), buffer, len);
    stream->len = new_len;
    #ifdef DEBUG_STREAM
    printf("length:%d after:",stream->len);
    for(int i=0;i<stream->len;i++){
        printf("%02x ",stream->data[i]);
    } 
    printf("\n");
    #endif 
    return true;
};
bool stream_delete_region(uint64_t addr, uint32_t offset, uint32_t len, uint8_t* buffer) {
    if (unlikely(g_read_only)) {
        return false;
    }
    struct stream_mem* stream = get_stream_by_addr(addr);
    if (unlikely(!stream)) {
        return false;
    }
    if (offset > stream->len) {
        return false;
    }
    
    if (offset + len > MAX_STREAM_LEN){
        len = MAX_STREAM_LEN - offset;
    }   
    uint32_t new_len = stream->len - len;

    stream->data = cache_buffer[stream->id];
    memcpy(buffer, &(stream->data[offset]), len);
    memmove(&(stream->data[offset]), &(stream->data[offset+len]), new_len - offset - len);
    
    stream->len = new_len;
    return true;
};
bool stream_set_region(uint64_t addr, uint32_t offset, uint32_t len, uint8_t* buffer){
    if (unlikely(g_read_only)) {
        return false;
    }
    struct stream_mem* stream = get_stream_by_addr(addr);
    if (unlikely(!stream)) {
        return false;
    }
    if (offset > stream->len) {
        return false;
    }
    
    if (offset + len > MAX_STREAM_LEN){
        len = MAX_STREAM_LEN - offset;
    }

    stream->data = cache_buffer[stream->id];
    memcpy(&(stream->data[offset]), buffer, len);

    return true;    
};
bool stream_get_region(uint64_t addr, uint32_t offset, uint32_t len, uint8_t* buffer) {
    struct stream_mem* stream = get_stream_by_addr(addr);
    if (unlikely(!stream)) {
        return false;
    }
    if (offset > stream->len) {
        return false;
    }
    
    if (offset + len > MAX_STREAM_LEN){
        len = MAX_STREAM_LEN - offset;
    }

    stream->data = cache_buffer[stream->id];
    memcpy(buffer, &(stream->data[offset]), len);

    return true; 

};



/* don't free the buffer */
bool get_stream_input(uint64_t addr, uint8_t **buffer, uint32_t* len) {
    struct stream_mem* stream = get_stream_by_addr(addr);
    if (unlikely(!stream)) {
        *buffer = NULL;
        *len = 0;
        return false;
    }
    *buffer = stream->data;
    *len = stream->len;
    return true;
}


bool set_stream_input(uint64_t addr, uint8_t *buffer, uint32_t len) {
    struct stream_mem* stream = get_stream_by_addr(addr);
    if (unlikely(!stream)) {
        return false;
    }
    stream->data = buffer;
    stream->len = len;
    return true;
}
