#include "stream.h"

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


struct streams_input g_stream_input;
struct streams_input g_stream_input2;

static uint8_t* g_file_buffer = NULL;
static uint32_t g_file_buffer_size = 0;

uint16_t get_num_mmio(struct streams_input* input){
    if(unlikely(!input)){
        return 0;
    }
    return input->num_mmio;
};

uint16_t get_num_stream(struct streams_input* input){
    if(unlikely(!input)){
        return 0;
    }
    return input->num_stream;    
};
khash_t(PTR) *get_mmios(struct streams_input* input){
    if(unlikely(!input)){
        return NULL;
    }
    return input->kh_mmios;
};

khash_t(PTR) *get_streams(struct streams_input* input){
    if(unlikely(!input)){
        return NULL;
    }
    return input->kh_streams;    
};

bool destory_streams_input(struct streams_input* input){
    if(unlikely(!input)) {
        return false;
    }

    khiter_t k;

    #ifdef DEBUG_STREAM
    printf("[%s] destory input at:%016x, num mmios: %d, num streams:%d, read only:%d\n",__func__, input, input->num_mmio, input->num_stream, input->read_only);
    #endif

    if (input->kh_mmios) {
        if (!input->read_only){
            for (k = kh_begin(input->kh_mmios); k != kh_end(input->kh_mmios); ++k){
		        if (kh_exist(input->kh_mmios, k)) {
                    struct mmio* mmio = kh_value(input->kh_mmios, k);
                    #ifdef DEBUG_STREAM
                    printf("[%s] free mmio at:%016x, mmio addr: %016lx, size:%d, stream id:%d\n",__func__, mmio, mmio->mmio_addr, mmio->size, mmio->stream_id);
                    #endif
                    free(mmio);   
                }
            }
        }
        kh_destroy(PTR, input->kh_mmios);
    }
    
    if (input->kh_streams) {
        if (!input->read_only) {

            for (k = kh_begin(input->kh_streams); k != kh_end(input->kh_streams); ++k){
		        if (kh_exist(input->kh_streams, k)) {
                    struct stream* stream = kh_value(input->kh_streams, k);
                    #ifdef DEBUG_STREAM
                    printf("[%s] free stream at:%016x, stream id: %d, len:%d\n",__func__, stream, stream->id, stream->len);
                    #endif
                    if (stream->data) {
                        #ifdef DEBUG_STREAM
                        printf("data: ");
                        for(int i=0;i<stream->len;i++){
                            printf("%02x ",stream->data[i]);
                        } 
                        printf("\n");
                        #endif
                        free(stream->data);
                    }
                    free(stream);
                }
            }
        }
        kh_destroy(PTR, input->kh_streams);
    }
    if (!input->read_only) {
        if (input->buffer) {
            free(input->buffer);
        }
    }

    input->num_mmio = 0;
    input->num_stream = 0;
    input->read_only = 1;
    input->kh_mmios = NULL;
    input->kh_streams = NULL;
    input->buffer = NULL;
    input->buffer_len = 0;
    return true;
};

bool init_streams_input(struct streams_input* input, uint8_t* buffer, uint32_t len, bool read_only) {
    if (unlikely(!input) || unlikely(!buffer)) {
        return false;
    }
    // the input must be destoryed before, or it will memory leak
    destory_streams_input(input);
    
    input->num_mmio = 0;
    input->num_stream = 0;
    input->read_only = read_only;
    input->kh_mmios = kh_init(PTR);
    input->kh_streams = kh_init(PTR);
    input->buffer = NULL;
    input->buffer_len = 0;

    if (len < 8) {
        #ifdef DEBUG_STREAM
        printf("[%s] build stream failed!!! file length is %d\n",__func__, len);
        #endif
        return false;
    };

    uint32_t flag = *(uint32_t*)buffer;
    if (flag != FLAGS) {
        #ifdef DEBUG_STREAM
        printf("[%s] build stream failed!!! flag is %08x\n",__func__, flag);
        #endif
        return false;
    }

    uint16_t num_mmio = *(uint16_t*)(buffer+4);
    uint16_t num_stream = *(uint16_t*)(buffer+6);

    uint32_t len_header = 8 + num_mmio * sizeof(struct mmio) + num_stream * sizeof(struct stream);
    if (len < len_header) {
        #ifdef DEBUG_STREAM
        printf("[%s] build stream failed!!! num mmio: %d, num stream: %d, length of file header:%d, file length:%d\n",__func__, num_mmio, num_stream, len_header, len);
        #endif
        return false;
    }

    struct mmio* mmios = (struct mmio*)&buffer[8];
    struct stream* streams = (struct stream*)&buffer[8 + num_mmio*sizeof(struct mmio)];
    uint32_t len_data = 0;
    for(int i=0;i<num_stream;i++){
        #ifdef DEBUG_STREAM
        printf("[%s] stream id: %d, stream length: %d\n", __func__, streams[i].id, streams[i].len);
        #endif
        len_data += streams[i].len;
    }
    if (len < len_header + len_data) {
        #ifdef DEBUG_STREAM
        printf("[%s] build stream failed!!! num mmio: %d, num stream: %d, length of file header:%d, length of stream_data:%d, file length:%d\n",__func__,num_mmio,num_stream,len_header,len_data, len);
        #endif
        return false;
    }
    
    input->num_mmio = num_mmio;
    input->num_stream = num_stream;
    
    if (read_only) {
        input->buffer = buffer;
        input->buffer_len = len;
    }
    
    int kh_res;

    for (int i=0;i<num_mmio;i++){
        #ifdef DEBUG_STREAM
        printf("[%s] mmio addr: %016lx, size:%d, stream id:%d\n",__func__, mmios[i].mmio_addr, mmios[i].size, mmios[i].stream_id);
        #endif
        struct mmio* new_mmio = NULL;
        if (read_only) {
            new_mmio = &mmios[i];
        }else {
            new_mmio = malloc(sizeof(struct mmio));
            if (unlikely(!new_mmio)){
                printf("malloc mmio failed!\n");
                exit(-1);
            }
            memcpy(new_mmio, &mmios[i], sizeof(struct mmio));
        }
        if(kh_get(PTR, input->kh_mmios, mmios[i].mmio_addr) == kh_end(input->kh_mmios)) {
            khiter_t k = kh_put(PTR, input->kh_mmios, mmios[i].mmio_addr, &kh_res);
            kh_value(input->kh_mmios, k) = new_mmio;
        }
    }

    for (int i=0;i<num_stream;i++) {
        struct stream* new_stream = NULL;
        if (read_only) {
            // offset when in file
            streams[i].data = &buffer[(uint64_t)streams[i].data];
            new_stream = &streams[i];
        }else{
            new_stream = malloc(sizeof(struct stream));
            if (unlikely(!new_stream)){
                printf("malloc stream failed!\n");
                exit(-1);
            }
            memcpy(new_stream, &streams[i], sizeof(struct stream));
            new_stream->data = malloc(MAX_STREAM_LEN);
            if (unlikely(!new_stream->data)){
                printf("malloc stream buffer failed!\n");
                exit(-1);
            }
            memcpy(new_stream->data, &buffer[(uint64_t)streams[i].data], new_stream->len);
        }
        
        if(kh_get(PTR, input->kh_streams, new_stream->id) == kh_end(input->kh_streams)) {
            khiter_t k = kh_put(PTR, input->kh_streams, new_stream->id, &kh_res);
            kh_value(input->kh_streams, k) = new_stream;
        }
        
        #ifdef DEBUG_STREAM
        printf("stream id: %d \n",new_stream->id);
        for(int j=0;j<new_stream->len;j++){
            printf("%02x ",new_stream->data[j]);
        } 
        printf("\n");
        #endif
    }
    #ifdef DEBUG_STREAM
    printf("[%s] build stream successfully!!! num mmio: %d, num stream: %d, length of file header:%d, length of stream_data:%d, file length:%d\n", __func__,num_mmio,num_stream,len_header,len_data, len);
    #endif
    return true;
};

// it will reused and not free the memory, use flag valid.
bool reset_streams_input(struct streams_input* input, uint8_t* buffer, uint32_t len) {
    if (!input || input->read_only || !input->kh_mmios || !input->kh_streams) {
        return false;
    }

    khiter_t k;
    for (k = kh_begin(input->kh_mmios); k != kh_end(input->kh_mmios); ++k){
        if (kh_exist(input->kh_mmios, k)) {
            struct mmio* mmio = kh_value(input->kh_mmios, k);
            #ifdef DEBUG_STREAM
            printf("[%s] reset mmio at:%016x, mmio addr: %016lx, size:%d, stream id:%d\n",__func__, mmio, mmio->mmio_addr, mmio->size, mmio->stream_id);
            #endif
            mmio->valid = false;
        }
    }
		
    
    for (k = kh_begin(input->kh_streams); k != kh_end(input->kh_streams); ++k) {
        if (kh_exist(input->kh_streams, k)) {
            struct stream* stream = kh_value(input->kh_streams, k);
            #ifdef DEBUG_STREAM
            printf("[%s] reset stream at:%016x, stream id: %d, len:%d\n",__func__, stream, stream->id, stream->len);
            #endif
            stream->rc = 0;
            stream->len = 0;
        }
    }
		

    if (!buffer || len < 8) {
        #ifdef DEBUG_STREAM
        printf("[%s] build stream failed!!! file length is %d\n",__func__,len);
        #endif
        return false;
    };

    uint32_t flag = *(uint32_t*)buffer;
    if (flag != FLAGS) {
        #ifdef DEBUG_STREAM
        printf("[%s] build stream failed!!! flag is %08x\n",__func__, flag);
        #endif
        return false;
    }

    uint16_t num_mmio = *(uint16_t*)(buffer+4);
    uint16_t num_stream = *(uint16_t*)(buffer+6);
    

    uint32_t len_header = 8 + num_mmio * sizeof(struct mmio) + num_stream * sizeof(struct stream);
    if (len < len_header) {
        #ifdef DEBUG_STREAM
        printf("[%s] build stream failed!!! num mmio: %d, num stream: %d, length of file header:%d, file length:%d\n",__func__, num_mmio, num_stream, len_header, len);
        #endif
        return false;
    }

    struct mmio* mmios = (struct mmio*)&buffer[8];
    struct stream* streams = (struct stream*)&buffer[8 + num_mmio*sizeof(struct mmio)];
    uint32_t len_data = 0;
    for(int i=0;i<num_stream;i++){
        #ifdef DEBUG_STREAM
        printf("[%s] stream id: %d, stream length: %d\n",__func__, streams[i].id, streams[i].len);
        #endif
        len_data += streams[i].len;
    }

    if (len < len_header + len_data) {
        #ifdef DEBUG_STREAM
        printf("[%s] build stream failed!!! num mmio: %d, num stream: %d, length of file header:%d, length of stream_data:%d, file length:%d\n",__func__,num_mmio,num_stream,len_header,len_data, len);
        #endif
        return false;
    }
    
    input->num_mmio = num_mmio;
    input->num_stream = num_stream;

    for (int i=0;i<num_mmio;i++){
        #ifdef DEBUG_STREAM
        printf("[%s] mmio addr: %016lx, size:%d, stream id:%d\n",__func__,mmios[i].mmio_addr, mmios[i].size, mmios[i].stream_id);
        #endif
        khiter_t k = kh_get(PTR, input->kh_mmios, mmios[i].mmio_addr);
        if(k != kh_end(input->kh_mmios)) {
            if (kh_exist(input->kh_mmios, k)) {
                struct mmio* mmio = kh_value(input->kh_mmios, k);
                mmio->valid = true;
            }
        }
    }
    
    
    for (int i=0;i<num_stream;i++) {
        khiter_t k = kh_get(PTR, input->kh_streams,streams[i].id);
        if(k != kh_end(input->kh_streams)) {
            if (kh_exist(input->kh_streams, k)) {
                struct stream* stream = kh_value(input->kh_streams, k);
                stream->rc = streams[i].rc;
                stream->len = streams[i].len;
            }
        }
        
    }
    #ifdef DEBUG_STREAM
    printf("[%s] build stream successfully!!! num mmio: %d, num stream: %d, length of file header:%d, length of stream_data:%d, file length:%d\n",__func__,num_mmio,num_stream,len_header,len_data, len);
    #endif
    return true;
};


bool get_streams_input_file(struct streams_input* input, uint8_t** buffer, uint32_t* len) {
    if(!input) {
        return false;
    }

    if (input->read_only) {
        *buffer = input->buffer;
        *len = input->buffer_len;
        return true;
    }

    uint16_t num_mmio = 0;
    uint16_t num_stream = 0;
    uint32_t len_data = 0;

    khiter_t k;
    
    if (input->kh_mmios) {
        for (k = kh_begin(input->kh_mmios); k != kh_end(input->kh_mmios); ++k){
            if (kh_exist(input->kh_mmios, k)) {
                struct mmio* mmio= kh_value(input->kh_mmios, k);
                if (mmio->valid) {
                    #ifdef DEBUG_STREAM
                    printf("[%s] mmio addr: %016lx, size:%d, stream id:%d\n",__func__,mmio->mmio_addr, mmio->size, mmio->stream_id);
                    #endif
                    num_mmio++;
                }
            }
        }
    }
    
    if (input->kh_streams) {
        for (k = kh_begin(input->kh_streams); k != kh_end(input->kh_streams); ++k){
            if (kh_exist(input->kh_streams, k)) {
                struct stream* stream= kh_value(input->kh_streams, k);
                if (stream->rc) {
                    #ifdef DEBUG_STREAM
                    printf("[%s] stream id: %d, stream length: %d\n",__func__, stream->id, stream->len);
                    #endif
                    num_stream++;
                    len_data += stream->len;
                }
            }
        }
    }
    
    uint32_t len_header = 8 + num_mmio * sizeof(struct mmio) + num_stream * sizeof(struct stream);
    uint32_t len_file = len_data + len_header;

    

    *len = len_file;
    

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
    *buffer = g_file_buffer;

    #ifdef DEBUG_STREAM
    printf("[%s] num mmio: %d, num stream: %d, length of file header:%d, length of stream_data:%d, file length:%d\n",__func__,num_mmio,num_stream,len_header,len_data, *len);
    #endif

    *(uint32_t*)g_file_buffer = FLAGS;
    *(uint16_t*)(g_file_buffer+4) = num_mmio;
    *(uint16_t*)(g_file_buffer+6) = num_stream;
    struct mmio* mmios = (struct mmio*)&g_file_buffer[8];
    struct stream* streams = (struct stream*)&g_file_buffer[8 + num_mmio * sizeof(struct mmio)];

    len_data = 0;
    num_mmio = 0;
    num_stream = 0;
    if (input->kh_mmios) {
        for (k = kh_begin(input->kh_mmios); k != kh_end(input->kh_mmios); ++k){
            if (kh_exist(input->kh_mmios, k)) {
                struct mmio* mmio= kh_value(input->kh_mmios, k);
                if (mmio->valid) {
                    #ifdef DEBUG_STREAM
                    printf("[%s] mmio addr: %016lx, size:%d, stream id:%d\n",__func__,mmio->mmio_addr, mmio->size, mmio->stream_id);
                    #endif
                    memcpy(&mmios[num_mmio], mmio, sizeof(struct mmio));
                    num_mmio++;
                }
            }
        }
    }

    if (input->kh_streams) {
        for (k = kh_begin(input->kh_streams); k != kh_end(input->kh_streams); ++k){
            if (kh_exist(input->kh_streams, k)) {
                struct stream* stream= kh_value(input->kh_streams, k);
                if (stream->rc) {
                    memcpy(&streams[num_stream], stream, sizeof(struct stream));
                    streams[num_stream].data = (uint8_t*)(len_header + len_data);
                    memcpy(g_file_buffer+len_header + len_data, stream->data, stream->len);
                    #ifdef DEBUG_STREAM
                    printf("[%s] stream id: %d, stream length: %d data offset:% d\n",__func__, stream->id, stream->len, len_header + len_data);
                    #endif
                    num_stream++;
                    len_data += stream->len;

                }
            }
        }
    }

    #ifdef DEBUG_STREAM
    for(int i=0;i<*len;i++){
        printf("%02x ",g_file_buffer[i]);
    } 
    printf("\n");
    #endif  
    return true;       
};




static uint32_t insert_stream(struct streams_input* input) {
    if (!input || !input->kh_streams) {
        return 0;
    }
    struct stream* new_stream = malloc(sizeof(struct stream));
    if (unlikely(!new_stream)) {
        printf("[insert_stream] malloc failed!\n");
        exit(-1);
    }
    memset(new_stream, 0 ,sizeof(struct stream));
    
    int kh_res;
    while(true) {
        uint32_t id = random()%MAX_STREAM_SIZE;
        khiter_t k = kh_get(PTR, input->kh_streams, id);
        if (id != 0 && k == kh_end(input->kh_streams)) {
            k = kh_put(PTR, input->kh_streams, id, &kh_res);
            new_stream->id = id;
            new_stream->rc = 1;
            new_stream->data = malloc(MAX_STREAM_LEN);
            if (unlikely(!new_stream->data)){
                printf("malloc stream buffer failed!\n");
                exit(-1);
            }
            kh_value(input->kh_streams, k) = new_stream;
            input->num_stream++;
            return id;
        }
    }
};


struct stream* get_stream_by_addr(struct streams_input* input, uint64_t addr) {
    if (!input || !input->kh_mmios || !input->kh_streams) {
        return NULL;
    }
    khiter_t k = kh_get(PTR, input->kh_mmios, addr);
    if( k != kh_end(input->kh_mmios)) {
        if(kh_exist(input->kh_mmios, k)) {
            struct mmio* mmio = kh_value(input->kh_mmios, k);
            k = kh_get(PTR, input->kh_streams, mmio->stream_id);
            if (k != kh_end(input->kh_streams)){
                if(kh_exist(input->kh_streams, k)) {
                    return kh_value(input->kh_streams, k);
                }
            }
        }
    }
    return NULL;
};

struct mmio* get_mmio_by_addr(struct streams_input* input, uint64_t addr) {
    if (!input || !input->kh_mmios) {
        return NULL;
    }

    khiter_t k = kh_get(PTR, input->kh_mmios, addr);
    if( k != kh_end(input->kh_mmios)) {
        if(kh_exist(input->kh_mmios, k)) {
            return kh_value(input->kh_mmios, k);
        }
    }
    return NULL;
};

/* insert a new mmio, when stream_id == 0 it'll also create a new stream. */
bool insert_mmio(struct streams_input* input, uint64_t addr, uint16_t size, uint32_t stream_id){
    if (!input || !input->kh_mmios || !input->kh_streams) {
        return false;
    }

    khiter_t k;
    int kh_res;
    struct mmio* new_mmio = get_mmio_by_addr(input, addr);

    if (new_mmio) {
        if (new_mmio->valid) {
            return true;
        }else{
            new_mmio->valid = true;
            input->num_mmio++;
            uint32_t old_stream_id = new_mmio->stream_id;
            uint32_t new_stream_id = 0;
            k = kh_get(PTR, input->kh_streams, old_stream_id);
            struct stream* old_stream = NULL;
            if (k != kh_end(input->kh_streams)) {
                if(kh_exist(input->kh_streams, k)) {
                    old_stream = kh_value(input->kh_streams, k);
                }
            }
            
            if (stream_id ==0) {
                if (old_stream && old_stream->rc == 0){
                    old_stream->rc++;
                    input->num_stream++;
                    return true;
                }else{
                    new_stream_id = insert_stream(input);
                    new_mmio->stream_id = new_stream_id;
                    return true;
                }
            }else{
                if (stream_id == old_stream_id) {
                    if (old_stream) {
                        if (old_stream->rc == 0) input->num_stream++;
                        old_stream->rc++;
                    }
                    return true;
                }else{
                    k = kh_get(PTR, input->kh_streams, stream_id);
                    struct stream* new_stream = NULL;
                    if (k != kh_end(input->kh_streams)) {
                        if(kh_exist(input->kh_streams, k)) {
                            new_stream = kh_value(input->kh_streams, k);
                        }
                    }
                    if (new_stream){
                        new_mmio->stream_id = stream_id;
                        if (new_stream->rc == 0) input->num_stream++;
                        new_stream->rc++;
                        return true;
                    }else{
                        printf("couldn't find stream id:%d\n",stream_id);
                        return false;
                    }
                }
            } 
        }
    }else{
        // not found
        new_mmio = malloc(sizeof(struct mmio));
        if (unlikely(!new_mmio)) {
            printf("[%s] malloc failed!\n",__func__);
            exit(-1);
        }
        new_mmio->valid = true;
        new_mmio->mmio_addr = addr;
        new_mmio->size = size;
        if (stream_id == 0) {
            new_mmio->stream_id = insert_stream(input);
        }else {
            k = kh_get(PTR, input->kh_streams, stream_id);
            struct stream* new_stream = NULL;
            if (k != kh_end(input->kh_streams)) {
                if (kh_exist(input->kh_streams, k)){
                    new_stream = kh_value(input->kh_streams, k);
                }
            }
            if (new_stream){
                new_mmio->stream_id = stream_id;
                if (new_stream->rc == 0) input->num_stream++;
                new_stream->rc++;
            }else{
                printf("couldn't find stream id:%d\n",stream_id);
                free(new_mmio);
                return false;
            }
        }

        k = kh_get(PTR, input->kh_mmios, addr);
        if (likely(k == kh_end(input->kh_mmios))) {
            k = kh_put(PTR, input->kh_mmios, addr, &kh_res);
            kh_value(input->kh_mmios, k) = new_mmio;
            input->num_mmio++;
            return true;
        }else{
            // never get here.
            printf("mmio already exist.\n");
            free(new_mmio);
            return false;
        }
    }

};




bool stream_insert_region(struct streams_input* input, uint64_t addr, uint32_t offset, uint32_t len, uint8_t* buffer) {
    if (unlikely(input->read_only)) {
        return false;
    }

    struct stream* stream = get_stream_by_addr(input, addr);
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


bool stream_delete_region(struct streams_input* input, uint64_t addr, uint32_t offset, uint32_t len, uint8_t* buffer) {
    if (unlikely(input->read_only)) {
        return false;
    }
    struct stream* stream = get_stream_by_addr(input, addr);
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

    memcpy(buffer, &(stream->data[offset]), len);
    memmove(&(stream->data[offset]), &(stream->data[offset+len]), stream->len - offset - len);
    
    stream->len = new_len;
    return true;
};


bool stream_set_region(struct streams_input* input, uint64_t addr, uint32_t offset, uint32_t len, uint8_t* buffer){
    if (unlikely(input->read_only)) {
        return false;
    }
    struct stream* stream = get_stream_by_addr(input, addr);
    if (unlikely(!stream)) {
        return false;
    }
    if (offset > stream->len) {
        return false;
    }
    
    if (offset + len > MAX_STREAM_LEN){
        len = MAX_STREAM_LEN - offset;
    }

    memcpy(&(stream->data[offset]), buffer, len);
    return true;    
};

bool stream_get_region(struct streams_input* input, uint64_t addr, uint32_t offset, uint32_t len, uint8_t* buffer) {
    struct stream* stream = get_stream_by_addr(input, addr);
    if (unlikely(!stream)) {
        return false;
    }
    if (offset > stream->len) {
        return false;
    }
    
    if (offset + len > MAX_STREAM_LEN){
        len = MAX_STREAM_LEN - offset;
    }

    memcpy(buffer, &(stream->data[offset]), len);

    return true; 

};

/* don't free the buffer if you want to restore it after */
bool get_stream_input(struct streams_input* input, uint64_t addr, uint8_t **buffer, uint32_t* len) {
    struct stream* stream = get_stream_by_addr(input, addr);
    if (unlikely(!stream)) {
        *buffer = NULL;
        *len = 0;
        return false;
    }
    *buffer = stream->data;
    *len = stream->len;
    return true;
}

/* we don't free old buffer, please save and restore it */
bool set_stream_input(struct streams_input* input, uint64_t addr, uint8_t *buffer, uint32_t len) {
    struct stream* stream = get_stream_by_addr(input, addr);
    if (unlikely(!stream)) {
        return false;
    }
    stream->data = buffer;
    stream->len = len;
    return true;
}
