#ifndef _HAVE_STREAM_H
#define _HAVE_STREAM_H
#include <stdint.h>
#include <stdbool.h>

#define MAX_MMIO_SIZE 65536
#define MAX_STREAM_SIZE (65536-3)
#define MAX_STREAM_LEN 0xA0000

#define STREAM_SHM_ENV_VAR         "__STREAM_SHM_ID"
//#define DEBUG_STREAM

//#define SMART_STREAM 1

#ifdef SMART_STREAM
#define FIFO_MAX_SZIE 8
typedef struct {
    uint64_t data[2 * FIFO_MAX_SZIE];
    int front;
    int rear;
    int count;
} CircularQueue;

void init_CircularQueue(CircularQueue* q);
bool enqueue_CircularQueue(CircularQueue* q, uint64_t val);
uint64_t* get_data__CircularQueue(CircularQueue* q, int *size);

extern CircularQueue last_read_mmio;
#endif

struct stream_status {
    uint64_t addr;
    uint16_t size;
    uint16_t new_stream;
} __attribute__((packed));


struct stream_feedback {
   struct stream_status status;
   uint32_t cursors[MAX_STREAM_SIZE];
} __attribute__((packed));


struct stream_mem {
   uint16_t id;        // stream id
   uint16_t size;      // the group read size of mmio? when merge? 
   uint32_t len;       // len of stream
   uint8_t *data;      // the data of stream;
} __attribute__((packed));

struct stream_file {
   uint16_t size;      // the group read size of mmio? when merge?
   uint32_t len;       // the length of stream
} __attribute__((packed));

struct mmio2stream {
   uint64_t mmio_addr; // the address of mmio
   uint16_t size;      // the mmio read size
   uint16_t stream_id; // the id of stream
} __attribute__((packed));

/* file format */
/*
struct file {
   uint16_t len_mmio;
   uint16_t len_stream;
   struct mmio2stream m2s[len_mmio];
   struct stream_file stream[len_stream];
}
*/


uint16_t get_num_mmio();
uint16_t get_num_stream();
struct mmio2stream* get_mmios();
struct stream_mem* get_streams();
// init stream view of file content
// return false if could't parse it
bool init_streams(uint8_t* buffer, uint32_t len, bool read_only);
bool destory_streams();
uint8_t* get_file(uint32_t* len);

bool insert_stream(uint64_t addr, uint16_t size);
struct stream_mem* stream_extend(uint64_t addr, uint8_t* buffer, uint32_t len);

uint16_t merge_stream_by_id(uint16_t id1, uint16_t id2);

struct stream_mem* get_stream_by_addr(uint64_t addr);
bool stream_insert_region(uint64_t addr, uint32_t offset, uint32_t len, uint8_t* buffer);
bool stream_delete_region(uint64_t addr, uint32_t offset, uint32_t len, uint8_t* buffer);
bool stream_set_region(uint64_t addr, uint32_t offset, uint32_t len, uint8_t* buffer);
bool stream_get_region(uint64_t addr, uint32_t offset, uint32_t len, uint8_t* buffer);

bool get_stream_input(uint64_t addr, uint8_t **buffer, uint32_t* len);
bool set_stream_input(uint64_t addr, uint8_t *buffer, uint32_t len);

#endif /* ! _HAVE_STREAM_H */
