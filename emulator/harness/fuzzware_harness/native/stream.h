#ifndef _HAVE_STREAM_H
#define _HAVE_STREAM_H
#include <stdint.h>
#include <stdbool.h>
#include "khash.h"

#define MAX_MMIO_SIZE 65536
#define MAX_STREAM_SIZE (65536-3)
#define MAX_STREAM_LEN 0xA0000

#define STREAM_SHM_ENV_VAR         "__STREAM_SHM_ID"
#define FLAGS          0x66757a7a  // "fuzz"
//#define DEBUG_STREAM

#define SMART_STREAM 1

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

KHASH_MAP_INIT_INT64(PTR, void*);

struct stream_status {
    uint64_t addr;
    uint32_t size;
    uint32_t new_stream;
} __attribute__((packed));


struct stream_feedback {
   struct stream_status status;
   uint32_t cursors[MAX_STREAM_SIZE];
} __attribute__((packed));


struct stream {
   uint32_t id;        // stream id 
   uint32_t len;       // len of stream
   uint8_t *data;      // the data of stream, offset when in file
   uint32_t rc;         // the reference of the stream
} __attribute__((packed));


struct mmio {
   uint64_t mmio_addr; // the address of mmio
   uint32_t size;      // the mmio read size
   uint32_t stream_id; // the id of stream
   uint8_t valid;      // the data is valid, when save and extend
} __attribute__((packed));

struct streams_input {
   uint16_t num_mmio;
   uint16_t num_stream;
   bool     read_only;
   khash_t(PTR) *kh_mmios;
   khash_t(PTR) *kh_streams;
   uint8_t* buffer;
   uint32_t buffer_len;
};

/* file format */
/*
struct file {
   uint32_t flags;
   uint16_t num_mmio;
   uint16_t num_stream;
   struct mmio mmios[num_mmio];
   struct stream streams[num_stream];
}
*/
extern struct streams_input g_stream_input;
extern struct streams_input g_stream_input2;

uint16_t get_num_mmio(struct streams_input*);
uint16_t get_num_stream(struct streams_input*);
khash_t(PTR) *get_mmios(struct streams_input*);
khash_t(PTR) *get_streams(struct streams_input*);

// init stream view of file content
// return false if could't parse it
bool destory_streams_input(struct streams_input*);
bool init_streams_input(struct streams_input*, uint8_t* buffer, uint32_t len, bool read_only);
bool reset_streams_input(struct streams_input*, uint8_t* buffer, uint32_t len); // it will reused and not free the memory, use flag valid.
bool get_streams_input_file(struct streams_input*, uint8_t** buffer, uint32_t* len);

bool insert_mmio(struct streams_input*, uint64_t addr, uint16_t size, uint32_t stream_id);
bool stream_extend(struct streams_input*, uint64_t addr, uint8_t* buffer, uint32_t len);


struct stream* get_stream_by_addr(struct streams_input*, uint64_t addr);
struct mmio* get_mmio_by_addr(struct streams_input* input, uint64_t addr);
bool stream_insert_region(struct streams_input*, uint64_t addr, uint32_t offset, uint32_t len, uint8_t* buffer);
bool stream_delete_region(struct streams_input*, uint64_t addr, uint32_t offset, uint32_t len, uint8_t* buffer);
bool stream_set_region(struct streams_input*, uint64_t addr, uint32_t offset, uint32_t len, uint8_t* buffer);
bool stream_get_region(struct streams_input*, uint64_t addr, uint32_t offset, uint32_t len, uint8_t* buffer);

bool get_stream_input(struct streams_input*, uint64_t addr, uint8_t **buffer, uint32_t* len);
bool set_stream_input(struct streams_input*, uint64_t addr, uint8_t *buffer, uint32_t len);

#endif /* ! _HAVE_STREAM_H */
