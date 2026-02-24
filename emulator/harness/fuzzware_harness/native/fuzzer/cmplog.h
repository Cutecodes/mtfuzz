#ifndef AFL_QEMU_CMPLOG_H
#define AFL_QEMU_CMPLOG_H


// 4K - 64K
#define CMPLOG_AREA_W_MAX (1<<20)
#define CMPLOG_AREA_W_MIN (1<<10)


#define CMP_MAP_W 65536
#define CMP_MAP_H 32
#define CMP_MAP_RTN_H (CMP_MAP_H / 4)

#define SHAPE_BYTES(x) (x + 1)

#define CMP_TYPE_INS 1
#define CMP_TYPE_RTN 2

#define OP_TYPE_MASK 0b00001111
#define OP_TYPE_RESULT_MASK 0b11110000

enum op_type {
  OP_ISUB = 0,
  OP_IADD,
  OP_FCMP,
  OP_AND,
  OP_OR,
  OP_XOR,
  OP_END,
  OP_ICMP = OP_ISUB
};

enum op_type_result {
  OP_ICMP_E = 16,   // signed eq or neq
  OP_ICMP_L,        // signed less or less eq
  OP_ICMP_G,        // signed greater or greater eq
  OP_UICMP_E,       // unsigned eq or neq
  OP_UICMP_L,        // unsigned less or less eq
  OP_UICMP_G,        // unsigned greater or greater eq
};

struct cmp_header {

  unsigned hits : 24;
  unsigned id : 24;
  unsigned cnt : 24;
  unsigned shape : 5;
  unsigned type : 4;
  unsigned attribute : 8;
  unsigned overflow : 1;
  unsigned reserved : 6;

} __attribute__((packed));

struct cmp_operands {

  uint64_t v0;
  uint64_t v1;
  uint64_t v0_128;
  uint64_t v1_128;

} __attribute__((packed));

struct cmpfn_operands {

  uint8_t v0[31];
  uint8_t v0_len;
  uint8_t v1[31];
  uint8_t v1_len;

} __attribute__((packed));

extern struct cmp_header* cmp_headers;
extern struct cmp_operands* cmp_log;
extern unsigned long cmp_map_w;
extern unsigned long cmp_map_h;
extern unsigned long cmp_counter;
extern unsigned long cmp_shadow_hash;
extern unsigned long cmp_mode;


struct cmp_map {

  struct cmp_header   headers[CMP_MAP_W];
  struct cmp_operands log[CMP_MAP_W][CMP_MAP_H];

};


#endif
