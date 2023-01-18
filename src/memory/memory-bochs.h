#ifndef BX_MEM_H
#  define BX_MEM_H 1

class BX_CPU_C;

class BOCHSAPI BX_MEM_C : public logfunctions {
private:
  Bit64u  len, allocated;  // could be > 4G
  Bit32u  block_size;      // individual block size, must be power of 2
  Bit8u   *actual_vector;
  Bit8u   *vector;   // aligned correctly
  Bit8u  **blocks;
  Bit8u   *bogus;    // 4k for unexisting memory

  Bit32u used_blocks;

public:
  BX_MEM_C();
 ~BX_MEM_C();

  void       init_memory(BX_CPU_C *cpu);
  void       cleanup_memory(void);
  Bit8u*     get_host_address(BX_CPU_C *cpu, bx_phy_address addr, unsigned rw);
  bx_address allocate_host_memory(bx_address addr, unsigned len);
  bool       query_host_memory(bx_address addr);

  // Note: accesses should always be contained within a single page
  void read_physical_page(BX_CPU_C *cpu, bx_phy_address addr, unsigned len, void *data);
  void write_physical_page(BX_CPU_C *cpu, bx_phy_address addr, unsigned len, void *data);

  bx_address allocate_physical_page(bx_address addr, unsigned rw);
  bx_address allocate_physical_pages(bx_address addr, Bit32u npages, unsigned rw);

  bool dbg_fetch_mem(BX_CPU_C *cpu, bx_phy_address addr, unsigned len, Bit8u *buf);
};

BOCHSAPI extern BX_MEM_C bx_mem;

#endif
