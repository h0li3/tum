#ifndef BX_MEM_H
#  define BX_MEM_H 1

#if BX_USE_MEM_SMF
// if static member functions on, then there is only one memory
#  define BX_MEM_SMF  static
#  define BX_MEM_THIS BX_MEM(0)->
#else
#  define BX_MEM_SMF
#  define BX_MEM_THIS this->
#endif

class BX_CPU_C;

#define BIOS_MAP_LAST128K(addr) (((addr) | 0xfff00000) & BIOS_MASK)

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

  void    init_memory(Bit64u guest, Bit64u host, Bit32u block_size);
  void    cleanup_memory(void);
  Bit8u*  get_vector(bx_phy_address addr);

  Bit8u*  getHostMemAddr(BX_CPU_C *cpu, bx_phy_address addr, unsigned rw);

  // Note: accesses should always be contained within a single page
  void    readPhysicalPage(BX_CPU_C *cpu, bx_phy_address addr,
                                      unsigned len, void *data);
  void    writePhysicalPage(BX_CPU_C *cpu, bx_phy_address addr,
                                       unsigned len, void *data);

  bool dbg_fetch_mem(BX_CPU_C *cpu, bx_phy_address addr, unsigned len, Bit8u *buf);
#if (BX_DEBUGGER || BX_GDBSTUB)
  bool dbg_set_mem(BX_CPU_C *cpu, bx_phy_address addr, unsigned len, Bit8u *buf);
  bool dbg_crc32(bx_phy_address addr1, bx_phy_address addr2, Bit32u *crc);
#endif

  Bit64u  get_memory_len(void);
  void allocate_block(Bit32u index);
  Bit8u* alloc_vector_aligned(Bit64u bytes, Bit64u alignment);
};

BOCHSAPI extern BX_MEM_C bx_mem;

BX_CPP_INLINE Bit64u BX_MEM_C::get_memory_len(void)
{
  return (BX_MEM_THIS len);
}

#endif
