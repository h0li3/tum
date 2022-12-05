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
  struct memory_handler_struct **memory_handlers;
  bool pci_enabled;
  bool bios_write_enabled;
  bool smram_available;
  bool smram_enable;
  bool smram_restricted;

  Bit64u  len, allocated;  // could be > 4G
  Bit32u  block_size;      // individual block size, must be power of 2
  Bit8u   *actual_vector;
  Bit8u   *vector;   // aligned correctly
  Bit8u  **blocks;
  Bit8u   *bogus;    // 4k for unexisting memory
  bool    rom_present[65];
  bool    memory_type[13][2];

  Bit32u used_blocks;

public:
  BX_MEM_C();
 ~BX_MEM_C();

  void    init_memory(Bit64u guest, Bit64u host, Bit32u block_size);
  void    cleanup_memory(void);
  Bit8u*  get_vector(bx_phy_address addr);

  Bit8u*  getHostMemAddr(BX_CPU_C *cpu, bx_phy_address addr, unsigned rw);

  // Note: accesses should always be contained within a single page
  BX_MEM_SMF void    readPhysicalPage(BX_CPU_C *cpu, bx_phy_address addr,
                                      unsigned len, void *data);
  BX_MEM_SMF void    writePhysicalPage(BX_CPU_C *cpu, bx_phy_address addr,
                                       unsigned len, void *data);

  BX_MEM_SMF bool dbg_fetch_mem(BX_CPU_C *cpu, bx_phy_address addr, unsigned len, Bit8u *buf);
#if (BX_DEBUGGER || BX_GDBSTUB)
  BX_MEM_SMF bool dbg_set_mem(BX_CPU_C *cpu, bx_phy_address addr, unsigned len, Bit8u *buf);
  BX_MEM_SMF bool dbg_crc32(bx_phy_address addr1, bx_phy_address addr2, Bit32u *crc);
#endif

  BX_MEM_SMF Bit64u  get_memory_len(void);
  BX_MEM_SMF void allocate_block(Bit32u index);
  BX_MEM_SMF Bit8u* alloc_vector_aligned(Bit64u bytes, Bit64u alignment);
};

BOCHSAPI extern BX_MEM_C bx_mem;

BX_CPP_INLINE Bit64u BX_MEM_C::get_memory_len(void)
{
  return (BX_MEM_THIS len);
}

#endif
