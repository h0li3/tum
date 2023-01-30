#ifndef BX_MEM_H
#  define BX_MEM_H 1

class BX_CPU_C;

class BOCHSAPI BX_MEM_C : public logfunctions {
private:
    bx_address page_table_base;

public:
    BX_MEM_C();
    ~BX_MEM_C();

    bx_address get_page_table() const;
    void       init_memory();
    void       cleanup_memory(void);
    bx_address allocate_stack(Bit32u len);
    void       free_stack(bx_address addr, Bit32u len);

    Bit8u* get_host_address(BX_CPU_C* cpu, bx_phy_address addr, unsigned rw);
    bx_address allocate_host_memory(bx_address addr, unsigned len, unsigned rw);
    void       free_host_memory(bx_address addr, unsigned len);
    bool       query_host_memory(bx_address addr);

    // Note: accesses should always be contained within a single page
    void read_physical_page(BX_CPU_C* cpu, bx_phy_address addr, unsigned len, void* data);
    void write_physical_page(BX_CPU_C* cpu, bx_phy_address addr, unsigned len, void* data);

    bx_address allocate_physical_page(bx_address addr, unsigned rw);
    bx_address allocate_physical_pages(bx_address addr, Bit32u npages, unsigned rw);
    void       free_physical_page(bx_address addr);
    void       free_physical_pages(bx_address addr, Bit32u npages);

    bool dbg_fetch_mem(BX_CPU_C* cpu, bx_phy_address addr, unsigned len, Bit8u* buf);
};

BOCHSAPI extern BX_MEM_C bx_mem;

#endif
