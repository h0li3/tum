#break BX_CPU_C::prefetch
#break BX_CPU_C::serveICacheMiss
#break fetchDecode64
break main
break BX_CPU_C::MOV_RAXOq
break BX_CPU_C::translate_linear_long_mode
#break BX_CPU_C::translate_linear
#break BX_CPU_C::getHostMemAddr
#break BX_MEM_C::getHostMemAddr

r

set pagination on
