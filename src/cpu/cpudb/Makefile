all: cpudb.a

cpudb.a: intel/corei5_arrandale_m520.o \
		intel/pentium.o \
		intel/pentium_mmx.o \
		intel/p2_klamath.o\
		intel/p3_katmai.o\
		intel/p4_willamette.o\
		intel/p4_prescott_celeron_336.o\
		intel/core_duo_t2400_yonah.o\
		intel/atom_n270.o\
		intel/core2_penryn_t9600.o\
		intel/corei5_lynnfield_750.o\
		amd/athlon64_clawhammer.o\
		amd/amd_k6_2_chomper.o\
		amd/athlon64_venice.o
	ar -crs $@ $^

%.o: %.cc
	g++ $(CFLAGS) -c $^ -o $@

