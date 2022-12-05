/////////////////////////////////////////////////////////////////////////
// $Id$
/////////////////////////////////////////////////////////////////////////
//
//  Copyright (C) 2001-2021  The Bochs Project
//
//  This library is free software; you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public
//  License as published by the Free Software Foundation; either
//  version 2 of the License, or (at your option) any later version.
//
//  This library is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
//
/////////////////////////////////////////////////////////////////////////

#ifndef BX_SIM_INTERFACE_H
#define BX_SIM_INTERFACE_H

//
// Intro to siminterface by Bryce Denney:
//
// Before I can describe what this file is for, I have to make the
// distinction between a configuration interface (CI) and the VGA display
// window (VGAW).  I will try to avoid the term 'GUI' because it is unclear
// if that means CI or VGAW, and because not all interfaces are graphical
// anyway.
//
// The traditional Bochs screen is a window with a large VGA display panel and
// a series of buttons (floppy, cdrom, snapshot, power).  Over the years, we
// have collected many implementations of the VGAW for different environments
// and platforms; each implementation is in a separate file under gui/*:
// x.cc, win32.cc, macintosh.cc, etc.  The files gui.h and gui.cc
// define the platform independent part of the VGAW, leaving about 15 methods
// of the bx_gui_c class undefined.  The platform dependent file must
// implement the remaining 15 methods.
//
// The configuration interface is relatively new, started by Bryce Denney in
// June 2001.  The CI is intended to allow the user to edit a variety of
// configuration and runtime options.  Some options, such as memory size or
// enabling the ethernet card, should only be changed before the simulation
// begins; others, such as floppy disk image, instructions per second, and
// logging options can be safely changed at runtime.  The CI allows the user to
// make these changes.  Before the CI existed, only a few things could be
// changed at runtime, all linked to clicking on the VGAW buttons.
//
// At the time that the CI was conceived, we were still debating what form the
// user interface part would take: stdin/stdout menus, a graphical application
// with menus and dialogs running in a separate thread, or even a tiny web
// server that you can connect to with a web browser.  As a result the
// interface to the CI was designed so that the user interface of the CI
// could be replaced easily at compile time, or maybe even at runtime via
// a plugin architecture.  To this end, we kept a clear separation between
// the user interface code and the siminterface, the code that interfaces with
// the simulator.  The same siminterface is used all the time, while
// different implementations of the CI can be switched in reasonably easily.
// Only the CI code uses library specific graphics and I/O functions; the
// siminterface deals in portable abstractions and callback functions.
// The first CI implementation was a series of text mode menus implemented in
// textconfig.cc.
//
// The configuration interface MUST use the siminterface methods to access the
// simulator.  It should not modify settings in some device with code like
// bx_floppy.s.media[2].heads = 17.  If such access is needed, then a
// siminterface method should be written to make the change on the CI's behalf.
// This separation is enforced by the fact that the CI does not even include
// bochs.h.  You'll notice that textconfig.cc includes osdep.h, paramtree.h
// and siminterface.h, so it doesn't know what bx_floppy or bx_cpu_c are.
// I'm sure some people will say is overly restrictive and/or annoying.  When I
// set it up this way, we were still talking about making the CI in a seperate
// process, where direct method calls would be impossible.  Also, we have been
// considering turning devices into plugin modules which are dynamically
// linked.  Any direct references to something like bx_floppy.s.media[2].heads
// would have to be reworked before a plugin interface was possible as well.
//
// The siminterface is the glue between the CI and the simulator.  There is
// just one global instance of the siminterface object, which can be referred
// to by the global variable bx_simulator_interface_c *SIM.  The base class
// bx_simulator_interface_c, contains only virtual functions and it defines the
// interface that the CI is allowed to use.  In siminterface.cc, a class
// called bx_real_sim_c is defined with bx_simulator_interface_c as its parent
// class.  Bx_real_sim_c implements each of the functions.  The separation into
// parent class and child class leaves the possibility of making a different
// child class that talks to the simulator in a different way (networking for
// example).  If you were writing a user interface in a separate process, you
// could define a subclass of bx_simulator_interface_c called
// bx_siminterface_proxy_c which opens up a network port and turns all method
// calls into network sends and receives.  Because the interface is defined
// entirely by the base class, the code that calls the methods would not know
// the difference.
//
// An important part of the siminterface implementation is the use of parameter
// classes, or bx_param_*.  The parameter classes are described below, where
// they are declared.  Search for "parameter classes" below for details.
//
// Also this header file declares data structures for certain events that pass
// between the siminterface and the CI.  Search for "event structures" below.


// base value for generated new parameter id
#define BXP_NEW_PARAM_ID 1001

typedef enum {
  BX_TOOLBAR_UNDEFINED,
  BX_TOOLBAR_FLOPPYA,
  BX_TOOLBAR_FLOPPYB,
  BX_TOOLBAR_CDROM1,
  BX_TOOLBAR_RESET,
  BX_TOOLBAR_POWER,
  BX_TOOLBAR_SAVE_RESTORE,
  BX_TOOLBAR_COPY,
  BX_TOOLBAR_PASTE,
  BX_TOOLBAR_SNAPSHOT,
  BX_TOOLBAR_CONFIG,
  BX_TOOLBAR_MOUSE_EN,
  BX_TOOLBAR_USER
} bx_toolbar_buttons;

// normally all action choices are available for all event types. The exclude
// expression allows some choices to be eliminated if they don't make any
// sense.  For example, it would be stupid to ignore a panic.
#define BX_LOG_OPTS_EXCLUDE(type, choice)  (             \
   /* can't die, ask or warn, on debug or info events */ \
   (type <= LOGLEV_INFO && (choice >= ACT_WARN))         \
   /* can't ignore panics */                             \
   || (type == LOGLEV_PANIC && choice == ACT_IGNORE)     \
   )

// floppy / cdrom media status
enum { BX_EJECTED = 0, BX_INSERTED = 1 };

// boot devices (using the same values as the rombios)
enum {
  BX_BOOT_NONE,
  BX_BOOT_FLOPPYA,
  BX_BOOT_DISKC,
  BX_BOOT_CDROM,
  BX_BOOT_NETWORK
};

// These are the different start modes.
enum {
  // Just start the simulation without running the configuration interface
  // at all, unless something goes wrong.
  BX_QUICK_START = 200,
  // Run the configuration interface.  The default action will be to load a
  // configuration file.  This makes sense if a config file could not be
  // loaded, either because it wasn't found or because it had errors.
  BX_LOAD_START,
  // Run the configuration interface.  The default action will be to
  // edit the configuration.
  BX_EDIT_START,
  // Run the configuration interface, but make the default action be to
  // start the simulation.
  BX_RUN_START
};

enum {
  BX_DDC_MODE_DISABLED,
  BX_DDC_MODE_BUILTIN,
  BX_DDC_MODE_FILE
};

enum {
  BX_MOUSE_TYPE_NONE,
  BX_MOUSE_TYPE_PS2,
  BX_MOUSE_TYPE_IMPS2,
#if BX_SUPPORT_BUSMOUSE
  BX_MOUSE_TYPE_INPORT,
  BX_MOUSE_TYPE_BUS,
#endif
  BX_MOUSE_TYPE_SERIAL,
  BX_MOUSE_TYPE_SERIAL_WHEEL,
  BX_MOUSE_TYPE_SERIAL_MSYS
};

enum {
  BX_MOUSE_TOGGLE_CTRL_MB,
  BX_MOUSE_TOGGLE_CTRL_F10,
  BX_MOUSE_TOGGLE_CTRL_ALT,
  BX_MOUSE_TOGGLE_F12
};

#define BX_FDD_NONE  0 // floppy not present
#define BX_FDD_525DD 1 // 360K  5.25"
#define BX_FDD_525HD 2 // 1.2M  5.25"
#define BX_FDD_350DD 3 // 720K  3.5"
#define BX_FDD_350HD 4 // 1.44M 3.5"
#define BX_FDD_350ED 5 // 2.88M 3.5"

#define BX_FLOPPY_NONE   10 // media not present
#define BX_FLOPPY_1_2    11 // 1.2M  5.25"
#define BX_FLOPPY_1_44   12 // 1.44M 3.5"
#define BX_FLOPPY_2_88   13 // 2.88M 3.5"
#define BX_FLOPPY_720K   14 // 720K  3.5"
#define BX_FLOPPY_360K   15 // 360K  5.25"
#define BX_FLOPPY_160K   16 // 160K  5.25"
#define BX_FLOPPY_180K   17 // 180K  5.25"
#define BX_FLOPPY_320K   18 // 320K  5.25"
#define BX_FLOPPY_LAST   18 // last legal value of floppy type

#define BX_FLOPPY_AUTO     19 // autodetect image size
#define BX_FLOPPY_UNKNOWN  20 // image size doesn't match one of the types above

#define BX_ATA_DEVICE_NONE       0
#define BX_ATA_DEVICE_DISK       1
#define BX_ATA_DEVICE_CDROM      2

#define BX_ATA_BIOSDETECT_AUTO   0
#define BX_ATA_BIOSDETECT_CMOS   1
#define BX_ATA_BIOSDETECT_NONE   2

enum {
  BX_SECT_SIZE_512,
  BX_SECT_SIZE_1024,
  BX_SECT_SIZE_4096
};

enum {
  BX_ATA_TRANSLATION_NONE,
  BX_ATA_TRANSLATION_LBA,
  BX_ATA_TRANSLATION_LARGE,
  BX_ATA_TRANSLATION_RECHS,
  BX_ATA_TRANSLATION_AUTO
};
#define BX_ATA_TRANSLATION_LAST  BX_ATA_TRANSLATION_AUTO

enum {
  BX_CLOCK_SYNC_NONE,
  BX_CLOCK_SYNC_REALTIME,
  BX_CLOCK_SYNC_SLOWDOWN,
  BX_CLOCK_SYNC_BOTH
};
#define BX_CLOCK_SYNC_LAST       BX_CLOCK_SYNC_BOTH

enum {
  BX_PCI_CHIPSET_I430FX,
  BX_PCI_CHIPSET_I440FX,
  BX_PCI_CHIPSET_I440BX
};

enum {
  BX_CPUID_SUPPORT_NOSSE,
  BX_CPUID_SUPPORT_SSE,
  BX_CPUID_SUPPORT_SSE2,
  BX_CPUID_SUPPORT_SSE3,
  BX_CPUID_SUPPORT_SSSE3,
  BX_CPUID_SUPPORT_SSE4_1,
  BX_CPUID_SUPPORT_SSE4_2,
#if BX_SUPPORT_AVX
  BX_CPUID_SUPPORT_AVX,
  BX_CPUID_SUPPORT_AVX2,
#if BX_SUPPORT_EVEX
  BX_CPUID_SUPPORT_AVX512
#endif
#endif
};

enum {
  BX_CPUID_SUPPORT_LEGACY_APIC,
  BX_CPUID_SUPPORT_XAPIC,
#if BX_CPU_LEVEL >= 6
  BX_CPUID_SUPPORT_XAPIC_EXT,
  BX_CPUID_SUPPORT_X2APIC
#endif
};

#define BX_CLOCK_TIME0_LOCAL     1
#define BX_CLOCK_TIME0_UTC       2

#endif
