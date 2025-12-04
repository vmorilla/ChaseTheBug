# A CSpect plugin to facilitate capturing nasty bugs 

The plugin is meant to capture attempts to write in memory that is reserved for code.
Currently, the plugin assumes the memory distribution used in Next Point:

- MMU0 and MMU1 are used for roms and for banked code extensions
- MMU5 is the main user code area, though the data segment is used at the end of this area. The plugin assumes that the symbol __data_crt_head points to the first byte that can be written. For the plugin to read this symbol, the configuration should point to a z88dk map file with symbol definitions.

The plugin also captures attempts to modify MMU1 non-consistently with the value in MMU0

