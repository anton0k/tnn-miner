#pragma once
/* Wave38 full-binary probe: verus_clhash.cpp includes primitives/block.h,
 * but this object path does not use block structures. Keep this as a minimal
 * compatibility shim to avoid pulling the full Verus block/transaction tree
 * into TNN's CPU binary probe.
 */
