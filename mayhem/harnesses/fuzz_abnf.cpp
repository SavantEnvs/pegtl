// mayhem/harnesses/fuzz_abnf.cpp — libFuzzer harness over PEGTL's ABNF (RFC 5234, updated by
// RFC 7405) example grammar (include/tao/pegtl/example/abnf_abnf.hpp) — the grammar abnf2pegtl
// uses to parse real ABNF grammar files (e.g. src/example/abnf.abnf, shipped as a seed). Bytes-only.
//
// abnf::rulelist recurses through option<>/group<> on nested '['/'(' constructs, so adversarial
// nesting can drive a genuine stack overflow. We deliberately do NOT guard that here (see
// docs/netnew-worker-prompt.md §6b): a resulting crash is a legitimate finding, not something to
// mask. The 64 KiB size cap below only bounds pathological backtracking cost, not recursion depth.
#include <cstddef>
#include <cstdint>
#include <exception>

#include <tao/pegtl.hpp>
#include <tao/pegtl/example/abnf_abnf.hpp>

namespace pegtl = TAO_PEGTL_NAMESPACE;

extern "C" int LLVMFuzzerTestOneInput( const std::uint8_t* data, std::size_t size )
{
   if( size > 65536 ) {
      return 0;  // bound pathological inputs (docs/netnew-worker-prompt.md §6b)
   }
   pegtl::view_input<> in( reinterpret_cast< const char* >( data ), size );
   try {
      pegtl::parse< pegtl::abnf::rulelist >( in );
   }
   catch( const typename decltype( in )::parse_error_t& ) {
      // Malformed ABNF — expected, not a finding.
   }
   catch( const std::exception& ) {
   }
   return 0;
}
