// mayhem/harnesses/fuzz_lua53.cpp — libFuzzer harness over PEGTL's Lua 5.3 example grammar
// (include/tao/pegtl/example/lua53.hpp) — the richest grammar PEGTL ships (a full statement /
// expression precedence chain for a real scripting language), chosen alongside json/uri/abnf per
// the worker brief's "strong set". Bytes-only, no file I/O.
//
// lua53::grammar is already `must< opt< shebang >, statement_list< eof > >` — full-string
// validation to eof, throwing (not returning false) on failure, exactly like the other harnesses.
#include <cstddef>
#include <cstdint>
#include <exception>

#include <tao/pegtl.hpp>
#include <tao/pegtl/example/lua53.hpp>

namespace pegtl = TAO_PEGTL_NAMESPACE;

extern "C" int LLVMFuzzerTestOneInput( const std::uint8_t* data, std::size_t size )
{
   if( size > 65536 ) {
      return 0;  // bound pathological inputs (docs/netnew-worker-prompt.md §6b)
   }
   pegtl::view_input<> in( reinterpret_cast< const char* >( data ), size );
   try {
      pegtl::parse< pegtl::lua53::grammar >( in );
   }
   catch( const typename decltype( in )::parse_error_t& ) {
      // Malformed Lua — expected, not a finding.
   }
   catch( const std::exception& ) {
   }
   return 0;
}
