// mayhem/harnesses/fuzz_uri.cpp — libFuzzer harness over PEGTL's RFC 3986 URI example grammar
// (include/tao/pegtl/example/uri.hpp). Bytes-only, no file I/O.
//
// The grammar alias matches upstream's OWN src/test/example_uri.cpp exactly
// (`using GRAMMAR = must< uri::URI, eof >;`) — full-string validation, not a prefix match.
#include <cstddef>
#include <cstdint>
#include <exception>

#include <tao/pegtl.hpp>
#include <tao/pegtl/example/uri.hpp>

namespace pegtl = TAO_PEGTL_NAMESPACE;

namespace mayhem_uri
{
   using grammar = pegtl::must< pegtl::uri::URI, pegtl::eof >;

}  // namespace mayhem_uri

extern "C" int LLVMFuzzerTestOneInput( const std::uint8_t* data, std::size_t size )
{
   if( size > 65536 ) {
      return 0;  // bound pathological inputs (docs/netnew-worker-prompt.md §6b)
   }
   pegtl::view_input<> in( reinterpret_cast< const char* >( data ), size );
   try {
      pegtl::parse< mayhem_uri::grammar >( in );
   }
   catch( const typename decltype( in )::parse_error_t& ) {
      // Malformed/rejected URI — expected, not a finding (must<> throws instead of returning false).
   }
   catch( const std::exception& ) {
   }
   return 0;
}
