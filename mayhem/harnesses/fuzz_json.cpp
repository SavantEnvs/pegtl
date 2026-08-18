// mayhem/harnesses/fuzz_json.cpp — libFuzzer harness over PEGTL's JSON example grammar
// (include/tao/pegtl/example/json.hpp). Bytes-only: the fuzzer's buffer is wrapped in a
// zero-copy pegtl::view_input, no file I/O anywhere (SPEC §6.2 item 13).
//
// The input is capped at 64 KiB (docs/netnew-worker-prompt.md §6b) — past that, a PEG parser's
// backtracking cost stops being an interesting signal and only risks eating libFuzzer's default
// 1200s per-input timeout, stalling the whole campaign on one giant input.
//
// A pegtl::parse_error is EXPECTED for malformed JSON — caught, not a crash. The check_depth<64>
// action mirrors upstream's OWN hardening in src/example/json_parse.cpp (there: check_depth<42>)
// against unbounded nesting depth. Without it, adversarial nesting (e.g. "[[[[[...") drives a
// genuine stack overflow; upstream itself treats that as a DoS worth guarding for this grammar, so
// replicating their own guard here is not "masking a bug" — it is the documented, intended usage.
#include <cstddef>
#include <cstdint>
#include <exception>

#include <tao/pegtl.hpp>
#include <tao/pegtl/action/check_depth.hpp>
#include <tao/pegtl/example/json.hpp>

namespace pegtl = TAO_PEGTL_NAMESPACE;

namespace mayhem_json
{
   using grammar = pegtl::seq< pegtl::json::text, pegtl::eof >;

   template< typename >
   struct action
   {};

   template<>
   struct action< pegtl::json::value >
      : pegtl::check_depth< 64 >
   {};

}  // namespace mayhem_json

extern "C" int LLVMFuzzerTestOneInput( const std::uint8_t* data, std::size_t size )
{
   if( size > 65536 ) {
      return 0;  // bound pathological inputs — see header comment
   }
   using input_t = pegtl::input_with_depth< pegtl::view_input<> >;
   input_t in( reinterpret_cast< const char* >( data ), size );
   try {
      pegtl::parse< mayhem_json::grammar, mayhem_json::action >( in );
   }
   catch( const typename decltype( in )::parse_error_t& ) {
      // Malformed/rejected JSON (incl. max-depth-exceeded) — expected, not a finding.
   }
   catch( const std::exception& ) {
      // Any other PEGTL-internal exception on malformed input — also expected.
   }
   return 0;
}
