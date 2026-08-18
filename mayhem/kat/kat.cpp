// mayhem/kat/kat.cpp — behavioral known-answer probe used by mayhem/test.sh (SPEC §6.3).
//
// WHY THIS EXISTS (do not delete / do not gate it behind a `[ -f ... ]` check): verify-repo's
// sabotage check LD_PRELOADs a shim whose constructor _exit(0)s any non-system executable before
// main() runs. An exit-code-only oracle is therefore reward-hackable even for a real, dynamically
// linked C++ binary — PEGTL's own `ctest` suite (275 small binaries, one process each, judged only
// by exit code) is EXACTLY this trap: a neutered binary that never reaches its
// TAO_PEGTL_TEST_ASSERT calls still exits 0, indistinguishable from a real silent pass. (Proven
// empirically on a different repo, pkgconf: `meson test` reported 32/32 OK under the sabotage
// shim — see docs/netnew-worker-prompt.md §4.) So the ctest suite alone cannot be the oracle here.
//
// This probe instead PRINTS parsed VALUES to stdout, built with PEGTL's own example machinery:
//   - JSON: parses a fixed object (via the exact builder pattern from src/example/json_builder.cpp)
//     and prints the parsed "name" string plus the recursive count_values() over the whole tree.
//   - URI:  parses a fixed absolute URI (via the exact struct+action pattern from
//     src/example/uri_struct.cpp) and prints every extracted component.
// mayhem/test.sh greps for exact `KAT_...=...` lines. A neutered process prints NOTHING (it never
// reaches main), so every grep fails and test.sh's failed count goes above zero — sabotage caught
// through stdout content, not exit code, which is where the shim cannot hide (SPEC §6.3).
//
// Built with NORMAL flags (no sanitizers, no fuzzer) by mayhem/build.sh — this is a functional
// oracle artifact, not a fuzz target.
#include <cstddef>
#include <exception>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <variant>
#include <vector>

#include <tao/pegtl.hpp>
#include <tao/pegtl/action/builders.hpp>
#include <tao/pegtl/example/json.hpp>
#include <tao/pegtl/example/uri.hpp>
#include <tao/pegtl/extra/builders.hpp>

namespace pegtl = TAO_PEGTL_NAMESPACE;

// ─────────────────────────────────────────────────────────────────────────────────────────────
// JSON: exact builder pattern lifted from src/example/json_builder.cpp.
// ─────────────────────────────────────────────────────────────────────────────────────────────
namespace kat_json
{
   namespace rules = pegtl::json;

   using grammar = pegtl::seq< rules::text, pegtl::eof >;

   struct value;
   using array = std::vector< value >;
   using object = std::map< std::string, value >;

   struct value
   {
      std::variant< std::nullptr_t, bool, double, std::string, array, object > data;
   };

   template< typename Rule >
   struct action
      : pegtl::nothing< Rule >
   {};

   template< typename Rule >
   using json_value = pegtl::create_for< Rule, value, action >;

   template<>
   struct action< rules::value >
      : pegtl::variant_to< &value::data,
                           pegtl::const_for< rules::null, nullptr >,
                           pegtl::cases< pegtl::case_< rules::false_, false >,
                                         pegtl::case_< rules::true_, true > >,
                           rules::number,
                           pegtl::unescape_for< rules::string_content >,
                           pegtl::repeat_for< rules::array, json_value< rules::array_element > >,
                           pegtl::repeat_for< rules::object, pegtl::multi_for< rules::member,
                                                                               pegtl::unescape_for< rules::key_content >,
                                                                               json_value< rules::member_value > > > >
   {};

   [[nodiscard]] std::size_t count_values( const value& v )
   {
      return std::visit(
         []( const auto& data ) -> std::size_t {
            using data_t = std::decay_t< decltype( data ) >;
            if constexpr( std::is_same_v< data_t, array > ) {
               std::size_t result = 1;
               for( const auto& element : data ) {
                  result += count_values( element );
               }
               return result;
            }
            else if constexpr( std::is_same_v< data_t, object > ) {
               std::size_t result = 1;
               for( const auto& member : data ) {
                  result += count_values( member.second );
               }
               return result;
            }
            else {
               return 1;
            }
         },
         v.data );
   }

}  // namespace kat_json

// ─────────────────────────────────────────────────────────────────────────────────────────────
// URI: exact struct+action pattern lifted from src/example/uri_struct.cpp.
// ─────────────────────────────────────────────────────────────────────────────────────────────
namespace kat_uri
{
   struct uri
   {
      std::string scheme;
      std::string authority;
      std::string userinfo;
      std::string host;
      std::string port;
      std::string path;
      std::string query;
      std::string fragment;

      template< typename ParseInput >
      explicit uri( ParseInput& in );
   };

   template< typename Rule >
   struct action
   {};

   template<>
   struct action< pegtl::uri::scheme > : pegtl::value_to< &uri::scheme >
   {};
   template<>
   struct action< pegtl::uri::authority > : pegtl::value_to< &uri::authority >
   {};
   template<>
   struct action< pegtl::uri::host > : pegtl::value_to< &uri::host >
   {};
   template<>
   struct action< pegtl::uri::port > : pegtl::value_to< &uri::port >
   {};
   template<>
   struct action< pegtl::uri::path_noscheme > : pegtl::value_to< &uri::path >
   {};
   template<>
   struct action< pegtl::uri::path_rootless > : pegtl::value_to< &uri::path >
   {};
   template<>
   struct action< pegtl::uri::path_absolute > : pegtl::value_to< &uri::path >
   {};
   template<>
   struct action< pegtl::uri::path_abempty > : pegtl::value_to< &uri::path >
   {};
   template<>
   struct action< pegtl::uri::query > : pegtl::value_to< &uri::query >
   {};
   template<>
   struct action< pegtl::uri::fragment > : pegtl::value_to< &uri::fragment >
   {};

   template<>
   struct action< pegtl::uri::opt_userinfo >
   {
      template< typename ActionInput >
      static void apply( const ActionInput& in, uri& u )
      {
         if( !in.empty() ) {
            u.userinfo = std::string( in.begin(), in.size() - 1 );
         }
      }
   };

   template< typename ParseInput >
   uri::uri( ParseInput& in )
   {
      using grammar = pegtl::must< pegtl::uri::URI >;
      pegtl::parse< grammar, action >( in, *this );
   }

}  // namespace kat_uri

namespace
{
   int run_json_kat()
   {
      // Known tree: root object (1) + "name" (1) + "numbers" array (1 + 3 elements = 4) +
      // "nested" object (1 + "ok" (1) = 2) = 1 + 1 + 4 + 2 = 8 values total.
      const std::string text = R"({"name":"pegtl","numbers":[1,2,3],"nested":{"ok":true}})";
      kat_json::value out;
      pegtl::view_input<> in( text.data(), text.size() );

      bool ok = false;
      try {
         ok = pegtl::parse< kat_json::grammar, kat_json::action >( in, out );
      }
      catch( const std::exception& ) {
         ok = false;
      }

      std::string name;
      std::size_t count = 0;
      if( ok ) {
         count = kat_json::count_values( out );
         try {
            const auto& obj = std::get< kat_json::object >( out.data );
            name = std::get< std::string >( obj.at( "name" ).data );
         }
         catch( const std::exception& ) {
            name.clear();
         }
      }

      std::cout << "KAT_JSON_OK=" << ( ok ? 1 : 0 ) << '\n';
      std::cout << "KAT_JSON_COUNT=" << count << '\n';
      std::cout << "KAT_JSON_NAME=" << name << '\n';
      return ok ? 0 : 1;
   }

   int run_uri_kat()
   {
      const std::string text = "https://user:pass@example.org:8080/a/b?x=1&y=2#frag";
      pegtl::view_input<> in( text.data(), text.size() );
      try {
         const kat_uri::uri u( in );
         std::cout << "KAT_URI_SCHEME=" << u.scheme << '\n';
         std::cout << "KAT_URI_HOST=" << u.host << '\n';
         std::cout << "KAT_URI_PORT=" << u.port << '\n';
         std::cout << "KAT_URI_USERINFO=" << u.userinfo << '\n';
         std::cout << "KAT_URI_PATH=" << u.path << '\n';
         std::cout << "KAT_URI_QUERY=" << u.query << '\n';
         std::cout << "KAT_URI_FRAGMENT=" << u.fragment << '\n';
         return 0;
      }
      catch( const std::exception& e ) {
         std::cout << "KAT_URI_ERROR=" << e.what() << '\n';
         return 1;
      }
   }

}  // namespace

int main()
{
   int failed = 0;
   failed += run_json_kat();
   failed += run_uri_kat();
   return failed;
}
