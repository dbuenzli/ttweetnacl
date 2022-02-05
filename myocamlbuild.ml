open Ocamlbuild_plugin
open Command

let lib s = match !Ocamlbuild_plugin.Options.ext_lib with
 | "" -> s ^ ".a"
 | x -> s ^ "." ^ x

let () =
  dispatch begin function
  | After_rules ->
      dep ["record_ttweetnacl_stubs"] [lib "src/libttweetnacl_stubs"];
      flag_and_dep
        ["link"; "ocaml"; "link_ttweetnacl_stubs"]
        (P (lib "src/libttweetnacl_stubs"));

      flag ["library"; "ocaml"; "byte"; "record_ttweetnacl_stubs"]
        (S ([A "-dllib"; A "-lttweetnacl_stubs"]));

      flag ["library"; "ocaml"; (* byte and native *)
            "record_ttweetnacl_stubs"]
        (S ([A "-cclib"; A "-lttweetnacl_stubs"]));

      ocaml_lib ~tag_name:"use_ttweetnacl_stubs"
        ~dir:"src" "src/ttweetnacl";

      flag ["link"; "ocaml"; "use_ttweetnacl_stubs"]
        (S [A "-ccopt"; A "-Lsrc"]);

      dep ["compile";"c"]
        ["src/tweetnacl.h"; ]
  | _ -> ()
  end
