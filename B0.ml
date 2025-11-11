open B0_kit.V000
open Result.Syntax

(* OCaml library names *)

let ttweetnacl = B0_ocaml.libname "ttweetnacl"

(* Libraries *)

let ttweetnacl_lib =
  let srcs = Fpath.[ `Dir (v "src") ] in
  let requires = [] in
  B0_ocaml.lib ttweetnacl ~doc:"The ttweetnacl library" ~srcs ~requires

(* Tests *)

let test_src f = `File Fpath.(v "test" // f)
let test_exe file ~doc =
  let file = Fpath.v file in
  let srcs = [test_src file] in
  let requires = [ ttweetnacl ] in
  B0_ocaml.exe (Fpath.basename ~drop_exts:true file) ~doc ~srcs ~requires

let test = test_exe "test.ml" ~doc:"Ttweetnacl tests"

(* Packs *)

let default =
  let meta =
    B0_meta.empty
    |> B0_meta.(add authors) ["The ttweetnacl programmers"]
    |> B0_meta.(add maintainers)
       ["Daniel Bünzli <daniel.buenzl i@erratique.ch>"]
    |> B0_meta.(add homepage) "https://erratique.ch/software/ttweetnacl"
    |> B0_meta.(add online_doc) "https://erratique.ch/software/ttweetnacl/doc"
    |> B0_meta.(add licenses) ["ISC"]
    |> B0_meta.(add repo) "git+https://erratique.ch/repos/ttweetnacl.git"
    |> B0_meta.(add issues) "https://github.com/dbuenzli/ttweetnacl/issues"
    |> B0_meta.(add description_tags)
      ["cryptography"; "bindings"; "nacl"; "org:erratique"; ]
    |> B0_meta.tag B0_opam.tag
    |> B0_meta.add B0_opam.build
      {|[["ocaml" "pkg/pkg.ml" "build" "--dev-pkg" "%{dev}%"]]|}
    |> B0_meta.add B0_opam.depends
      [ "ocaml", {|>= "4.13.0"|};
        "ocamlfind", {|build|};
        "ocamlbuild", {|build|};
         "topkg", {|build & >= "1.1.0"|}; ]
  in
  B0_pack.make "default" ~doc:"ttweetnacl" ~meta ~locked:true @@
  B0_unit.list ()
