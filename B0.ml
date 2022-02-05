open B0_kit.V000
open B00_std
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
  B0_ocaml.exe (Fpath.basename ~no_ext:true file) ~doc ~srcs ~requires

let test = test_exe "test.ml" ~doc:"Ttweetnacl tests"

(* Packs *)

let default =
  let meta =
    let open B0_meta in
    empty
    |> add authors ["The ttweetnacl programmers"]
    |> add maintainers ["Daniel Bünzli <daniel.buenzl i@erratique.ch>"]
    |> add homepage "https://erratique.ch/software/ttweetnacl"
    |> add online_doc "https://erratique.ch/software/ttweetnacl/doc"
    |> add licenses ["ISC"]
    |> add repo "git+https://erratique.ch/repos/ttweetnacl.git"
    |> add issues "https://github.com/dbuenzli/ttweetnacl/issues"
    |> add description_tags ["cryptography"; "bindings"; "nacl";
                             "org:erratique"; ]
    |> add B0_opam.Meta.build
      {|[["ocaml" "pkg/pkg.ml" "build" "--dev-pkg" "%{dev}%"]]|}
    |> tag B0_opam.tag
    |> add B0_opam.Meta.depends
      [ "ocaml", {|>= "4.13.0"|};
        "ocamlfind", {|build|};
        "ocamlbuild", {|build|};
         "topkg", {|build & >= "1.0.3"|}; ]
  in
  B0_pack.v "default" ~doc:"ttweetnacl" ~meta ~locked:true @@
  B0_unit.list ()
