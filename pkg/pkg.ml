#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let () =
  Pkg.describe "ttweetnacl" @@ fun c ->
  Ok [ Pkg.mllib "src/ttweetnacl.mllib";
       Pkg.clib "src/libttweetnacl_stubs.clib";
       Pkg.test "test/test";
       Pkg.doc "doc/index.mld" ~dst:"odoc-pages/index.mld"]
