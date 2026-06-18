(lang dune 3.11)

(name lpf)

(package
 (name lpf)
 (synopsis "PF-style control plane for Linux networking")
 (description "OCaml-first firewall policy control plane targeting nftables, policy routing, tc, conntrack, and NFLOG.")
 (depends
  (ocaml (>= 5.1))
  (dune (>= 3.11))
  (ocamlformat (and (= 0.26.2) :with-test))))
