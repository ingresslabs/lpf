%global debug_package %{nil}

Name:           lpf
Version:        0.1.1
Release:        1%{?dist}
Summary:        PF-style control plane for Linux networking
License:        Apache-2.0
URL:            https://github.com/avkcode/lpf
Source0:        lpf-%{version}.tar.gz

BuildRequires:  ocaml >= 5.1.0
BuildRequires:  ocaml-dune >= 3.11
BuildRequires:  opam
Requires:       nftables
Requires:       iproute
Requires:       conntrack-tools

%description
OCaml-first firewall policy control plane targeting nftables, policy routing,
tc, conntrack, and NFLOG. Provides readable policy files, safe atomic apply
with rollback, packet decision explainability, policy tests, dynamic tables,
and multi-backend diff/live readback.

%prep
%setup -q

%build
opam exec -- dune build --profile=release @install

%install
opam exec -- dune install --prefix=/usr --destdir=%{buildroot} --sections=bin
opam exec -- dune exec -- lpf man install --prefix %{buildroot}/usr

%files
%{_bindir}/lpf
%{_mandir}/man8/lpf*.8*
%{_mandir}/man5/lpf*.5*
%doc README.md CHANGELOG.md

%changelog
* Thu Jun 18 2026 avkcode - 0.1.1-1
- CI hardening, eBPF release coverage, and external lab documentation cleanup

* Wed Jun 17 2026 avkcode - 0.1.0-1
- Initial release
