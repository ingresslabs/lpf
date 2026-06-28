%global debug_package %{nil}

Name:           lpf
Version:        0.3.0
Release:        1%{?dist}
Summary:        PF-style control plane for Linux networking
License:        Apache-2.0
URL:            https://github.com/ingresslabs/lpf
Source0:        lpf-%{version}.tar.gz

BuildRequires:  ocaml >= 5.1.0
BuildRequires:  ocaml-dune >= 3.15
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
if [ -n "${OPAMSWITCH:-}" ]; then
  opam exec --switch="$OPAMSWITCH" -- dune build --profile=release @install
else
  opam exec -- dune build --profile=release @install
fi

%install
if [ -n "${OPAMSWITCH:-}" ]; then
  opam exec --switch="$OPAMSWITCH" -- dune install --prefix=/usr --destdir=%{buildroot} --sections=bin
  opam exec --switch="$OPAMSWITCH" -- dune exec -- lpf man install --prefix %{buildroot}/usr
else
  opam exec -- dune install --prefix=/usr --destdir=%{buildroot} --sections=bin
  opam exec -- dune exec -- lpf man install --prefix %{buildroot}/usr
fi
mkdir -p %{buildroot}%{_datadir}/bash-completion/completions
cp bin/lpf-completion.sh %{buildroot}%{_datadir}/bash-completion/completions/lpf

%files
%{_bindir}/lpf
%{_mandir}/man8/lpf*.8*
%{_mandir}/man5/lpf*.5*
%{_datadir}/bash-completion/completions/lpf
%doc README.md CHANGELOG.md

%changelog
* Sun Jun 28 2026 avkcode - 0.3.0-1
- Primary CNI packaging and real eBPF cgroup_skb enforcement
- Add Kubernetes policy packaging, daemon metrics, and real-traffic validation

* Mon Jun 22 2026 avkcode - 0.2.3-1
- Verified rollback-safe advanced policies across Ubuntu and Fedora VMs
- Fix CIDR explain semantics, NAT/RDR rendering, TC/routing batches, and owned-table rollback

* Thu Jun 18 2026 avkcode - 0.1.2-1
- Remove the experimental dataplane compiler command and refresh packages

* Thu Jun 18 2026 avkcode - 0.1.1-1
- CI hardening, release coverage, and external lab documentation cleanup

* Wed Jun 17 2026 avkcode - 0.1.0-1
- Initial release
