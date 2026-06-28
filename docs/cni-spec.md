# lpf CNI — cross-platform container network plugin

## 1. Overview

lpf CNI is a container network interface plugin that compiles a single `.lpf`
policy file into an eBPF datapath and attaches it at pod granularity via
cgroup/skb and LSM hooks.  It targets Kubernetes, k3s, and Nomad with no
platform-specific policy dialects.

**Why it exists**: Cilium is k8s-only, Calico splits policy across YAML dialects,
Antrea is OVS-based.  No existing CNI offers:

1. One policy language for k8s and Nomad
2. eBPF datapath with Z3-grade formal verification before rollout
3. Per-pod cgroup attachment (not per-host iptables)
4. Deterministic explain/diff/dry-run on any policy before applying to a cluster

### 1.1 What ships

| Component | Language | Role |
|-----------|----------|------|
| `lpf-cni` | OCaml | CNI protocol (ADD/DEL/CHECK/VERSION), netns plumbing, IPAM client, policy dispatch |
| `lpf-policy` | OCaml | Policy parser → IR → eBPF plan (existing, extended) |
| `lpf-prog` | C/eBPF | cgroup/skb + LSM datapath (existing, extended for CNI) |
| `lpf-daemon` | OCaml | Per-node policy agent, map lifecycle, ring-buffer relay |

### 1.2 Non-goals

- Overlay networks (VXLAN, Geneve).  lpf CNI assumes routable pod CIDRs.
- Service mesh sidecar.  kube-proxy / eBPF service LB is a separate concern.
- Inline L7 inspection.  Policy is L3/L4 with optional DNS-based identity.

---

## 2. CNI Architecture

### 2.1 Attachment model

```
┌─────────────────────────────────────────────────────┐
│                   Pod netns                         │
│  ┌─────────┐  ┌──────────────────────────────────┐  │
│  │ lpf_cni │  │  cgroup/skb ingress/egress        │  │
│  │  (ADD)  │──│  LSM socket_connect/bind          │──│
│  └─────────┘  │  XDP on veth host end (optional)  │  │
│               └──────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│              BPF maps (per-node)                     │
│  lpf_rules  lpf_cidr4  lpf_cidr6  lpf_conntrack     │
│  lpf_dnat   lpf_snat   lpf_events  lpf_cgroup        │
└─────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│              lpf-daemon (per-node)                    │
│  - watches policy CRD / lpf-policy ConfigMap          │
│  - recompiles policy → BPF maps on change             │
│  - relays ring-buffer events → metrics/log            │
│  - reports node health to control plane               │
└─────────────────────────────────────────────────────┘
```

### 2.2 CNI ADD flow (pod creation)

```
kubelet/containerd/nomad
  │
  ├─1. invokes lpf-cni with CNI_COMMAND=ADD
  │     stdin: network config JSON with policy_ref
  │
  ├─2. lpf-cni:
  │     a. create veth pair (host: lpfhXXXX, pod: eth0)
  │     b. move pod end into netns, rename to requested ifname
  │     c. assign IP from IPAM (host-local, whereabouts, or DHCP)
  │     d. add default route via host veth
  │     e. read pod labels/annotations from CNI_ARGS
  │        (K8S_POD_NAMESPACE, K8S_POD_NAME, NOMAD_GROUP_NAME, …)
  │     f. map pod identity → cgroup_id and cidr_set index
  │        via lpf-daemon gRPC or direct BPF map update
  │     g. write result JSON to stdout
  │
  └─3. lpf-daemon (async):
        a. detects new cgroup via cgroupfs inotify
        b. attaches cgroup_skb_{ingress,egress} to cgroup
        c. attaches LSM socket_{connect,bind} to cgroup
        d. updates lpf_cgroup map: cgroup_id → set_index
        e. updates lpf_cidr4/6 maps with pod IP
```

### 2.3 CNI DEL flow (pod deletion)

```
kubelet/containerd/nomad
  │
  ├─1. invokes lpf-cni with CNI_COMMAND=DEL
  │
  ├─2. lpf-cni:
  │     a. remove veth from pod netns
  │     b. delete host veth
  │     c. release IP back to IPAM (if configured)
  │     d. signal lpf-daemon: remove cgroup attachments,
  │        clean lpf_cgroup map entry, remove pod CIDR
  │
  └─3. lpf-daemon:
        a. detaches BPF programs from cgroup
        b. deletes lpf_cgroup map entry
        c. removes pod IP from lpf_cidr4/6
```

### 2.4 CNI CHECK flow

Verifies pod networking is intact: veth exists, IP matches, routes present, BPF
programs attached to correct cgroup.  Returns success/failure to runtime so it
can decide to tear down and re-create.

### 2.5 eBPF program lifecycle

BPF programs are **pinned** to `/sys/fs/bpf/lpf/`:

```
/sys/fs/bpf/lpf/
├── progs/
│   ├── cgroup_ingress_v3    ← current active version
│   ├── cgroup_egress_v3
│   ├── lsm_connect_v3
│   └── lsm_bind_v3
├── maps/
│   ├── lpf_rules            ← shared, atomically swapped
│   ├── lpf_cidr4
│   ├── lpf_cidr6
│   ├── lpf_cgroup
│   └── lpf_events
└── version.txt
```

Policy updates use **atomic map swap** (the existing `versioned_loader_script`
pattern in `lib/ebpf.ml:1328`).  Attached programs continue running against the
same map FDs; new map content takes effect on next packet.

### 2.6 Multi-tenancy

Each pod gets its own **cgroup_id → set_index** entry in `lpf_cgroup`.  The
BPF ingress/egress programs read `bpf_get_current_cgroup_id()` to resolve
the pod identity, then use the set index for CIDR membership checks
(is this destination IP in `<tenant-a-db>`?).  Policies are namespace-scoped:

```lpf
# cluster policy (applied to all pods)
set default deny

# namespace: tenant-a (label selector: app.kubernetes.io/name=web)
anchor tenant-a-web {
  pass in on eth0 proto tcp from <tenant-a-db> to any port 5432
  pass in on eth0 proto tcp from any to any port {80,443}
  pass out on eth0 to any port {443,53} keep state
}

# namespace: tenant-b
anchor tenant-b-api {
  pass in on eth0 proto tcp from any to any port 8080
  pass out on eth0 to any port {443,53,9092} keep state
}
```

Pod → anchor mapping: `lpf-daemon` labels each cgroup with the matching anchor
name; the BPF program resolves `cgroup_id → anchor → rule set`.

---

## 3. Policy Model

### 3.1 Three policy tiers

| Tier | Scope | Source | Applied by |
|------|-------|--------|------------|
| **Cluster** | All nodes | `lpf-policy` ConfigMap or CRD | lpf-daemon watches + recompiles |
| **Namespace** | One ns | `NetworkPolicy` CRD → .lpf translation | lpf-daemon namespace selector |
| **Pod** | One pod | Pod annotation `lpf.ingresslabs.com/policy` | lpf-cni on ADD |

Tiers merge: Cluster + Namespace + Pod = effective policy.  Same as the anchor
model: higher-tier anchors are always active; pod-level policy can only further
restrict (never widen).

### 3.2 Kubernetes NetworkPolicy translation

lpf ships a **bidirectional translator** between `networking.k8s.io/v1`
NetworkPolicy and `.lpf` format.  This means lpf CNI is a drop-in replacement
for Calico/Cilium/Weave — existing NetworkPolicy YAMLs work without change.

```
# Kubernetes NetworkPolicy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-allow
  namespace: tenant-a
spec:
  podSelector:
    matchLabels:
      app: api
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: web
      ports:
        - port: 8080
          protocol: TCP
```

Translates to:

```lpf
# Generated from NetworkPolicy tenant-a/api-allow
anchor tenant-a-api-allow {
  pass in on eth0 proto tcp from <tenant-a-web> to any port 8080
}
```

The translator handles: `podSelector`, `namespaceSelector`, `ipBlock`
(excluding+including), `ports` (named ports via pod spec resolution),
`policyTypes` (Ingress/Egress), and `endPort` (port ranges).

### 3.3 Nomad network stanza translation

```
# Nomad jobspec
job "api" {
  group "api" {
    network {
      mode = "bridge"
      port "http" { static = 8080 }
    }
  }
}
```

Translates to:

```lpf
# Generated from Nomad job api / group api
anchor nomad-api-api {
  pass in on eth0 proto tcp from any to any port 8080
  pass out on eth0 to any port {443,53} keep state
}
```

### 3.4 Identity model

Identities are CIDR sets populated by lpf-daemon:

| Set | Populated from | Example |
|-----|---------------|---------|
| `<pod-labels>` | Pod label selector → pod IPs | `<tenant-a-web>` → `{10.42.1.5, 10.42.2.7}` |
| `<ns>` | All pods in namespace | `<tenant-a>` → `{10.42.1.0/24}` |
| `<cidr>` | Literal CIDR | `<10.0.0.0/8>` |
| `<svc>` | Service ClusterIP | `<kube-dns>` → `{10.43.0.10}` |

lpf-daemon watches the Kubernetes API (or Nomad API) and keeps CIDR sets in
sync.  Pod churn triggers incremental BPF map updates — no full recompilation
for single-pod add/delete when only CIDR sets change.

---

## 4. BPF Datapath Extensions

### 4.1 What already exists (v0.3.0)

| Feature | Hooks | Status |
|---------|-------|--------|
| cgroup ingress/egress classifier | `cgroup_skb/ingress`, `cgroup_skb/egress` | Implemented (`lpf_kern.c:891,900`) |
| LSM socket_connect | `lsm/socket_connect` | Implemented (`lpf_kern.c:909`) |
| LSM socket_bind | `lsm/socket_bind` | Stub (`lpf_kern.c:950`) |
| Conntrack (keep-state) | LRU hash, 5-tuple | Implemented (`lpf_kern.c:320`) |
| DNAT / SNAT | XDP+TC checksum rewrite | Implemented (`lpf_kern.c:434,468`) |
| TCP RST injection | TC egress | Implemented (`lpf_kern.c:523`) |
| FIB lookup (route-to) | `bpf_fib_lookup` | Implemented (`lpf_kern.c:802`) |
| QoS classid | `skb->tc_classid` | Implemented (`lpf_kern.c:798`) |
| Ring buffer events | `BPF_MAP_TYPE_RINGBUF` | Implemented (`lpf_kern.c:299`) |
| CIDR LPM sets | `BPF_MAP_TYPE_LPM_TRIE` | Implemented |
| Per-cgroup identity | `lpf_cgroup` hash map | Implemented (`lpf_kern.c:222`) |
| O(1) rule hash dispatch | `lpf_rules_hash` | Implemented (`lpf_kern.c:198`) |

### 4.2 What needs to be added

| Feature | Rationale | Effort |
|---------|-----------|--------|
| **DNS-based identity** (already in map def) | `lpf_dns` map exists but is unused — wire it to resolve pod FQDN → IP set for policies like `from <*.tenant-a.svc.cluster.local>` | Small |
| **Atomic map swap at cgroup scope** | Current versioned swap is host-global. Need per-pod map pinning so policy updates don't interrupt unrelated pods | Medium |
| **BPF spinlock for concurrent map updates** | lpf-daemon and CNI ADD may race on `lpf_cgroup` map. Requires spinlock or per-CPU update pattern | Small |
| **IPv6 conntrack** | Conntrack handles UDP/TCP for IPv4; extend 5-tuple and expiry to IPv6 | Medium |
| **Bandwidth enforcement (EDT/HTB)** | Hook into `BPF_HTB` qdisc or `fq` pacing for queue bandwidth limits at pod level | Medium |
| **Flow export (IPFIX/sFlow)** | Ring buffer events → structured flow logs → IPFIX template | Medium |
| **Policy audit mode** | `--observe` flag: BPF programs in shadow mode count what would-have-been-blocked without actually dropping | Small |
| **eBPF service LB** | Replace kube-proxy: `BPF_MAP_TYPE_LRU_HASH` for service backend selection, FIB lookup for NodePort | Large (v2) |

### 4.3 Performance model

| Scenario | Expected throughput | Basis |
|----------|--------------------|-------|
| cgroup/skb allow (conntrack fastpath) | Line rate | Single `bpf_get_current_cgroup_id()` + hash lookup |
| cgroup/skb deny (first packet) | ~100 ns overhead | Rule scan with O(1) hash dispatch, CIDR LPM |
| LSM connect deny | ~50 ns overhead | Single map lookup, no packet data |
| Policy update (single pod churn) | ~1 ms | Incremental CIDR map update via `bpf_map_update_elem` |
| Full policy recompilation | ~200 ms | OCaml compile → BPF map swap |

---

## 5. lpf-cni Binary Design

### 5.1 Interface

```
lpf-cni <command>

Commands:
  add       Handle CNI ADD (called by container runtime)
  del       Handle CNI DEL
  check     Handle CNI CHECK
  version   Print CNI version info (CNI spec 1.0.0)
  daemon    Start per-node policy agent
  install   Install CNI config files into /etc/cni/net.d/
  status    Print node health (attached programs, pod count, errors)
```

For container runtimes, only `lpf-cni` is needed.  The runtime calls it with
standard CNI environment variables and a network configuration on stdin.

### 5.2 Network configuration (stdin JSON)

```json
{
  "cniVersion": "1.0.0",
  "name": "lpf",
  "type": "lpf-cni",
  "ipam": {
    "type": "host-local",
    "subnet": "10.42.0.0/16",
    "routes": [{ "dst": "0.0.0.0/0" }]
  },
  "policy": {
    "mode": "auto",
    "defaultAction": "deny",
    "clusterPolicyRef": "lpf-cluster-policy",
    "logDropped": true
  },
  "dns": {}
}
```

| Field | Type | Meaning |
|-------|------|---------|
| `policy.mode` | `auto` / `static` / `none` | `auto`: use lpf-daemon for policy. `static`: inline policy. `none`: pass-through (debug). |
| `policy.defaultAction` | `deny` / `pass` | Default verdict when no rule matches |
| `policy.clusterPolicyRef` | string | ConfigMap or CRD name with `.lpf` policy |
| `policy.logDropped` | bool | Emit ring-buffer events for dropped packets |
| `policy.auditMode` | bool | Shadow mode: log would-have-blocked, don't drop |

### 5.3 IPAM integration

lpf-cni delegates IP allocation to standard CNI IPAM plugins:

| Plugin | Use case |
|--------|----------|
| `host-local` | Single-node (k3s, kind) |
| `whereabouts` | Multi-node without overlay |
| `dhcp` | Bare-metal / Nomad |
| `static` | Debug / test fixtures |

lpf-cni calls the delegated IPAM plugin as a subprocess (standard CNI chaining).

### 5.4 Chaining

lpf can be chained with other CNI plugins (e.g., Multus for multi-interface pods,
or a bandwidth plugin for QoS):

```json
{
  "cniVersion": "1.0.0",
  "name": "lpf-chained",
  "plugins": [
    { "type": "bandwidth", "ingressRate": 100, "egressRate": 100 },
    { "type": "lpf-cni", "ipam": { "type": "host-local", "subnet": "10.42.0.0/16" } }
  ]
}
```

---

## 6. lpf-daemon Design

The daemon runs on every node as a DaemonSet (k8s) or system job (Nomad).
Privileged container with host PID, BPF caps, and `/sys/fs/bpf` mounted.

### 6.1 Responsibilities

| Function | How |
|----------|-----|
| **Policy watch** | Watches ConfigMap/CRD via informer (k8s) or Consul watch (Nomad). Recompiles `.lpf` → BPF plan on change. |
| **Pod watch** | Watches pod create/delete. Assigns cgroup_id → set_index. Updates CIDR maps. |
| **BPF lifecycle** | Loads programs at startup (from pinned path or embedded ELF). Pins to `/sys/fs/bpf/lpf/`. Atomic map swap on policy change. |
| **Cgroup attachment** | For each new pod cgroup: `bpftool cgroup attach <cgroup> cgroup_skb ingress pinned /sys/fs/bpf/lpf/progs/cgroup_ingress` |
| **Ring buffer relay** | Reads `lpf_events` ring buffer. Emits structured logs (JSON), Prometheus metrics (drop counters per rule), optional OpenTelemetry traces. |
| **Health reporting** | gRPC health check. Exposes `/readyz`, `/livez`, `/metrics` (Prometheus). |

### 6.2 gRPC API

```protobuf
service LpfDaemon {
  // Called by lpf-cni on CNI ADD to register pod identity.
  rpc RegisterPod(RegisterPodRequest) returns (RegisterPodResponse);

  // Called by lpf-cni on CNI DEL to remove pod identity.
  rpc UnregisterPod(UnregisterPodRequest) returns (UnregisterPodResponse);

  // Check policy validity without applying (dry-run for CI/CD).
  rpc ValidatePolicy(ValidatePolicyRequest) returns (ValidatePolicyResponse);

  // Diff current BPF maps against intended policy.
  rpc DiffPolicy(DiffPolicyRequest) returns (DiffPolicyResponse);

  // Stream ring-buffer events for central logging.
  rpc StreamEvents(StreamEventsRequest) returns (stream Event);

  // Node health.
  rpc HealthCheck(HealthCheckRequest) returns (HealthCheckResponse);
}

message RegisterPodRequest {
  string pod_uid = 1;
  string pod_name = 2;
  string namespace = 3;
  uint64 cgroup_id = 4;
  string ip = 5;             // primary pod IP (CIDR)
  repeated string ips = 6;   // additional IPs (multus)
  map<string, string> labels = 7;
}

message Event {
  string pod_uid = 1;
  string verdict = 2;         // PASS, DROP, REJECT, NAT
  uint32 rule_index = 3;
  string hook = 4;            // ingress, egress, connect, bind
  string src_ip = 5;
  string dst_ip = 6;
  uint16 src_port = 7;
  uint16 dst_port = 8;
  uint8 protocol = 9;
  uint64 timestamp_ns = 10;
}
```

---

## 7. Test Suite Design

### 7.1 Test matrix

Four layers of testing, each with concrete tooling:

```
Layer 0: Unit            BPF_PROG_TEST_RUN, OCaml expect tests     < 5 sec
Layer 1: Docker sandbox   CNI ADD/DEL in container, traffic gen      < 30 sec
Layer 2: k3s cluster      Single-node k3s, real pods, real traffic   < 5 min
Layer 3: Multi-node k8s   kind 3-node, kubeadm 5-node, chaos         < 20 min
```

### 7.2 Layer 0 — Unit & BPF conformance

**Tooling**: Existing `dune runtest` + `bpf/e2e_progrun.py` extended for CNI.

**Tests** (~200 cases):

```
test_cni_bpf/
├── test_cgroup_ingress.c        # BPF_PROG_TEST_RUN for cgroup_skb/ingress
│   ├── ingress_allow_port_80          # pass in proto tcp to port 80
│   ├── ingress_block_port_22          # deny in proto tcp to port 22
│   ├── ingress_cidr_set_match         # from <admins> to any
│   ├── ingress_cidr_set_nomatch       # from <unknown> to any
│   ├── ingress_conntrack_fastpath     # established flow bypass
│   ├── ingress_dnat_rewrite           # rdr on eth0 to 10.0.0.5:8080
│   └── ingress_default_deny           # no matching rule → drop
├── test_cgroup_egress.c
│   ├── egress_allow_dns_53            # pass out to port 53
│   ├── egress_snat_rewrite            # nat on eth0 from <lan> to any -> eth0
│   ├── egress_tcp_rst                 # reject out → RST injection
│   └── egress_route_to_gateway        # route-to 192.0.2.1
├── test_lsm_connect.c
│   ├── connect_allow_destination      # LSM allows connect to <allowed>
│   ├── connect_block_destination      # LSM denies connect to <blocked>
│   ├── connect_non_tcp_skip           # UDP not enforced at LSM
│   └── connect_port_range             # port range in rule
├── test_lsm_bind.c
│   ├── bind_allow_port_8080           # LSM allows bind to port 8080
│   └── bind_block_privileged          # LSM denies bind to port < 1024
├── test_cgroup_identity.c
│   ├── cgroup_a_sees_set_a            # pod in cgroup A resolves CIDR set A
│   ├── cgroup_b_cannot_see_set_a      # pod in cgroup B does not
│   ├── cgroup_add_remove              # dynamic cgroup registration
│   └── cgroup_concurrent              # 100 cgroups, concurrent add/del
├── test_conntrack.c
│   ├── ct_established_refresh         # keep-state refreshes expiry
│   ├── ct_udp_timeout_short           # UDP 30s, TCP 3600s
│   └── ct_overflow_eviction           # LRU eviction at 65536 entries
├── test_dnat.c
│   ├── dnat_single_port               # rdr port 80 → 10.0.0.5:8080
│   ├── dnat_port_range                # rdr port 8000:9000 → 10.0.0.5:*
│   └── dnat_no_match_passthrough      # no DNAT for non-matching packets
├── test_snat.c
│   ├── snat_lpm_prefix                # SNAT with LPM prefix match
│   ├── snat_checksum_update           # IP+TCP checksum correct after SNAT
│   └── snat_source_port_randomization # ephemeral port selection
├── test_events.c
│   ├── event_drop_ringbuf             # drop generates ring buffer event
│   ├── event_conntrack_new            # new flow → conntrack event
│   └── event_conntrack_expire         # expiry → conntrack event
└── test_policy_compile.ml             # OCaml tests: policy → BPF plan
    ├── compile_networkpolicy_yaml      # K8s NP → .lpf → BPF plan
    ├── compile_nomad_network_stanza    # Nomad → .lpf → BPF plan
    ├── compile_cluster_policy          # ClusterPolicy → BPF plan
    ├── compile_pod_annotation          # Pod annotation → BPF plan
    ├── compile_idempotent              # Same policy → same checksum
    ├── compile_error_handling          # Invalid policy → descriptive error
    └── compile_formal_verification     # Z3: no two rules contradict
```

### 7.3 Layer 1 — Docker sandbox integration

**Tooling**: Docker containers (privileged, with BPF caps).  Each test:

1. Builds `lpf-cni` image: `docker build -f Dockerfile.cni -t lpf-cni:test .`
2. Runs container with real cgroup, BPF, netns
3. Simulates CNI ADD/DEL calls inside container
4. Generates real traffic with `ncat`, `curl`, `iperf3`
5. Verifies policy enforcement via exit codes, ring-buffer events

**Test harness** (`ci/cni/cni-sandbox.sh`, ~200 lines):

```bash
#!/bin/bash
# cni-sandbox.sh — Layer 1 CNI integration tests in Docker

TEST_IMAGE="lpf-cni:test"
PASS=0; FAIL=0; TOTAL=0

run_test() {
  local name="$1" policy="$2" src_cidr="$3" dst_addr="$4" dst_port="$5" expect="$6"
  TOTAL=$((TOTAL+1))
  if docker run --rm --privileged \
    --cap-add BPF --cap-add NET_ADMIN --cap-add SYS_ADMIN \
    -v /sys/fs/bpf:/sys/fs/bpf \
    -e "LPF_TEST_POLICY=$policy" \
    -e "LPF_TEST_SRC=$src_cidr" \
    -e "LPF_TEST_DST=$dst_addr" \
    -e "LPF_TEST_DPORT=$dst_port" \
    "$TEST_IMAGE" ci/cni/test-case.sh "$expect"; then
    PASS=$((PASS+1)); echo "  PASS $name"
  else
    FAIL=$((FAIL+1)); echo "  FAIL $name"
  fi
}

# CNI ADD creates veth + IP + BPF attach, then sends probe traffic
run_test "allow: ingress port 80" \
  "pass in on eth0 proto tcp from any to any port 80" \
  "10.42.0.2/32" "10.42.0.1" "80" "PASS"

run_test "block: ingress port 22" \
  "block in on eth0 proto tcp from any to any port 22" \
  "10.42.0.2/32" "10.42.0.1" "22" "DROP"

run_test "keep-state: outbound dns + return traffic" \
  "pass out on eth0 to any port 53 keep state pass in on eth0 from any to any keep state" \
  "10.42.0.2/32" "10.43.0.10" "53" "PASS"

run_test "DNAT: rdr port 80 -> 8080" \
  "rdr on eth0 proto tcp from any to any port 80 -> 10.42.0.3 port 8080" \
  "10.42.0.2/32" "10.42.0.4" "80" "DNAT"

run_test "cgroup identity: pod-A blocked from pod-B CIDR set" \
  "table <set-a> { 10.42.1.0/24 } pass in on eth0 proto tcp from any to any port 443 block in on eth0 proto tcp from <set-a> to any" \
  "10.42.2.5/32" "10.42.0.1" "443" "PASS"

echo "=== $PASS/$TOTAL passed, $FAIL failed ==="
exit $FAIL
```

### 7.4 Layer 2 — k3s cluster E2E

**Tooling**: [k3d](https://k3d.io/) or `k3s` binary.  Single-node cluster with lpf CNI
installed.  Real Kubernetes API, real pods, real `kubectl`.

**Setup** (`ci/cni/k3s-e2e.sh`):

```bash
#!/bin/bash
# k3s-e2e.sh — Layer 2 k3s cluster with lpf CNI

set -euo pipefail

# 1. Create k3s cluster with lpf as default CNI
k3d cluster create lpf-cni-test \
  --k3s-arg "--flannel-backend=none@server:0" \
  --k3s-arg "--disable-network-policy@server:0" \
  --volume "$(pwd)/ci/cni/lpf-cni-install.sh:/var/lib/rancher/k3s/server/manifests/lpf-cni.yaml"

# 2. Wait for lpf-daemon DaemonSet to be ready
kubectl wait --for=condition=ready pod -n kube-system -l app=lpf-daemon --timeout=120s

# 3. Apply cluster-wide policy
kubectl apply -f ci/cni/test-policies/cluster-deny.yaml

# 4. Deploy test workloads
kubectl create ns tenant-a
kubectl create ns tenant-b

kubectl run web --image=nginx:alpine --port=80 -n tenant-a
kubectl run db --image=postgres:16-alpine --port=5432 -n tenant-a
kubectl run attacker --image=alpine/curl -n tenant-b -- sleep 3600

kubectl wait --for=condition=ready pod web db attacker --timeout=60s

# 5. Test connectivity
WEB_IP=$(kubectl get pod web -n tenant-a -o jsonpath='{.status.podIP}')
DB_IP=$(kubectl get pod db -n tenant-a -o jsonpath='{.status.podIP}')
ATTACKER_POD=$(kubectl get pod attacker -n tenant-b -o jsonpath='{.metadata.name}')

# Allow: web → db:5432 should work
kubectl exec "$ATTACKER_POD" -n tenant-b -- \
  timeout 5 wget -q -O- "http://${WEB_IP}" && echo "PASS: web reachable" || echo "FAIL: web reachable"

# Block: attacker → db:5432 should be denied
kubectl exec "$ATTACKER_POD" -n tenant-b -- \
  timeout 5 nc -zv "$DB_IP" 5432 && echo "FAIL: db reachable from attacker" || echo "PASS: db blocked"

# 6. Test lpf-specific features: RDR, QoS, keep-state
# ...

# 7. Validate ring-buffer events
kubectl logs -n kube-system daemonset/lpf-daemon | grep -c '"verdict":"DROP"'

# 8. Test policy update (rolling change)
kubectl apply -f ci/cni/test-policies/cluster-allow-db-from-web.yaml
sleep 5
kubectl exec web -n tenant-a -- timeout 3 nc -zv "$DB_IP" 5432 && echo "PASS: web→db after update" || echo "FAIL"

# 9. Test CNI DEL (pod deletion + recreation keeps policy)
kubectl delete pod web -n tenant-a
kubectl wait --for=condition=ready pod web -n tenant-a --timeout=30s
NEW_WEB_IP=$(kubectl get pod web -n tenant-a -o jsonpath='{.status.podIP}')
# Policy should still apply to new pod

echo "=== k3s E2E complete ==="
```

**Test policy files** (`ci/cni/test-policies/`):

```
cluster-deny.yaml            → .lpf: set default deny, allow dns+node
cluster-allow-db-from-web.yaml → .lpf: pass from <web> to <db> port 5432
namespace-tenant-a.yaml
namespace-tenant-b.yaml
nomad-equivalent.hcl          → .lpf translated
k8s-networkpolicy-golden.yaml → NetworkPolicy → .lpf round-trip test
invalid-policy.yaml           → .lpf parse error, expect validation failure
```

### 7.5 Layer 3 — Multi-node k8s cluster E2E

**Tooling**: [kind](https://kind.sigs.k8s.io/) 3-node cluster.

**Setup**:

```yaml
# ci/cni/kind-config.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
  - role: worker
networking:
  disableDefaultCNI: true
  podSubnet: "10.42.0.0/16"
```

**Tests** (multi-node specific):

| Test | Description |
|------|-------------|
| **Cross-node pod-to-pod** | Pod on worker-0 → pod on worker-1, policy enforced on both ingress/egress |
| **Cross-node SNAT** | Pod on worker-0 → external internet, source IP rewritten to node IP |
| **Cross-node DNAT** | NodePort: external → node IP:NodePort → pod IP:targetPort via DNAT |
| **Policy propagation latency** | Create policy → measure time until all nodes enforce it (target: < 5s) |
| **Node failure** | Kill worker-1, verify worker-0 pods still enforce policy (no cascading failure) |
| **DaemonSet restart** | Rolling restart lpf-daemon, verify 0 dropped packets during restart |
| **500-pod stress** | Deploy 500 pods across 3 nodes, verify policy correctly applied to all |
| **Ring buffer backpressure** | Generate 100K drops/sec, verify no ring-buffer event loss |
| **Prometheus metrics** | Verify `lpf_drops_total{rule="block-ssh"}`, `lpf_conntrack_entries` |
| **BPF map memory** | 500 pods → CIDR map growth bounded, conntrack LRU eviction working |

**Chaos tests**:

| Test | Description |
|------|-------------|
| **Network partition** | iptables DROP between worker-0 and worker-1, verify lpf-daemon reconnects, policy stale but still enforced |
| **Disk full** | Fill `/sys/fs/bpf`, verify graceful degradation (not kernel panic) |
| **Rapid pod churn** | Create/destroy 50 pods/second for 60 seconds, verify no leaked cgroups, no leaked BPF maps |
| **Policy loop** | Policy that blocks lpf-daemon's own API traffic — verify it can't self-block (reserved rule priority) |
| **Memory pressure** | Node with 128MB free, deploy 100 pods, verify OOM kills pods not lpf-daemon |

### 7.6 Layer 4 — Nomad E2E

**Tooling**: Nomad dev agent + Docker task driver.

```bash
#!/bin/bash
# ci/cni/nomad-e2e.sh

# Start Nomad in dev mode with lpf CNI
nomad agent -dev \
  -config ci/cni/nomad-lpf.hcl &

# Submit test jobs
nomad run ci/cni/test-jobs/web-server.nomad
nomad run ci/cni/test-jobs/database.nomad
nomad run ci/cni/test-jobs/attacker.nomad

# Verify policy enforcement (same assertions as k8s, different API)
nomad alloc exec -task web curl -s http://db.local:5432 && echo "PASS" || echo "BLOCKED"
```

### 7.7 CI Pipeline Integration

```
┌──────────────────────────────────────────────────────────┐
│  GitHub Actions / Jenkins (per commit)                    │
│                                                          │
│  Layer 0 (5s)      BPF conformance + OCaml unit tests     │
│  ─────────────────────────────────────                    │
│  Layer 1 (30s)     Docker sandbox CNI ADD/DEL/traffic     │
│  ─────────────────────────────────────                    │
│  Layer 2 (5min)    k3s cluster E2E (10 tests)             │
│  ─────────────────────────────────────                    │
│  Layer 3 (20min)   kind 3-node E2E + chaos (PR only)      │
│  ─────────────────────────────────────                    │
│  Layer 4 (15min)   Nomad E2E (PR only)                    │
│                                                          │
│  Nightly:           500-pod stress, 1hr soak, fuzzing     │
│  Release-blocking:  Layer 0-2 must pass. Layer 3-4 must   │
│                     pass + benchmark regression check.    │
└──────────────────────────────────────────────────────────┘
```

### 7.8 Performance benchmarks (CI-gated)

Run on every PR against `main`.  Regression threshold: ±5%.

| Benchmark | Tool | Metric | Baseline (target) |
|-----------|------|--------|-------------------|
| cgroup/skb allow (fastpath) | `iperf3` | Gbps | ≥ 9.4 (line rate 10G) |
| cgroup/skb deny (cold) | `iperf3` | kpps | ≥ 1000 |
| LSM connect allow | `sockperf` | conn/s | ≥ 100K |
| LSM connect deny | `sockperf` | conn/s | ≥ 100K |
| Policy compile (100 rules) | wall clock | ms | ≤ 200 |
| CNI ADD (cold) | pod start latency | ms | ≤ 100 |
| CNI ADD (warm, cached BPF) | pod start latency | ms | ≤ 50 |
| CNI DEL | pod stop latency | ms | ≤ 20 |
| CIDR set update (100 IPs) | map update | μs | ≤ 500 |

---

## 8. Files to Create

```
bpf/
  lpf_kern_cni.c               # CNI-specific BPF program extensions
                                 # (L4-only cgroup variant, lighter than full XDP+TC)

ci/cni/
  Dockerfile.cni                # Builds lpf-cni + lpf-daemon container
  cni-sandbox.sh                # Layer 1 test harness
  cni-sandbox-entrypoint.sh     # Per-test execution inside Docker
  k3s-e2e.sh                    # Layer 2 k3s cluster tests
  k3s-cni-install.yaml          # k3s manifest: lpf-daemon DaemonSet + config
  kind-config.yaml              # kind 3-node cluster config
  kind-e2e.sh                   # Layer 3 kind cluster tests
  nomad-e2e.sh                  # Layer 4 Nomad tests
  nomad-lpf.hcl                 # Nomad CNI plugin config
  benchmark.sh                  # Performance regression suite
  test-policies/
    cluster-deny.lpf
    cluster-allow-db.lpf
    namespace-tenant-a.lpf
    namespace-tenant-b.lpf
    k8s-networkpolicy-input.yaml
    k8s-networkpolicy-expected.lpf
    nomad-network-input.hcl
    nomad-network-expected.lpf
    invalid-policy.lpf
  test-jobs/
    web-server.nomad
    database.nomad
    attacker.nomad
    web-server.yaml (k8s)
    database.yaml (k8s)
    attacker.yaml (k8s)

lib/
  cni.ml                        # CNI protocol handler
  cni.mli
  network_policy_translate.ml   # K8s NetworkPolicy → .lpf translator
  network_policy_translate.mli
  nomad_policy_translate.ml     # Nomad network stanza → .lpf translator
  nomad_policy_translate.mli
  lpf_daemon.ml                 # Per-node policy agent
  lpf_daemon.mli

bin/
  cni/
    main.ml                     # lpf-cni entry point (ADD/DEL/CHECK)
    dune                        # Build lpf-cni binary + container image
  daemon/
    main.ml                     # lpf-daemon entry point
    dune

test/
  test_cni_unit.ml              # OCaml CNI protocol tests
  test_cni_bpf/                 # BPF_PROG_TEST_RUN C tests
    test_cgroup_ingress.c
    test_cgroup_egress.c
    test_lsm_connect.c
    test_lsm_bind.c
    test_cgroup_identity.c
    test_conntrack.c
    test_dnat.c
    test_snat.c
    test_events.c
    Makefile                    # Build+run BPF conformance suite
  test_network_policy_translate.ml    # K8s NetworkPolicy → .lpf tests
  test_nomad_policy_translate.ml      # Nomad → .lpf tests
  test_lpf_daemon_unit.ml             # Daemon unit tests

docs/
  cni-spec.md                   # This document
  cni-architecture.svg          # Architecture diagram

packaging/
  k8s/
    lpf-cni-daemonset.yaml      # lpf-daemon DaemonSet
    lpf-cni-configmap.yaml      # Cluster policy config
    lpf-cni-crd.yaml            # (optional) LpfPolicy CRD
```

---

## 9. Implementation Phases

### Phase 1 — Foundation (2 weeks)
- [ ] `bin/cni/main.ml`: CNI ADD/DEL/CHECK handler with veth+IPAM
- [ ] `lib/cni.ml`: CNI protocol wire format (JSON config parse)
- [ ] `Dockerfile.cni`: Container image build
- [ ] `ci/cni/cni-sandbox.sh`: Layer 1 test harness
- [ ] `test/cni_bpf/test_cgroup_ingress.c`: 6 BPF conformance tests
- [ ] All existing `lpf_kern.c` cgroup hooks verified against CNI usage

### Phase 2 — Policy engine (2 weeks)
- [ ] `lib/network_policy_translate.ml`: K8s NetworkPolicy → .lpf
- [ ] `lib/nomad_policy_translate.ml`: Nomad → .lpf
- [ ] `lib/lpf_daemon.ml`: Policy watch, recompilation, map sync
- [ ] BPF cgroup identity map population (lpf_cgroup)
- [ ] `packaging/k8s/lpf-cni-daemonset.yaml`

### Phase 3 — Cluster integration (2 weeks)
- [ ] `ci/cni/k3s-e2e.sh`: Layer 2 tests
- [ ] `ci/cni/kind-e2e.sh`: Layer 3 multi-node tests
- [ ] Ring-buffer relay → JSON logs + Prometheus metrics
- [ ] gRPC health check endpoint

### Phase 4 — Hardening (2 weeks)
- [ ] `ci/cni/nomad-e2e.sh`: Layer 4 tests
- [ ] 500-pod stress + chaos tests
- [ ] `ci/cni/benchmark.sh`: Performance regression suite
- [ ] Formal verification pipeline: Z3 policy consistency proofs
- [ ] Atomic map swap at per-pod granularity

### Phase 5 — Production readiness (2 weeks)
- [ ] IPv6 conntrack
- [ ] DNS-based identity (lpf_dns map)
- [ ] Policy audit mode (shadow counting)
- [ ] Bandwidth enforcement
- [ ] IPFIX/sFlow export
- [ ] OpenTelemetry traces from ring-buffer events

---

## 10. Differences from Existing CNIs

| Feature | lpf CNI | Cilium | Calico | Antrea |
|---------|---------|--------|--------|--------|
| K8s support | yes | yes | yes | yes |
| Nomad support | **yes** | no | yes (iptables) | no |
| Policy language | **.lpf (PF-style)** | NetworkPolicy + CiliumNetworkPolicy | NetworkPolicy + CalicoNetworkPolicy | NetworkPolicy + AntreaNetworkPolicy |
| eBPF datapath | cgroup/skb + LSM + XDP (optional) | XDP + TC + cgroup | eBPF (k8s only) | OVS userspace |
| Formal verification | **Z3 (policy contradictions, shadow detection)** | no | no | no |
| Per-pod attachment | **cgroup_id** | endpoint ID | iptables per-host | OVS flow per-pod |
| Atomic policy swap | **BPF map swap** | endpoint regeneration | iptables-restore | OVS flow mod |
| Dry-run / diff | **lpf diff, lpf plan --dry-run** | cilium connectivity test | calicoctl ipam check | antreactl trace-packet |
| Conntrack | LRU hash in BPF | CT map in BPF | conntrack iptables | conntrack OVS |
| CIDR sets | LPM trie | LPM in BPF | ipset | OVS group |
| DNS identity | **planned (lpf_dns map)** | yes (FQDN policy) | yes (network sets) | no |
| Service LB | planned (v2) | yes (kube-proxy replacement) | yes (eBPF DS) | yes (AntreaProxy) |
| Bandwidth QoS | planned | yes (EDT) | no | no |
| Multi-arch image | **OCaml native + BPF CO-RE** | Go + BPF CO-RE | Go + BPF CO-RE | Go + OVS |
