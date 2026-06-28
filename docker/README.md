# lpf Docker images

Multi-architecture Dockerfiles for building, testing, deploying, and
developing `lpf` across Linux distributions.

## Images

| Dockerfile | Purpose | Base | Distros |
|---|---|---|---|
| `runtime.Dockerfile` | Production runtime | `ubuntu:22.04` | ubuntu |
| `ebpf.Dockerfile` | eBPF datapath dev + test | `ocaml/opam:debian-12` | debian |
| `rootfs.Dockerfile` | Firecracker microVM rootfs | `ocaml/opam:debian-12` | debian |

The root `Dockerfile` and `Dockerfile.ci` at the repo root are the
canonical files referenced by CI pipelines and Makefile targets.

## Usage

### Runtime image (production)

```sh
docker build -f docker/runtime.Dockerfile -t lpf:latest .
docker run --rm --privileged lpf help
```

### CI image (5-distro test matrix)

```sh
# Build for each distro
for distro in debian ubuntu-22 ubuntu-24 alpine fedora; do
  docker build -f Dockerfile.ci \
    --build-arg BASE=ocaml/opam:${distro}-ocaml-5.1 \
    -t lpf-ci:${distro} .
done

# Run feature suite on each
docker run --rm lpf-ci:debian \
  bash -lc "cd /home/opam/src && ci/vagabond/feature-suite.sh"
```

### eBPF development image

```sh
docker build -f docker/ebpf.Dockerfile -t lpf-ebpf:latest .
docker run --rm --privileged \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  lpf-ebpf:latest \
  bash -lc "cd /home/opam/src && ci/vagabond/ebpf-suite.sh"
```

### Firecracker rootfs

```sh
# Build and export rootfs
docker build -f docker/rootfs.Dockerfile -t lpf-rootfs:latest .
docker export $(docker create lpf-rootfs:latest) | gzip > lpf-rootfs.tar.gz

# Use with Vagabond
vagabondRun(
  image: 'lpf-ci:debian',
  runtime: 'nomad.firecracker',
  kernel: '/images/vmlinux-6.1',
  rootfs: '/images/lpf-rootfs.tar.gz',
  command: ['bash', '-lc', 'ci/vagabond/ebpf-suite.sh']
)
```

## Root-level CI image

`Dockerfile.ci` at the repo root is the canonical CI image referenced by
all pipelines, Makefile targets, and Jenkins jobs.
