# EC2 kernel compatibility matrix

This manually invoked release check exercises iodyne on four popular kernel
families in `us-east-2`:

| Guest | Expected kernel family |
|---|---|
| RHEL 9 | 5.14 |
| Ubuntu 22.04 LTS | 5.15 |
| Debian 12 | 6.1 |
| Ubuntu 24.04 LTS | 6.8 |

Each guest runs `iodyne --diag` in six modes: unprivileged and eBPF-enabled on
the bare guest, under Docker, and under Podman. The privileged checks require
the block-latency, base VFS, event-time path, FUSE requester, FUSE PID-zero
writeback, and OverlayFS collectors to be active.

Run the complete matrix with:

```sh
testing/ec2/matrix.sh all
```

To rerun only selected guests while developing a compatibility fix:

```sh
IODYNE_EC2_DISTROS='rhel-9 debian-12' testing/ec2/matrix.sh all
```

The harness uses `t3.medium` spot instances by default. It creates an ephemeral
EC2 key pair and an SSH security group restricted to the caller's current
public IP. Every AWS resource is tagged with `Project=iodyne-kernel-matrix`,
`ManagedBy=iodyne-ec2-matrix`, and a unique `RunId`. Instances, the EC2 key
pair, the local private key, and the security group are removed when `all`
finishes or fails. Logs remain outside the repository under
`$XDG_STATE_HOME/iodyne/ec2/<run-id>/results` (or
`~/.local/state/iodyne/ec2/...`). No AWS credentials or SSH keys are written to
the repository.

For debugging, keep resources temporarily or split the lifecycle into steps:

```sh
testing/ec2/matrix.sh all --keep
testing/ec2/matrix.sh up
testing/ec2/matrix.sh run RUN_ID
testing/ec2/matrix.sh status RUN_ID
testing/ec2/matrix.sh down RUN_ID
```

Always run `down` for a kept run. Tagged leftovers can be found even if the
local state directory is lost:

```sh
aws ec2 describe-instances --region us-east-2 \
  --filters Name=tag:Project,Values=iodyne-kernel-matrix
```

The AMIs are resolved from Canonical and Debian public SSM parameters and the
official Red Hat owner account at launch time. Because current Ubuntu cloud
images may move to newer enablement kernels, the harness explicitly installs,
boots, and verifies `linux-aws-5.15` on Ubuntu 22.04 and `linux-aws-6.8` on
Ubuntu 24.04 before testing. Debian 12 and RHEL 9 must already report their 6.1
and 5.14 vendor kernel families or the host fails.
