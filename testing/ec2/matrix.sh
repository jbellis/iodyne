#!/usr/bin/env bash
set -euo pipefail

REGION="${AWS_REGION:-us-east-2}"
INSTANCE_TYPE="${IODYNE_EC2_INSTANCE_TYPE:-t3.medium}"
DISTRO_LIST="${IODYNE_EC2_DISTROS:-rhel-9 ubuntu-22.04 debian-12 ubuntu-24.04}"
PROJECT_TAG="iodyne-kernel-matrix"
OWNER_TAG="${IODYNE_EC2_OWNER:-codex}"
STATE_ROOT="${XDG_STATE_HOME:-$HOME/.local/state}/iodyne/ec2"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ACTIVE_RUN_ID=""
KEEP_RESOURCES=0

usage() {
    cat <<'EOF'
Usage:
  testing/ec2/matrix.sh all [--keep]
  testing/ec2/matrix.sh up
  testing/ec2/matrix.sh run RUN_ID
  testing/ec2/matrix.sh status RUN_ID
  testing/ec2/matrix.sh down RUN_ID

Environment:
  AWS_REGION                  AWS region (default: us-east-2)
  IODYNE_EC2_INSTANCE_TYPE    Spot instance type (default: t3.medium)
  IODYNE_EC2_DISTROS          Space-delimited guest subset
  IODYNE_EC2_OWNER            Resource Owner tag (default: codex)
  XDG_STATE_HOME              Local keys/results root; never stored in git
EOF
}

need() {
    command -v "$1" >/dev/null || {
        echo "missing required command: $1" >&2
        exit 1
    }
}

aws_cli() {
    aws --region "$REGION" "$@"
}

new_run_id() {
    printf '%s-%s\n' "$(date -u +%Y%m%dT%H%M%SZ)" "$(printf '%04x' "$((RANDOM % 65536))")"
}

run_dir() {
    printf '%s/%s\n' "$STATE_ROOT" "$1"
}

key_name() {
    printf 'iodyne-matrix-%s\n' "$1"
}

security_group_name() {
    printf 'iodyne-matrix-%s\n' "$1"
}

resolve_ami() {
    case "$1" in
        ubuntu-22.04)
            aws_cli ssm get-parameter \
                --name /aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id \
                --query Parameter.Value --output text
            ;;
        ubuntu-24.04)
            aws_cli ssm get-parameter \
                --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id \
                --query Parameter.Value --output text
            ;;
        debian-12)
            aws_cli ssm get-parameter \
                --name /aws/service/debian/release/12/latest/amd64 \
                --query Parameter.Value --output text
            ;;
        rhel-9)
            aws_cli ec2 describe-images \
                --owners 309956199498 \
                --filters \
                    'Name=name,Values=RHEL-9.*_HVM-*-x86_64-*-Hourly2-GP3' \
                    'Name=architecture,Values=x86_64' \
                    'Name=state,Values=available' \
                --query 'Images[].[ImageId,Name,CreationDate]' \
                --output text \
                | sort -t $'\t' -k2,2V -k3,3 \
                | tail -n 1 \
                | cut -f1
            ;;
        *)
            echo "unknown distro: $1" >&2
            return 1
            ;;
    esac
}

ssh_user() {
    case "$1" in
        ubuntu-*) printf 'ubuntu\n' ;;
        debian-*) printf 'admin\n' ;;
        rhel-*) printf 'ec2-user\n' ;;
    esac
}

tag_spec() {
    local resource_type="$1" run_id="$2" name="$3"
    printf 'ResourceType=%s,Tags=[{Key=Project,Value=%s},{Key=Owner,Value=%s},{Key=ManagedBy,Value=iodyne-ec2-matrix},{Key=RunId,Value=%s},{Key=Name,Value=%s}]' \
        "$resource_type" "$PROJECT_TAG" "$OWNER_TAG" "$run_id" "$name"
}

launch() {
    local run_id="${1:-$(new_run_id)}"
    local dir key_file key sg_id vpc_id my_ip distro ami user instance_id root_device
    local -a distros
    dir="$(run_dir "$run_id")"
    key="$(key_name "$run_id")"
    key_file="$dir/$key.pem"
    mkdir -p "$dir/results"
    chmod 700 "$dir"
    printf '%s\n' "$run_id" >"$dir/run-id"
    git -C "$REPO_ROOT" rev-parse HEAD >"$dir/commit"

    if ! git -C "$REPO_ROOT" diff --quiet || ! git -C "$REPO_ROOT" diff --cached --quiet; then
        echo "working tree has tracked changes; commit them before launching a reproducible matrix" >&2
        return 1
    fi

    umask 077
    aws_cli ec2 create-key-pair \
        --key-name "$key" \
        --key-type ed25519 \
        --tag-specifications "$(tag_spec key-pair "$run_id" "$key")" \
        --query KeyMaterial --output text >"$key_file"
    chmod 600 "$key_file"

    vpc_id="$(aws_cli ec2 describe-vpcs --filters Name=is-default,Values=true --query 'Vpcs[0].VpcId' --output text)"
    my_ip="$(curl -fsS https://checkip.amazonaws.com | tr -d '[:space:]')"
    sg_id="$(aws_cli ec2 create-security-group \
        --group-name "$(security_group_name "$run_id")" \
        --description "Temporary SSH for iodyne kernel matrix $run_id" \
        --vpc-id "$vpc_id" \
        --tag-specifications "$(tag_spec security-group "$run_id" "$(security_group_name "$run_id")")" \
        --query GroupId --output text)"
    aws_cli ec2 authorize-security-group-ingress \
        --group-id "$sg_id" --protocol tcp --port 22 --cidr "$my_ip/32" >/dev/null
    printf '%s\n' "$sg_id" >"$dir/security-group-id"

    read -r -a distros <<<"$DISTRO_LIST"
    : >"$dir/instances.tsv"
    for distro in "${distros[@]}"; do
        ami="$(resolve_ami "$distro")"
        user="$(ssh_user "$distro")"
        root_device="$(aws_cli ec2 describe-images --image-ids "$ami" \
            --query 'Images[0].RootDeviceName' --output text)"
        echo "launching $distro ($ami) as a $INSTANCE_TYPE spot instance"
        instance_id="$(aws_cli ec2 run-instances \
            --image-id "$ami" \
            --instance-type "$INSTANCE_TYPE" \
            --key-name "$key" \
            --security-group-ids "$sg_id" \
            --associate-public-ip-address \
            --instance-market-options 'MarketType=spot,SpotOptions={SpotInstanceType=one-time,InstanceInterruptionBehavior=terminate}' \
            --block-device-mappings "DeviceName=$root_device,Ebs={VolumeSize=20,VolumeType=gp3,DeleteOnTermination=true}" \
            --tag-specifications \
                "$(tag_spec instance "$run_id" "iodyne-$distro-$run_id")" \
                "$(tag_spec volume "$run_id" "iodyne-$distro-$run_id")" \
            --query 'Instances[0].InstanceId' --output text)"
        printf '%s\t%s\t%s\t%s\n' "$distro" "$instance_id" "$user" "$ami" >>"$dir/instances.tsv"
    done

    mapfile -t instance_ids < <(cut -f2 "$dir/instances.tsv")
    aws_cli ec2 wait instance-running --instance-ids "${instance_ids[@]}"
    aws_cli ec2 wait instance-status-ok --instance-ids "${instance_ids[@]}"
    echo "run ID: $run_id"
}

instance_ip() {
    aws_cli ec2 describe-instances --instance-ids "$1" \
        --query 'Reservations[0].Instances[0].PublicIpAddress' --output text
}

wait_for_ssh() {
    local key_file="$1" user="$2" ip="$3" known_hosts="$4"
    local attempt
    for attempt in $(seq 1 60); do
        if ssh -i "$key_file" \
            -o BatchMode=yes -o ConnectTimeout=5 \
            -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$known_hosts" \
            "$user@$ip" true 2>/dev/null; then
            return 0
        fi
        sleep 5
    done
    echo "SSH did not become ready for $user@$ip" >&2
    return 1
}

run_host() {
    local run_id="$1" distro="$2" instance_id="$3" user="$4" ami="$5"
    local dir key_file known_hosts ip archive log remote
    dir="$(run_dir "$run_id")"
    key_file="$dir/$(key_name "$run_id").pem"
    known_hosts="$dir/known_hosts"
    archive="$dir/iodyne-$(cat "$dir/commit").tar.gz"
    log="$dir/results/$distro.log"
    remote="$user@$(instance_ip "$instance_id")"
    ip="${remote#*@}"

    {
        printf 'distro=%s\ninstance=%s\nami=%s\nip=%s\n\n' "$distro" "$instance_id" "$ami" "$ip"
        wait_for_ssh "$key_file" "$user" "$ip" "$known_hosts"
        scp -i "$key_file" -o BatchMode=yes \
            -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$known_hosts" \
            "$archive" "$SCRIPT_DIR/remote-test.sh" "$remote:/tmp/"
        set +e
        ssh -i "$key_file" -o BatchMode=yes \
            -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$known_hosts" \
            "$remote" "bash /tmp/remote-test.sh '$distro' '$run_id' '/tmp/$(basename "$archive")' prepare-kernel"
        prepare_rc=$?
        set -e
        if ((prepare_rc == 10)); then
            echo "rebooting $distro into its target kernel"
            ssh -i "$key_file" -o BatchMode=yes \
                -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$known_hosts" \
                "$remote" "sudo reboot" >/dev/null 2>&1 || true
            sleep 10
            wait_for_ssh "$key_file" "$user" "$ip" "$known_hosts"
            # Ubuntu cloud images clear /tmp during reboot.
            scp -i "$key_file" -o BatchMode=yes \
                -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$known_hosts" \
                "$archive" "$SCRIPT_DIR/remote-test.sh" "$remote:/tmp/"
            ssh -i "$key_file" -o BatchMode=yes \
                -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$known_hosts" \
                "$remote" "bash /tmp/remote-test.sh '$distro' '$run_id' '/tmp/$(basename "$archive")' prepare-kernel"
        elif ((prepare_rc != 0)); then
            return "$prepare_rc"
        fi
        ssh -i "$key_file" -o BatchMode=yes \
            -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$known_hosts" \
            "$remote" "bash /tmp/remote-test.sh '$distro' '$run_id' '/tmp/$(basename "$archive")' test"
    } >"$log" 2>&1
}

run_matrix() {
    local run_id="$1" dir archive distro instance_id user ami
    local -a pids=() names=()
    local failures=0 index
    dir="$(run_dir "$run_id")"
    test -f "$dir/instances.tsv" || {
        echo "unknown run ID or missing local state: $run_id" >&2
        return 1
    }
    archive="$dir/iodyne-$(cat "$dir/commit").tar.gz"
    if [[ ! -f "$archive" ]]; then
        git -C "$REPO_ROOT" archive --format=tar.gz -o "$archive" "$(cat "$dir/commit")"
    fi

    while IFS=$'\t' read -r distro instance_id user ami; do
        echo "starting matrix on $distro ($instance_id)"
        run_host "$run_id" "$distro" "$instance_id" "$user" "$ami" &
        pids+=("$!")
        names+=("$distro")
    done <"$dir/instances.tsv"

    for index in "${!pids[@]}"; do
        if wait "${pids[$index]}"; then
            echo "PASS ${names[$index]}"
        else
            echo "FAIL ${names[$index]} (see $dir/results/${names[$index]}.log)" >&2
            failures=$((failures + 1))
        fi
    done
    printf 'results: %s/results\n' "$dir"
    ((failures == 0))
}

status() {
    local run_id="$1"
    aws_cli ec2 describe-instances \
        --filters "Name=tag:Project,Values=$PROJECT_TAG" "Name=tag:RunId,Values=$run_id" \
        --query 'Reservations[].Instances[].{Name:Tags[?Key==`Name`]|[0].Value,Id:InstanceId,State:State.Name,IP:PublicIpAddress,Spot:InstanceLifecycle}' \
        --output table
}

down() {
    local run_id="$1" dir sg_id key
    local -a instance_ids=()
    dir="$(run_dir "$run_id")"
    key="$(key_name "$run_id")"
    mapfile -t instance_ids < <(aws_cli ec2 describe-instances \
        --filters "Name=tag:Project,Values=$PROJECT_TAG" "Name=tag:RunId,Values=$run_id" \
            Name=instance-state-name,Values=pending,running,stopping,stopped \
        --query 'Reservations[].Instances[].InstanceId' --output text | tr '\t' '\n' | sed '/^$/d')
    if ((${#instance_ids[@]})); then
        echo "terminating ${instance_ids[*]}"
        aws_cli ec2 terminate-instances --instance-ids "${instance_ids[@]}" >/dev/null
        aws_cli ec2 wait instance-terminated --instance-ids "${instance_ids[@]}"
    fi
    aws_cli ec2 delete-key-pair --key-name "$key" >/dev/null 2>&1 || true
    if [[ -f "$dir/security-group-id" ]]; then
        sg_id="$(cat "$dir/security-group-id")"
    else
        sg_id="$(aws_cli ec2 describe-security-groups \
            --filters "Name=tag:Project,Values=$PROJECT_TAG" "Name=tag:RunId,Values=$run_id" \
            --query 'SecurityGroups[0].GroupId' --output text)"
    fi
    if [[ -n "${sg_id:-}" && "$sg_id" != "None" ]]; then
        aws_cli ec2 delete-security-group --group-id "$sg_id" >/dev/null 2>&1 || true
    fi
    rm -f "$dir/$key.pem" "$dir/known_hosts"
    echo "resources for $run_id removed; results retained in $dir/results"
}

cleanup_active_run() {
    local rc=$?
    trap - EXIT INT TERM
    if [[ -n "$ACTIVE_RUN_ID" ]] && ((KEEP_RESOURCES == 0)); then
        down "$ACTIVE_RUN_ID" || true
    fi
    exit "$rc"
}

main() {
    local action="${1:-}" run_id rc=0
    need aws
    need curl
    need git
    need ssh
    need scp
    case "$action" in
        all)
            [[ "${2:-}" == "--keep" ]] && KEEP_RESOURCES=1
            run_id="$(new_run_id)"
            ACTIVE_RUN_ID="$run_id"
            trap cleanup_active_run EXIT
            trap 'exit 130' INT TERM
            launch "$run_id"
            run_matrix "$run_id" || rc=$?
            return "$rc"
            ;;
        up)
            launch
            ;;
        run|status|down)
            run_id="${2:-}"
            [[ -n "$run_id" ]] || { usage >&2; return 2; }
            "$action" "$run_id"
            ;;
        *)
            usage >&2
            return 2
            ;;
    esac
}

main "$@"
