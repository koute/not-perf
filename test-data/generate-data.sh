#!/bin/bash

unset LD_PRELOAD
set -euo pipefail

function generate_test_ex {
    local TEST=$1
    local OUTPUT_NAME=$2
    local EXTRA_ARGS=$3

    if [ -e "artifacts/$PREFIX-$OUTPUT_NAME.nperf" ]; then
        return
    fi

    PENDING=1
    echo "./$PREFIX-$TEST &" >> "$WORKDIR/script.sh"
    echo "PID=\$!" >> "$WORKDIR/script.sh"
    echo "./$PREFIX-nperf record -F 100 --sample-count 200 -s sw_cpu_clock -P $PREFIX-$TEST -w -o /output/$PREFIX-$OUTPUT_NAME.nperf $EXTRA_ARGS" >> "$WORKDIR/script.sh"
    echo "kill \$PID" >> "$WORKDIR/script.sh"
    echo "wait \$PID" >> "$WORKDIR/script.sh"
}

function generate_test {
    generate_test_ex $1 $1 "--offline"
}

function generate {
    PREFIX=$1
    PENDING=0

    WORKDIR=../target/qemu/$PREFIX
    mkdir -p "$WORKDIR"
    WORKDIR=$(realpath $WORKDIR)

    echo "#!/bin/sh" > "$WORKDIR/script.sh"
    echo "cd /input" >> "$WORKDIR/script.sh"

    generate_test "usleep_in_a_loop_fp"
    generate_test "usleep_in_a_loop_no_fp"
    generate_test "usleep_in_a_loop_external_info"
    generate_test "pthread_cond_wait"
    generate_test "inline_functions"
    generate_test "noreturn"

    if [[ "$PREFIX" = "amd64" ]]; then
        generate_test_ex "usleep_in_a_loop_no_fp" "usleep_in_a_loop_no_fp_online" ""
    fi

    local EXTRA_ARGS=""
    for FILE in bin/$PREFIX-*; do
        local EXTRA_ARGS="$EXTRA_ARGS -i $FILE"
    done

    if [[ "$PENDING" = "0" ]]; then
        return
    fi

    tools/qemurun.sh -w "$WORKDIR" -a $PREFIX -o artifacts $EXTRA_ARGS "$WORKDIR/script.sh"
}

generate amd64
generate arm
generate mips64
