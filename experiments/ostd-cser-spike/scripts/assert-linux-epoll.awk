# Validate the exact retained Round 5 epoll/readiness execution trace.
#
# The guest program is fixed input, so the bounded runner must produce one
# deterministic semantic receipt for each Linux operation.  Scheduler trace
# noise is ignored; every epoll/readiness receipt is ordered and exact.

function fail(message) {
    print "linux epoll assertion failed at serial line " NR ": " message > "/dev/stderr"
    failed = 1
    exit 1
}

function expect(line) {
    expected[++expected_count] = line
}

BEGIN {
    expect("LINUX_EPOLL_SLICE BEGIN workload=linux-round5-epoll format=ELF64 type=ET_EXEC adapted_regular_file_eperm=true registry=common readiness=kernel_owned smp=1")
    expect("LINUX_EPOLL Create epfd=3 ready_set=1:1 registry=true")
    expect("LINUX_EPOLL Pipe2 object=1 read_fd=4 write_fd=5 source=1:1")
    expect("LINUX_EPOLL Attach epfd=3 target_fd=4 subscription=1:1 source=1:1 mode=Edge cookie=0x11 sample_arm=atomic")
    expect("LINUX_EPOLL ReadyCommit wait_effect=6 delivery=1 sequence=1 count=1 timeout=-1 frozen=true")
    expect("LINUX_EPOLL ReadyCommit wait_effect=8 delivery=2 sequence=2 count=0 timeout=0 frozen=true")
    expect("LINUX_EPOLL Modify epfd=3 target_fd=4 subscription=1:2 mode=OneShot cookie=0x22 old_generation_rejected=true")
    expect("LINUX_EPOLL ReadyCommit wait_effect=11 delivery=3 sequence=3 count=1 timeout=-1 frozen=true")
    expect("LINUX_EPOLL ReadyCommit wait_effect=12 delivery=4 sequence=4 count=0 timeout=0 frozen=true")
    expect("LINUX_EPOLL SocketPair object=2 left_fd=6 right_fd=7 source_left=2:1 source_right=3:1")
    expect("LINUX_EPOLL Attach epfd=3 target_fd=6 subscription=2:1 source=2:1 mode=Level cookie=0x33 sample_arm=atomic")
    expect("LINUX_EPOLL ReadyCommit wait_effect=18 delivery=5 sequence=5 count=1 timeout=-1 frozen=true")
    expect("LINUX_EPOLL ReadyCommit wait_effect=19 delivery=6 sequence=6 count=1 timeout=0 frozen=true")
    expect("LINUX_EPOLL ReadyCommit wait_effect=21 delivery=7 sequence=7 count=0 timeout=0 frozen=true")
    expect("LINUX_EPOLL OpenArtifact fd=8 path=/bin/linux-hello readonly=true")
    expect("LINUX_EPOLL Ctl regular_file=true result=EPERM linux_compatible=true subscription_created=false")
    expect("LINUX_EPOLL stdout=round5 epoll ok")
    expect("LINUX_EPOLL GuestExit task=900 status=0 resumed_after_exit=false")
    expect("EFFECT_REGISTRY Quiescent workload=linux-round5-epoll live=0 pending_publications=0 subscriptions=0 queued=0 unpublished_deliveries=0 credits=Free")
    expect("LINUX_EPOLL_SLICE PASS workload=linux-round5-epoll adapted=true syscalls=23 pipe_et=true pipe_oneshot=true socket_lt=true regular_file_eperm=true sample_arm=atomic registry_quiescent=true")
}

{
    sub(/\r$/, "")
    relevant = ($0 ~ /^LINUX_EPOLL( |_)/ ||
                $0 ~ /^EFFECT_REGISTRY Quiescent workload=linux-round5-epoll /)
    if (!relevant)
        next

    observed++
    if (observed > expected_count)
        fail("unexpected additional receipt: " $0)
    if ($0 != expected[observed])
        fail("receipt #" observed " mismatch; expected: " expected[observed] "; observed: " $0)
}

END {
    if (failed)
        exit 1
    if (observed != expected_count)
        fail("expected " expected_count " receipts, observed " observed)
}
