# NATrium-daemon
Simple and basic userspace NAT daemon meant to run on a pair of EC2 instances behind a GWLB.

It decapsulates GENEVE packets coming from the GWLB and attempts to do IP masquerade with their payload.

This is expected to be used in conjunction with NATrium-orchestrator, which runs on two instances and uses CRIU to checkpoint and restore this process with its open connections to the peer instance without any packet loss, and just some seconds of delay, in which it's buffering incoming connections..
