#!/usr/bin/env python3
from __future__ import annotations
import json, os, socket, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from matrix_protocol import barrier
metrics = Path(os.environ["CSER_EXPERIMENT_GUEST_METRICS"])
metrics.write_text(json.dumps({"retired_by_evidence": 1, "retained_claims": 2, "gate_rejections": 3}), encoding="utf-8")
path = os.environ["CSER_EXPERIMENT_BARRIER_SOCKET"]
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
    server.bind(path); server.listen(1)
    with server.accept()[0] as client:
        target = int(os.environ["CSER_EXPERIMENT_CUTPOINT"])
        for cutpoint in range(1, target + 1):
            client.sendall(barrier(os.environ["CSER_EXPERIMENT_RUN_ID"], cutpoint))
            response = client.recv(1024)
            if cutpoint == target:
                # Target trials receive no ACK; a close is required before kill.
                assert response == b""
            else:
                assert response.startswith(b"CSER1 ACK ")
while True: time.sleep(1)
