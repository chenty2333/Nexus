from __future__ import annotations
import hashlib, json, socket, sqlite3, subprocess, sys, tempfile, threading, unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
from handoff_identity import ParentDescriptorContext, child_transport_effect_id, expected_child_request, expected_source_request  # noqa: E402
from tool_provider import _child_descriptor_v1  # noqa: E402
from handoff_matrix_controller import _kill_container, _one_terminal, compare_recoveries, observe_handoff_barriers, validate_receipt, verify_endpoint_ledgers  # noqa: E402
from matrix_protocol import barrier, parse_config_hello  # noqa: E402
from summarize_handoff_metrics import summarize  # noqa: E402

RUN = "a" * 32
def receipt(**extra: object) -> dict[str, object]:
    value: dict[str, object] = {"version":1,"variant":"cser","run_id":RUN,"descriptor_digest":"b"*64,
        "parent_transferred":True,"child_installed":True,"child_intent":True,"child_terminal":True,
        "coordinate_gate":{"live_gate_observed":True,"reject_while_live":True,"admit_after_terminal":True,"revision_unchanged":True,"head_unchanged":True},
        "recovery_steps":2,"scope":"logical","device_actions":0}
    value.update(extra); return value

class HandoffMatrixTests(unittest.TestCase):
    def test_single_variant_summary_is_explicitly_partial(self) -> None:
        row = {"variant": "cser", "trial": 1, "cutpoint": "handoff_committed",
               "cutpoint_id": 24, "crash_method": "container_kill", "container_id": "a" * 64}
        with self.assertRaisesRegex(ValueError, "coverage differs"):
            summarize([row])
        summary = summarize([row], require_matched=False)
        self.assertFalse(summary["matched"])
        self.assertIn("not matched", summary["acceptance"])

    def test_strict_summary_requires_and_accepts_all_five_matched_cuts(self) -> None:
        rows = [
            {"variant": variant, "trial": 1, "cutpoint": cut, "cutpoint_id": cut_id,
             "crash_method": "container_kill", "container_id": f"{variant}-{cut_id}"}
            for variant in ("cser", "baseline")
            for cut, cut_id in (
                ("descriptor_discovered", 21),
                ("parent_ack_or_descriptor_durable", 22),
                ("child_installed", 23),
                ("handoff_committed", 24),
                ("child_first_observed", 25),
            )
        ]
        summary = summarize(rows)
        self.assertTrue(summary["matched"])
        self.assertEqual(summary["acceptance"], "matched 5 cuts x 2 variants")

    def test_strict_summary_rejects_non_container_crash_provenance(self) -> None:
        row = {"variant": "cser", "trial": 1, "cutpoint": "descriptor_discovered", "cutpoint_id": 21,
               "crash_method": "container_kill", "container_id": "a" * 64}
        for change in ({"crash_method": "pid_sigkill"}, {"container_id": None}, {"container_id": ""}):
            with self.subTest(change=change):
                invalid = row | change
                with self.assertRaisesRegex(ValueError, "container-kill provenance"):
                    summarize([invalid])

    def test_container_crash_uses_only_the_label_validated_recorded_cid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cid_path = Path(directory) / "container.cid"
            cid_path.write_text("a" * 64 + "\n", encoding="ascii")
            inspected = mock.Mock(returncode=0, stderr="", stdout=json.dumps({"nexus.cser-experiment": "handoff", "nexus.cser-run-id": RUN, "nexus.cser-trial-token": "b" * 64}))
            killed = mock.Mock(returncode=0, stderr="")
            with mock.patch("handoff_matrix_controller.subprocess.run", side_effect=[inspected, killed]) as run:
                self.assertEqual(_kill_container(cid_path, run_id=RUN, trial_token="b" * 64), "a" * 64)
            self.assertEqual(run.call_args_list[1].args[0], ["/usr/bin/docker", "kill", "a" * 64])
            cid_path.write_text("../../not-a-cid\n", encoding="ascii")
            with self.assertRaisesRegex(RuntimeError, "invalid container cid"):
                _kill_container(cid_path, run_id=RUN, trial_token="b" * 64)

    def test_missing_cid_discovers_only_one_exactly_labelled_handoff_container(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cid_path = Path(directory) / "missing.cid"
            discovered = mock.Mock(returncode=0, stderr="", stdout="c" * 64 + "\n")
            inspected = mock.Mock(returncode=0, stderr="", stdout=json.dumps({"nexus.cser-experiment": "handoff", "nexus.cser-run-id": RUN, "nexus.cser-trial-token": "b" * 64}))
            killed = mock.Mock(returncode=0, stderr="")
            with mock.patch("handoff_matrix_controller.subprocess.run", side_effect=[discovered, inspected, killed]) as run:
                self.assertEqual(_kill_container(cid_path, run_id=RUN, trial_token="b" * 64), "c" * 64)
            self.assertIn("label=nexus.cser-trial-token=" + "b" * 64, run.call_args_list[0].args[0])
            self.assertEqual(run.call_args_list[2].args[0], ["/usr/bin/docker", "kill", "c" * 64])

    def test_container_cleanup_refuses_uncertain_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cid_path = Path(directory) / "missing.cid"
            discovered = mock.Mock(returncode=0, stderr="", stdout=("c" * 64 + "\n" + "d" * 64 + "\n"))
            with mock.patch("handoff_matrix_controller.subprocess.run", return_value=discovered) as run:
                with self.assertRaisesRegex(RuntimeError, "identity is uncertain"):
                    _kill_container(cid_path, run_id=RUN, trial_token="b" * 64)
            self.assertEqual(run.call_count, 1)

    def test_cleanup_allows_an_absent_labelled_container_but_not_ambiguity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cid_path = Path(directory) / "missing.cid"
            absent = mock.Mock(returncode=0, stderr="", stdout="")
            with mock.patch("handoff_matrix_controller.subprocess.run", return_value=absent):
                self.assertIsNone(_kill_container(cid_path, run_id=RUN, trial_token="b" * 64, allow_absent=True))

    def test_real_qemu_controller_rejects_recovery_budget_at_inner_launcher_limit(self) -> None:
        controller = TOOLS / "handoff_matrix_controller.py"
        launcher = TOOLS / "qemu_boot.sh"
        result = subprocess.run([
            sys.executable, str(controller), "--variant", "cser", "--run-id", RUN,
            "--catalog-digest", "b" * 64, "--namespace-id", "handoff-test",
            "--authority-id", "c" * 32, "--effect-id", "d" * 32,
            "--trial", "1", "--cutpoint", "descriptor_discovered", "--cutpoint-id", "21",
            "--barrier-socket", "/tmp/nexus-handoff-timeout.sock",
            "--trial-dir", "/tmp/nexus-handoff-timeout-trial",
            "--metrics-jsonl", "/tmp/nexus-handoff-timeout.jsonl",
            "--recovery-timeout-seconds", "130", "--real-qemu", "--recovery-guest", str(launcher),
            "--", str(launcher),
        ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, 2)
        self.assertIn("recovery timeout greater than the internal 130s", result.stderr)

    def test_controller_configures_and_acks_only_strict_prefix(self) -> None:
        host, guest = socket.socketpair(); observed=[]
        def fake_guest() -> None:
            from matrix_protocol import _checksum
            hello=["CSER1","CONFIG_HELLO"]; guest.sendall((" ".join(hello+[_checksum(hello)]) + "\n").encode())
            config=guest.recv(1024); self.assertIn(b"CSER1 CONFIG "+RUN.encode(), config)
            for cut in (21,22,23):
                guest.sendall(barrier(RUN, cut)); data=guest.recv(1024); observed.append((cut,data))
        thread=threading.Thread(target=fake_guest); thread.start()
        self.assertFalse(observe_handoff_barriers(host,RUN,23,catalog_digest="c"*64,namespace_id="handoff",authority_id="d"*32,effect_id="e"*32))
        thread.join(2); host.close(); guest.close()
        self.assertIn(b"ACK "+RUN.encode()+b" 21",observed[0][1]); self.assertIn(b"ACK "+RUN.encode()+b" 22",observed[1][1]); self.assertEqual(observed[2][1],b"")

    def test_identity_mismatch_is_rejected(self) -> None:
        bad=json.dumps(receipt(run_id="c"*32)).encode()+b"\n"
        with self.assertRaisesRegex(ValueError,"identity mismatch"):
            _one_terminal([b"CSER_HANDOFF_TERMINAL "+bad],variant="cser",run_id=RUN)

    def test_missing_or_duplicate_receipts_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError,"exactly one"):_one_terminal([b"noise\n"],variant="cser",run_id=RUN)
        row=(b"CSER_HANDOFF_TERMINAL "+json.dumps(receipt()).encode()+b"\n")
        with self.assertRaisesRegex(ValueError,"exactly one"):_one_terminal([row,row],variant="cser",run_id=RUN)

    def test_second_recovery_must_be_stable_and_not_claim_live_gate(self) -> None:
        first=receipt(); second=receipt(coordinate_gate={"live_gate_observed":False,"reject_while_live":None,"admit_after_terminal":True,"revision_unchanged":None,"head_unchanged":None})
        compare_recoveries(first,second)
        unstable=receipt(descriptor_digest="c"*64,coordinate_gate=second["coordinate_gate"])
        with self.assertRaisesRegex(ValueError,"identity changed"): compare_recoveries(first,unstable)
        with self.assertRaisesRegex(ValueError,"unobserved live gate"): compare_recoveries(first,receipt())

    def test_host_verifies_two_independent_exact_key_ledgers(self) -> None:
        namespace, authority, parent, catalog = "handoff", "c" * 32, "d" * 32, "e" * 64
        child = child_transport_effect_id(namespace, authority, parent, RUN, catalog)
        source_key, source_payload, source_input = expected_source_request(
            parent=ParentDescriptorContext(0x48414e44, 1, 6)
        )
        descriptor = _child_descriptor_v1((namespace, authority, parent, catalog, RUN, source_key), source_input, source_payload)
        self.assertIsNotNone(descriptor); descriptor = descriptor or b""
        child_key, child_payload, child_input = expected_child_request(descriptor, parent=ParentDescriptorContext(0x48414e44, 1, 6))
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name, effect, key, digest, payload, kind, output in (("parent",parent,source_key,source_input,source_payload,"child_descriptor_v1",descriptor),("child",child,child_key,child_input,child_payload,"none",b"")):
                endpoint=root/f"handoff-{name}-endpoint.sqlite"; provider=root/f"handoff-{name}-provider.sqlite"
                with closing(sqlite3.connect(endpoint)) as db:
                    db.execute("CREATE TABLE operations(namespace_id,authority_id,effect_id,run_id,operation_key,input_digest,payload,state,result,catalog_digest,output_kind,output,provider_applied_at_ns)")
                    db.execute("INSERT INTO operations VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",(namespace,authority,effect,RUN,key,digest,payload,"succeeded","success",catalog,kind,output,123))
                    db.commit()
                with closing(sqlite3.connect(provider)) as db:
                    db.execute("CREATE TABLE provider_operations(namespace_id,authority_id,effect_id,catalog_digest,run_id,operation_key,input_digest,payload,state,result,output_kind,output,applied_at_ns)")
                    db.execute("INSERT INTO provider_operations VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",(namespace,authority,effect,catalog,RUN,key,digest,payload,"succeeded","success",kind,output,123))
                    db.commit()
            verified=verify_endpoint_ledgers(root,namespace_id=namespace,authority_id=authority,parent_effect_id=parent,run_id=RUN,catalog_digest=catalog,descriptor_digest=hashlib.sha256(descriptor).hexdigest())
            self.assertEqual(verified["source"]["provider_application_rows"],1)
            with closing(sqlite3.connect(root/"handoff-parent-endpoint.sqlite")) as db:
                db.execute("UPDATE operations SET operation_key='same-tampered-source'")
                db.commit()
            with closing(sqlite3.connect(root/"handoff-parent-provider.sqlite")) as db:
                db.execute("UPDATE provider_operations SET operation_key='same-tampered-source'")
                db.commit()
            with self.assertRaisesRegex(ValueError,"source endpoint/provider request is not canonical"):
                verify_endpoint_ledgers(root,namespace_id=namespace,authority_id=authority,parent_effect_id=parent,run_id=RUN,catalog_digest=catalog,descriptor_digest=hashlib.sha256(descriptor).hexdigest())
            with closing(sqlite3.connect(root/"handoff-parent-endpoint.sqlite")) as db:
                db.execute("UPDATE operations SET operation_key=?", (source_key,))
                db.commit()
            with closing(sqlite3.connect(root/"handoff-parent-provider.sqlite")) as db:
                db.execute("UPDATE provider_operations SET operation_key=?", (source_key,))
                db.commit()
            with closing(sqlite3.connect(root/"handoff-parent-provider.sqlite")) as db:
                db.execute("UPDATE provider_operations SET output=?", (b"tampered",))
                db.commit()
            with self.assertRaisesRegex(ValueError,"provider/endpoint"):
                verify_endpoint_ledgers(root,namespace_id=namespace,authority_id=authority,parent_effect_id=parent,run_id=RUN,catalog_digest=catalog,descriptor_digest=hashlib.sha256(descriptor).hexdigest())
            with closing(sqlite3.connect(root/"handoff-parent-provider.sqlite")) as db:
                db.execute("UPDATE provider_operations SET output=?", (descriptor,))
                db.commit()
                db.execute("UPDATE provider_operations SET output_kind='none'")
                db.commit()
            with self.assertRaisesRegex(ValueError,"provider/endpoint"):
                verify_endpoint_ledgers(root,namespace_id=namespace,authority_id=authority,parent_effect_id=parent,run_id=RUN,catalog_digest=catalog,descriptor_digest=hashlib.sha256(descriptor).hexdigest())
            with closing(sqlite3.connect(root/"handoff-parent-provider.sqlite")) as db:
                db.execute("UPDATE provider_operations SET output_kind='child_descriptor_v1'")
                db.commit()
            with closing(sqlite3.connect(root/"handoff-child-endpoint.sqlite")) as db:
                db.execute("UPDATE operations SET operation_key='wrong-child-key'")
                db.commit()
            with closing(sqlite3.connect(root/"handoff-child-provider.sqlite")) as db:
                db.execute("UPDATE provider_operations SET operation_key='wrong-child-key'")
                db.commit()
            with self.assertRaisesRegex(ValueError,"child endpoint/provider request"):
                verify_endpoint_ledgers(root,namespace_id=namespace,authority_id=authority,parent_effect_id=parent,run_id=RUN,catalog_digest=catalog,descriptor_digest=hashlib.sha256(descriptor).hexdigest())
            with closing(sqlite3.connect(root/"handoff-child-endpoint.sqlite")) as db:
                db.execute("UPDATE operations SET operation_key=?", (child_key,))
                db.commit()
            with closing(sqlite3.connect(root/"handoff-child-provider.sqlite")) as db:
                db.execute("UPDATE provider_operations SET operation_key=?", (child_key,))
                db.commit()
            with closing(sqlite3.connect(root/"handoff-child-endpoint.sqlite")) as db:
                db.execute("UPDATE operations SET input_digest='wrong-child-input'")
                db.commit()
            with closing(sqlite3.connect(root/"handoff-child-provider.sqlite")) as db:
                db.execute("UPDATE provider_operations SET input_digest='wrong-child-input'")
                db.commit()
            with self.assertRaisesRegex(ValueError,"child endpoint/provider request"):
                verify_endpoint_ledgers(root,namespace_id=namespace,authority_id=authority,parent_effect_id=parent,run_id=RUN,catalog_digest=catalog,descriptor_digest=hashlib.sha256(descriptor).hexdigest())
            with closing(sqlite3.connect(root/"handoff-child-provider.sqlite")) as db:
                db.execute("DELETE FROM provider_operations")
                db.commit()
            with self.assertRaisesRegex(ValueError,"provider/endpoint"): verify_endpoint_ledgers(root,namespace_id=namespace,authority_id=authority,parent_effect_id=parent,run_id=RUN,catalog_digest=catalog,descriptor_digest=hashlib.sha256(descriptor).hexdigest())

if __name__ == "__main__": unittest.main()
