"""Keep standalone KDK evidence distinct from kernel-collection evidence."""
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ifnet_verifier", ROOT / "tools/verify_ifnet_kernel_contracts.py")
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


def kernel_fixture(header_value=None, duplicate_header=False):
    base = 0xffffff8000200000
    segment = struct.pack("<II16sQQQQiiII", 0x19, 152, b"__TEXT", base, 0x2000,
                          0, 0x2000, 5, 5, 1, 0)
    section = struct.pack("<16s16sQQIIIIIIII", b"__text", b"__TEXT", base + 0x1000,
                          0x500, 0x1000, 4, 0, 0, 0x80000400, 0, 0, 0)
    linkedit = struct.pack("<II16sQQQQiiII", 0x19, 72, b"__LINKEDIT", base + 0x2000,
                           0x1000, 0, 0x1000, 1, 1, 0, 0) if duplicate_header else \
        struct.pack("<II16sQQQQiiII", 0x19, 72, b"__LINKEDIT", base + 0x2000,
                    0x1000, 0x2000, 0x1000, 1, 1, 0, 0)
    strings = b"\0__mh_execute_header\0_ifnet_ioctl\0"
    symbols = struct.pack("<IBBHQ", 1, 3, 0, 0, base if header_value is None else header_value)
    symbols += struct.pack("<IBBHQ", 21, 0xf, 1, 0, base + 0x1000)
    commands = segment + section + linkedit
    commands += struct.pack("<II16s", 0x1b, 24, bytes(range(1, 17)))
    commands += struct.pack("<IIIIII", 2, 24, 0x2000, 2, 0x2040, len(strings))
    header = struct.pack("<IiiIIIII", 0xfeedfacf, 0x1000007, 3, 2, 4, len(commands), 0, 0)
    blob = bytearray(0x3000)
    blob[:len(header + commands)] = header + commands
    blob[0x2000:0x2000 + len(symbols)] = symbols
    blob[0x2040:0x2040 + len(strings)] = strings
    return blob


class IfnetVerifierInputTests(unittest.TestCase):
    def read(self, data, standalone=True):
        with tempfile.TemporaryDirectory(prefix="ifnet-input-", dir="/private/tmp") as tmp:
            path = Path(tmp) / "input"
            path.write_bytes(data)
            return verifier.read_image(path, 0, verifier.collect_header_symbol_names(),
                                       standalone=standalone)

    def test_standalone_metadata_never_claims_a_fileset_member(self):
        result = self.read(kernel_fixture())
        self.assertEqual(result["image_kind"], "standalone-MH_EXECUTE")
        self.assertIsNone(result["outer"]["kernel_entry"])
        self.assertIsNone(result["inner"]["fileset_entry"])
        self.assertNotIn("collection_sha256", result)
        self.assertEqual(len(result["candidates"]), len(verifier.EXPECTED_BODY_BY_PROFILE))

    def test_explicit_kind_architecture_and_header_identity_are_required(self):
        with self.assertRaisesRegex(verifier.VerificationError, "MH_FILESET"):
            self.read(kernel_fixture(), standalone=False)
        wrong_type = kernel_fixture()
        struct.pack_into("<I", wrong_type, 12, 0xc)
        with self.assertRaisesRegex(verifier.VerificationError, "MH_EXECUTE"):
            self.read(wrong_type)
        wrong_arch = kernel_fixture()
        struct.pack_into("<i", wrong_arch, 4, 0x100000c)
        with self.assertRaisesRegex(verifier.VerificationError, "not x86_64"):
            self.read(wrong_arch)
        with self.assertRaisesRegex(verifier.VerificationError, "header mapping"):
            self.read(kernel_fixture(header_value=123))
        with self.assertRaisesRegex(verifier.VerificationError, "unique readable header"):
            self.read(kernel_fixture(duplicate_header=True))

    def test_duplicate_inputs_across_kinds_are_not_counted_twice(self):
        with self.assertRaisesRegex(verifier.VerificationError, "duplicate"):
            verifier.verify([Path("same-kernel")], [Path("same-kernel")])
        with self.assertRaisesRegex(verifier.VerificationError, "explicit"):
            verifier.verify([])

    def read_saved(self, data):
        with tempfile.TemporaryDirectory(prefix="ifnet-excerpt-", dir="/private/tmp") as tmp:
            path = Path(tmp) / "sample.json"
            path.write_bytes(data)
            return verifier.read_excerpt(path, 0, verifier.collect_header_symbol_names())

    def saved_fixture(self):
        return json.loads(verifier.excerpt_bytes(self.read(kernel_fixture())))

    def test_excerpt_round_trip_does_not_require_or_reverify_original_image(self):
        original = self.read(kernel_fixture())
        self.assertFalse(Path(original["path"]).exists())
        saved = verifier.excerpt_bytes(original)
        result = self.read_saved(saved)
        self.assertEqual(result["symbols"], original["symbols"])
        self.assertEqual(result["segments"], original["segments"])
        self.assertEqual(result["candidates"], original["candidates"])
        self.assertEqual(result["image_sha256"], original["image_sha256"])
        self.assertEqual(result["input_kind"], "contract-excerpt")
        self.assertFalse(result["original_image_reverified"])
        self.assertEqual(result["excerpt_sha256"], verifier.hashlib.sha256(saved).hexdigest())

    def test_excerpt_rejects_ambiguous_or_invalid_harness_inputs(self):
        def exercise(mutate):
            data = self.saved_fixture()
            mutate(data)
            with self.assertRaises(verifier.VerificationError):
                self.read_saved(json.dumps(data).encode())

        mutations = (
            lambda d: d["candidates"].pop(),
            lambda d: d["candidates"][0].update(descriptor_index=255),
            lambda d: d["candidates"][0].update(descriptor_index=False),
            lambda d: d["candidates"][0].update(body_size=1),
            lambda d: d["candidates"][0].update(body_hex="00"),
            lambda d: d["candidates"][1].update(profile="mutex-inline"),
            lambda d: d["candidates"][0]["function_info"].update(symbol_va=0),
            lambda d: d["symbols"].update(_ifnet_ioctl="0x1234"),
            lambda d: d["symbols"].update(_ifnet_ioctl=True),
            lambda d: d["symbols"].update(_untrusted_symbol=0),
            lambda d: d.update(symbol_va=1),
            lambda d: d["segments"][0].update(vmsize=0xffffffffffffffff),
            lambda d: d["segments"][0].update(initprot=8),
            lambda d: d["segments"][0].update(name="invalid\nname"),
            lambda d: d.update(image_kind="retail-system"),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                exercise(mutate)

    def test_excerpt_candidates_must_describe_the_same_function(self):
        data = self.saved_fixture()
        data["candidates"][0]["body_hex"] = "ff" + data["candidates"][0]["body_hex"][2:]
        with self.assertRaisesRegex(verifier.VerificationError, "disagree"):
            self.read_saved(json.dumps(data).encode())

    def test_excerpt_semantic_evidence_is_optional_but_bounded(self):
        data = self.saved_fixture()
        self.assertEqual(data.get("semantic_evidence", []), [])
        record = {"address": "0xffffff8000201000", "executable": False,
                  "bytes_hex": "7465737400"}
        data["semantic_evidence"] = [record]
        saved = self.read_saved(json.dumps(data).encode())
        self.assertEqual(saved["semantic_evidence"], [record])

        malformed = (
            [{"address": "bad", "executable": True, "bytes_hex": "90"}],
            [{"address": "0x1", "executable": False, "bytes_hex": "616263"}],
            [{"address": "0x1", "executable": True, "bytes_hex": "aa" * 257}],
            [{"address": "0x1", "executable": False, "bytes_hex": "6100"},
             {"address": "0x1", "executable": False, "bytes_hex": "6200"}],
        )
        for index, evidence in enumerate(malformed):
            with self.subTest(index=index):
                invalid = self.saved_fixture()
                invalid["semantic_evidence"] = evidence
                with self.assertRaises(verifier.VerificationError):
                    self.read_saved(json.dumps(invalid).encode())

    def test_excerpt_size_duplicate_keys_and_export_destination_are_bounded(self):
        with self.assertRaisesRegex(verifier.VerificationError, "1 MiB"):
            self.read_saved(b" " * (verifier.MAX_EXCERPT_BYTES + 1))
        with self.assertRaisesRegex(verifier.VerificationError, "duplicate excerpt key"):
            self.read_saved(b'{"symbols":{},"symbols":{}}')
        with tempfile.TemporaryDirectory(prefix="ifnet-export-", dir="/private/tmp") as tmp:
            with self.assertRaisesRegex(verifier.VerificationError, "new directory"):
                verifier.verify([Path("unused-image")], save_excerpts=Path(tmp))
            with self.assertRaisesRegex(verifier.VerificationError, "image inputs only"):
                verifier.verify([], excerpts=[Path("unused-excerpt")],
                                save_excerpts=Path(tmp) / "new")


if __name__ == "__main__":
    unittest.main()
