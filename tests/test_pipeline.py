import contextlib
import csv
import http.client
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import run_experiment as pipeline
import score


class FakeResponse:
    def __init__(self, lines):
        self.lines = lines

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def __iter__(self):
        return iter(self.lines)


class IncompleteResponse(FakeResponse):
    def __iter__(self):
        yield b'{"response":"partial","done":false}\n'
        raise http.client.IncompleteRead(b"")


class PipelineTests(unittest.TestCase):
    def test_flush_reload_samples_get_all_three_conditions(self):
        self.assertEqual(
            pipeline.get_conditions_for_sample("FR-L0_flushreload_canonical"),
            ["A", "B_rowhammer", "B_flushreload"],
        )
        self.assertEqual(
            pipeline.get_conditions_for_sample("L0_rowhammer_canonical"),
            ["A", "B_rowhammer"],
        )

    def test_generate_stream_requires_completion_marker(self):
        response = FakeResponse([
            b'{"response":"answer","done":false}\n',
            b'{"response":"","done":true}\n',
        ])
        with mock.patch.object(pipeline.urllib.request, "urlopen", return_value=response) as urlopen:
            events = list(pipeline.stream_response("m", "system", "prompt"))

        self.assertIsNone(events[-1][4])
        self.assertTrue(events[-1][1])
        self.assertEqual(events[-1][2], "answer")
        self.assertIn("/api/generate", urlopen.call_args.args[0].full_url)

    def test_incomplete_stream_is_reported_as_error(self):
        response = FakeResponse([b'{"response":"partial","done":false}\n'])
        with mock.patch.object(pipeline.urllib.request, "urlopen", return_value=response):
            events = list(pipeline.stream_response("m", "system", "prompt"))

        self.assertIn("without a completion marker", events[-1][4])

    def test_broken_http_stream_is_reported_as_error(self):
        with mock.patch.object(
            pipeline.urllib.request, "urlopen", return_value=IncompleteResponse([])
        ):
            events = list(pipeline.stream_response("m", "system", "prompt"))

        self.assertIsNotNone(events[-1][4])

    def test_confidence_only_extracts_clear_label(self):
        self.assertEqual(
            pipeline.extract_confidence("Confidence: 87/100"),
            "87",
        )
        self.assertEqual(
            pipeline.extract_confidence("The code uses 64-byte cache lines."),
            "",
        )
        self.assertEqual(
            pipeline.extract_confidence("Confidence: 150/100"),
            "",
        )

    def test_failed_cached_runs_are_removed_but_successes_remain(self):
        with tempfile.TemporaryDirectory() as directory:
            results_path = Path(directory) / "all_responses.json"
            records = {
                "good": {"response": "completed answer"},
                "bad": {"response": "[CONNECTION ERROR: timeout]"},
                "empty": {"response": ""},
            }
            results_path.write_text(json.dumps(records), encoding="utf-8")
            with (
                mock.patch.object(pipeline, "RESULTS_JSON", results_path),
                mock.patch.object(pipeline, "LOG_FILE", Path(directory) / "run_log.txt"),
            ):
                loaded = pipeline.load_existing()

            self.assertEqual(set(loaded), {"good"})
            self.assertEqual(set(json.loads(results_path.read_text(encoding="utf-8"))), {"good"})

    def test_csv_reconciliation_preserves_manual_scores(self):
        with tempfile.TemporaryDirectory() as directory:
            csv_path = Path(directory) / "all_responses.csv"
            record = {
                "run_id": "run-1",
                "sample": "L0_sample",
                "response": "answer",
                "R1": "",
                "confidence_stated": "90",
                "notes": "",
            }
            with csv_path.open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=pipeline.CSV_HEADERS)
                writer.writeheader()
                writer.writerow({
                    key: value for key, value in {
                        **record, "R1": "3", "notes": "human reviewed"
                    }.items() if key in pipeline.CSV_HEADERS
                })

            with mock.patch.object(pipeline, "RESULTS_CSV", csv_path):
                self.assertTrue(pipeline.reconcile_csv({"run-1": record}))

            with csv_path.open(newline="", encoding="utf-8") as f:
                row = next(csv.DictReader(f))
            self.assertEqual(row["R1"], "3")
            self.assertEqual(row["notes"], "human reviewed")
            self.assertEqual(row["confidence_stated"], "90")

    def test_csv_reconciliation_keeps_valid_rows_without_json_records(self):
        with tempfile.TemporaryDirectory() as directory:
            csv_path = Path(directory) / "all_responses.csv"
            record = {
                "run_id": "csv-only",
                "response_preview": "completed response preview",
                "R1": "2",
            }
            with csv_path.open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=pipeline.CSV_HEADERS)
                writer.writeheader()
                writer.writerow(record)

            with mock.patch.object(pipeline, "RESULTS_CSV", csv_path):
                self.assertTrue(pipeline.reconcile_csv({}))

            with csv_path.open(newline="", encoding="utf-8") as f:
                row = next(csv.DictReader(f))
            self.assertEqual(row["run_id"], "csv-only")
            self.assertEqual(row["R1"], "2")


class ScoringTests(unittest.TestCase):
    def test_missing_confidence_is_excluded_and_tsi_uses_exact_adjacent_levels(self):
        with tempfile.TemporaryDirectory() as directory:
            csv_path = Path(directory) / "all_responses.csv"
            metrics_path = Path(directory) / "metrics.json"
            headers = [
                "sample", "model_key", "condition",
                *(f"R{i}" for i in range(1, 7)),
                *(f"C{i}" for i in range(1, 7)),
                "confidence_stated",
            ]
            rows = []
            for sample, rating, confidence in [
                ("L0_rowhammer_canonical", "3", ""),
                ("L1_rowhammer_comments_stripped", "0", "100"),
                ("FR-L0_flushreload_canonical", "0", ""),
            ]:
                rows.append({
                    "sample": sample,
                    "model_key": "model",
                    "condition": "A",
                    **{field: rating for field in headers if field.startswith(("R", "C"))},
                    "confidence_stated": confidence,
                })
            with csv_path.open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
                writer.writerows(rows)

            output = io.StringIO()
            with (
                mock.patch.object(score, "CSV_IN", csv_path),
                mock.patch.object(score, "JSON_OUT", metrics_path),
                contextlib.redirect_stdout(output),
            ):
                score.main()

            metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
            self.assertIsNone(metrics["L0_rowhammer_canonical__model__A"]["brier"])
            self.assertEqual(metrics["L1_rowhammer_comments_stripped__model__A"]["brier"], 1.0)
            self.assertIn("100.00 pts/step", output.getvalue())


if __name__ == "__main__":
    unittest.main()
