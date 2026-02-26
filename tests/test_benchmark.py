import unittest
from pathlib import Path

from formal_cloud.benchmark import run_benchmark


class BenchmarkTests(unittest.TestCase):
    def test_benchmark_corpus_is_deterministic(self) -> None:
        report = run_benchmark(Path("benchmarks/corpus/cases.yaml"), iterations=3)
        self.assertTrue(report["summary"]["pass"])

        for case in report["cases"]:
            self.assertTrue(case["stable_decision"])
            self.assertTrue(case["stable_certificate"])
            self.assertTrue(case["expected_match"])


if __name__ == "__main__":
    unittest.main()
