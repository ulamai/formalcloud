# Benchmark Regression Mode

FormalCloud benchmark corpus supports optional `expected_certificate_id` values per case.

When provided, benchmark execution validates:

1. Decision stability across iterations.
2. Certificate ID stability across iterations.
3. Match against the expected fixed certificate ID.

This provides strong regression guarantees for policy semantics and deterministic certificate generation.
