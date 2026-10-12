# Contributing

## Tests

- `npm test` runs the whole suite (vitest). Real-Chromium tests need `npx playwright install chromium`; set
  `REQUIRE_CHROMIUM=1` to make them fail instead of skip when Chromium is missing.
- **Test-count gate.** CI runs `node scripts/test-gate.mjs` (also `npm run test:gate`), which fails the job if
  any test is skipped/todo/pending or if fewer tests executed than the number in `test/EXPECTED_TEST_COUNT`. It prints
  `test-gate: executed N / expected M, skipped K` and the list of test files that ran.
- **When you add tests, bump `test/EXPECTED_TEST_COUNT`** to the new total in the same PR. When you remove tests on
  purpose, lower it and say why in the PR.
