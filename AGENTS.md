# Repository agent instructions

Repository rules for `ores-lib-core`:

- Build values, don't mutate them: functions return new values instead of filling `&mut`/pointer
  parameters or caller-owned collections; every language. Deliberate exceptions on hot paths carry a
  `HOT-PATH (imperative by design)` comment with the reason. See
  [`docs/FUNCTIONAL-STYLE.md`](./docs/FUNCTIONAL-STYLE.md).
