# codex

A minimal repository containing an interactive CLI tool for generating
C/C++ fuzzing harnesses. Run the tool and answer a few prompts to create
LibFuzzer, AFL++, or OSS-Fuzz harnesses along with a sample build script.

## Usage

```bash
python fuzz_harness_cli.py
```

The harnesses and build script are written to the `fuzz_harness/`
directory. Optional example seeds may also be generated.
