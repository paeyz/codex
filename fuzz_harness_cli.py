#!/usr/bin/env python3
"""Interactive CLI tool to generate fuzzing harnesses.

This script uses questionary to present a simple UI for generating
fuzzing harnesses for various fuzzers. Harnesses are created inside the
``fuzz_harness/`` directory along with a ``build.sh`` script that can be
used to compile them.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

import questionary
from jinja2 import Template

FUZZERS = ["LibFuzzer", "AFL++", "OSS-Fuzz (LibFuzzer-based)"]

# Templates for different fuzzer harnesses.
LIBFUZZER_TEMPLATE = Template(
    r"""#include <stddef.h>
#include <stdint.h>

// Fuzzing harness for function: {{ func }}
// Target source: {{ source }}
// Optional dependencies: {{ deps }}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // TODO: Map fuzz data to parameters of {{ func }} as needed.
    {{ func }}(data, size); // Call the target function with fuzz data
    return 0; // Non-zero return values are treated as crashes
}
"""
)

AFL_TEMPLATE = Template(
    r"""#include <stdint.h>
#include <unistd.h>

// Fuzzing harness for function: {{ func }}
// Target source: {{ source }}
// Optional dependencies: {{ deps }}

int main(int argc, char **argv) {
    uint8_t buf[4096];
    ssize_t len = read(0, buf, sizeof(buf)); // Read fuzz data from stdin
    if (len > 0) {
        {{ func }}(buf, len); // Call the target function
    }
    return 0; // AFL++ interprets non-zero as abnormal termination
}
"""
)

OSS_FUZZ_TEMPLATE = Template(
    r"""#include <stddef.h>
#include <stdint.h>

// Fuzzing harness for function: {{ func }} (OSS-Fuzz)
// Target source: {{ source }}
// Optional dependencies: {{ deps }}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // TODO: Convert fuzz data for {{ func }} as required.
    {{ func }}(data, size);
    return 0;
}

/*
CMakeLists.txt snippet for OSS-Fuzz integration:

add_executable({{ func }}_fuzz {{ func }}_oss_fuzz.cpp)
target_link_libraries({{ func }}_fuzz PRIVATE $${LIB_FUZZING_ENGINE})
*/
"""
)

BUILD_SCRIPT_TEMPLATE = Template(
    r"""#!/bin/bash
# Auto-generated build script
set -euo pipefail

CXX=${CXX:-clang++}
COMMON_FLAGS="-g -O1 -std=c++17"

case "{{ fuzzer }}" in
    LibFuzzer|OSS-Fuzz\ \(LibFuzzer-based\))
        FUZZ_FLAGS="-fsanitize=fuzzer,address"
        ;;
    AFL++)
        # AFL++ usually uses afl-clang-fast, but clang++ with -fsanitize=address works for basic cases
        FUZZ_FLAGS="-fsanitize=address"
        ;;
esac

for SRC in fuzz_harness/*_fuzz.cpp; do
    OUT="${SRC%.cpp}"
    echo "Compiling $SRC -> $OUT"
    "$CXX" $COMMON_FLAGS $FUZZ_FLAGS $SRC -o $OUT {{ deps }}
done
"""
)


def ask_functions() -> List[str]:
    """Prompt the user for function names and return a list."""
    funcs = questionary.text(
        "Enter function name(s) to fuzz (comma-separated)",
    ).ask() or ""
    return [f.strip() for f in funcs.split(",") if f.strip()]


def generate_harness(fuzzer: str, func: str, source: str, deps: str) -> str:
    """Return rendered harness code for the chosen fuzzer."""
    if fuzzer == "LibFuzzer":
        return LIBFUZZER_TEMPLATE.render(func=func, source=source, deps=deps)
    if fuzzer == "AFL++":
        return AFL_TEMPLATE.render(func=func, source=source, deps=deps)
    if fuzzer == "OSS-Fuzz (LibFuzzer-based)":
        return OSS_FUZZ_TEMPLATE.render(func=func, source=source, deps=deps)
    raise ValueError(f"Unknown fuzzer: {fuzzer}")


def generate_build_script(fuzzer: str, deps: str) -> str:
    return BUILD_SCRIPT_TEMPLATE.render(fuzzer=fuzzer, deps=deps)


def main() -> None:
    fuzzer = questionary.select("Select the fuzzer type", choices=FUZZERS).ask()
    if not fuzzer:
        return
    functions = ask_functions()
    source = questionary.text(
        "Path to target source file or project directory",
    ).ask() or ""
    deps = questionary.text(
        "Optional dependencies (e.g., include paths or build flags)",
    ).ask() or ""
    generate_seeds = questionary.confirm(
        "Generate example seed corpus?", default=False
    ).ask()

    harness_dir = Path("fuzz_harness")
    harness_dir.mkdir(exist_ok=True)

    for func in functions:
        suffix = {
            "LibFuzzer": "libfuzzer",
            "AFL++": "afl",
            "OSS-Fuzz (LibFuzzer-based)": "oss_fuzz",
        }[fuzzer]
        harness_file = harness_dir / f"{func}_{suffix}_fuzz.cpp"
        code = generate_harness(fuzzer, func, source, deps)
        harness_file.write_text(code)
        print(f"Created {harness_file}")

    # Write build script
    build_script = harness_dir / "build.sh"
    build_script.write_text(generate_build_script(fuzzer, deps))
    build_script.chmod(0o755)
    print(f"Created {build_script}")

    if generate_seeds:
        seeds_dir = harness_dir / "seeds"
        seeds_dir.mkdir(exist_ok=True)
        for func in functions:
            sample = seeds_dir / f"{func}_seed.txt"
            sample.write_text("example input\n")
        print(f"Created example seeds in {seeds_dir}")

    print("Fuzzing harness generation complete.")


if __name__ == "__main__":
    main()
