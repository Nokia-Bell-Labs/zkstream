import logging
import re
import sys
import statistics


# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
# Redirect logs to stderr
stderr_handler = logging.StreamHandler(sys.stderr)
# Change log format
log_format = logging.Formatter("[%(levelname)s] %(message)s")
stderr_handler.setFormatter(log_format)
logger.addHandler(stderr_handler)

err = logger.error
info = logger.info


def find_last_match(pattern, text):
    """Find the last match of the regular expression `pattern` in `text`. Returns None
    if no match was found."""
    matches = re.findall(pattern, text)
    return matches[-1] if matches else None


def all_identical(lst: list[str]) -> bool:
    """Check if all elements in `lst` are identical."""
    if len(lst) <= 1:
        return True
    return all(l == lst[0] for l in lst)


def check_all_included(name: str, lst: list[str], n: int):
    """Check if `lst` contains `n` elements and print them."""
    if len(lst) != n:
        err(f"found only {len(lst)} {name}")
    info(f"{name}: {lst}")


def check_all_identical(name: str, lst: list[str], n: int):
    """Check if `lst` contains `n` identical elements and print their value."""
    if len(lst) != n:
        err(f"found only {len(lst)} {name}")

    if len(lst) == 0:
        info(f"{name}: missing")
        return

    if not all_identical(lst):
        err(f"not all {name} are equal: {lst}")
    else:
        info(f"{name}: {lst[0]}")


def check_all_equal_to(name: str, lst: list[str], val: str, n: int):
    """Check if `lst` contains `n` elements equal to `val` and print the value."""
    if len(lst) != n:
        err(f"found only {len(lst)} {name}")

    if len(lst) == 0:
        info(f"{name}: missing")
        return

    if not all(l == val for l in lst):
        err(f"not all {name} are equal: {lst}")
    else:
        info(f"{name}: {val}")


def check_parameters(log: str) -> int:
    # Each run starts with:
    #   Hostname: web3
    #   Time: 2023-07-15T13:08:39+00:00
    #   Zokrates version: ZoKrates 0.8.7
    #   Git revision: 4731107
    #   VARIANTS=poseidon.nosig poseidon sha256.nosig
    #   LOG_FILE=log
    #   DEBUG=
    # The debug flag is missing for the output of ./run-verifier.sh.
    # We read this in for all runs, check whether they all have the same values, and
    # print those.
    # This returns the number of runs.
    n_runs = len(re.findall(r"Run (\d+)\n", log))
    check_all_identical("hostname", re.findall(r"\nHostname: (.*)\n", log), n_runs)
    check_all_included("time", re.findall(r"\nTime: (.*)\n", log), n_runs)
    check_all_identical(
        "Zokrates version", re.findall(r"\nZokrates version: (.*)\n", log), n_runs
    )
    check_all_identical(
        "git revision", re.findall(r"\nGit revision: (.*)\n", log), n_runs
    )
    check_all_identical("variants", re.findall(r"\nVARIANTS=(.*)\n", log), n_runs)
    check_all_equal_to("debug", re.findall(r"\nDEBUG=(.*)\n", log), "", n_runs)
    return n_runs


# Part of a regular expression that matches a time.
TIME_RE_PART = r"\d+(?:\.\d+)?(?:s|ms|µs|ns)"
# Part of a regular expression that matches a time and captures it as "time".
TIME_RE_GROUP = r"(?P<time>\d+(?:\.\d+)?(?:s|ms|µs|ns))"


def parse_time(time) -> int:
    """
    Parse a time as output by Rust's std::time::Duration default format. There are four
    formats:
    - 123.456s
    - 123.456ms
    - 123.456µs
    - 123.456ns
    We return the time as an int in nanoseconds.
    """
    match = re.match(r"(?P<value>\d+(\.\d+)?)(?P<unit>s|ms|µs|ns)", time)
    if not match:
        raise ValueError("Invalid time format")
    value = float(match.group("value"))
    unit = match.group("unit")

    if unit == "s":
        return int(value * 1e9)
    elif unit == "ms":
        return int(value * 1e6)
    elif unit == "µs":
        return int(value * 1e3)
    elif unit == "ns":
        return int(value)
    else:
        raise ValueError(f"Invalid time unit: {unit}")


def parse_compile_setup(log):
    # Looks like:
    #  > Compiling historical.poseidon.nosig
    #  | Time to compile: 70.111102514s
    #  > Set up for historical.poseidon.nosig
    #  | Time to setup: 3.843018792s
    # Map (variant, "historical"|"challenge1") -> list[compile times]
    compile = {}
    # Map (variant, "historical"|"challenge1") -> list[setup times]
    setup = {}

    matches = re.findall(
        r"> Compiling (?P<program>historical|challenge1)\.(?P<variant>.*)\n\| Time to compile: "
        + TIME_RE_GROUP
        + r"\n",
        log,
    )
    for m in matches:
        program, variant, time = m
        compile.setdefault((variant, program), []).append(parse_time(time))

    matches = re.findall(
        r"> Set up for (?P<program>historical|challenge1)\.(?P<variant>.*)\n\| Time to setup: "
        + TIME_RE_GROUP
        + r"\n",
        log,
    )
    for m in matches:
        program, variant, time = m
        setup.setdefault((variant, program), []).append(parse_time(time))

    return (compile, setup)


def parse_compute_witness(log):
    # Looks like:
    #  Witness file written to 'historical.poseidon.nosig-0.witness'
    #  | Time to compute-witness: 1.796934482s
    # or:
    #  Witness file written to 'challenge1.poseidon.nosig.witness'
    #  | Time to compute-witness: 2.044895518s
    # Map (variant, "historical-$i"|"challenge1") -> list[witness times]
    compute_witness = {}

    matches = re.findall(
        r"Witness file written to 'historical.(?P<variant>.*)-(?P<i>\d+).witness'\n\| Time to compute-witness: "
        + TIME_RE_GROUP
        + r"\n",
        log,
    )
    for m in matches:
        variant, i, time = m
        compute_witness.setdefault((variant, f"historical-{i}"), []).append(
            parse_time(time)
        )

    matches = re.findall(
        r"Witness file written to 'challenge1.(?P<variant>.*).witness'\n\| Time to compute-witness: "
        + TIME_RE_GROUP
        + r"\n",
        log,
    )
    for m in matches:
        variant, time = m
        compute_witness.setdefault((variant, "challenge1"), []).append(parse_time(time))

    return compute_witness


def parse_generate_proof(log):
    # Looks like:
    #  > Generating proof for historical.poseidon.nosig-0
    #  | Time to generate-proof: 4.080131974s
    # or:
    #  > Generating proof for challenge1.poseidon.nosig
    #  | Time to generate-proof: 4.634451328s
    # Map (variant, "historical-$i"|"challenge1") -> list[proof times]
    generate_proof = {}

    matches = re.findall(
        r"> Generating proof for historical.(?P<variant>.*)-(?P<i>\d+)\n\| Time to generate-proof: "
        + TIME_RE_GROUP
        + r"\n",
        log,
    )
    for m in matches:
        variant, i, time = m
        generate_proof.setdefault((variant, f"historical-{i}"), []).append(
            parse_time(time)
        )

    matches = re.findall(
        r"> Generating proof for challenge1.(?P<variant>.*)\n\| Time to generate-proof: "
        + TIME_RE_GROUP
        + r"\n",
        log,
    )
    for m in matches:
        variant, time = m
        generate_proof.setdefault((variant, "challenge1"), []).append(parse_time(time))

    return generate_proof


def parse_aggregate_signatures(log):
    # Looks like:
    #  > Generating proof for challenge1.poseidon.nosig
    #  | Time to generate-proof: 4.566421319s
    #  > Aggregating signatures
    #  Number of signatures to aggregate = 4156
    #  | Time to aggregate signatures: 13.105498ms
    # Map (variant,) -> list[proof times]
    aggregate_signatures = {}

    matches = re.findall(
        r"> Generating proof for challenge1.(?P<variant>.*)"
        + r"\n\| Time to generate-proof: "
        + TIME_RE_PART
        + r"\n> Aggregating signatures"
        + r"\nNumber of signatures to aggregate = \d+"
        + r"\n\| Time to aggregate signatures: "
        + TIME_RE_GROUP
        + r"\n",
        log,
    )
    for m in matches:
        variant, time = m
        aggregate_signatures.setdefault((variant,), []).append(parse_time(time))

    return aggregate_signatures


def parse_verify(log):
    # Verification of a single signature looks like (for most variants):
    #  | Time to verify signature of message 3011785: 418.172µs
    # or (for BLS variants):
    #  > Verify BLS aggregated signature
    #  | Time to verify BLS aggregated signature: 365.09119ms
    # Verification of a historical proof looks like:
    #  > Verifying proof for historical.poseidon.nosig-0
    #  | Time to verify: 47.252082ms
    # Verification of challenge1 proof looks like:
    #  > Verifying proof for challenge1.poseidon.nosig
    #  | Time to verify: 49.069485ms
    # Total verification looks like (for most variants):
    #  | Time to verify everything: 3.622435577s
    # or (for BLS variants):
    #  > Verifying proof for challenge1.poseidon.nosig
    #  | Time to verify: 49.897646ms
    #  Number of hashes = 4156
    #  > Verify BLS aggregated signature
    #  | Time to verify BLS aggregated signature: 365.09119ms
    #  | Time to verify everything: 1.942336259s

    # Map (variant, "historical-$i"|"challenge1") -> list[time]
    verify_signature = {}
    # Map (variant, "historical-$i"|"challenge1") -> list[time]
    verify_proof = {}
    # Map (variant,) -> list[time]
    verify_total = {}

    # Verify signature:
    # For most variants:
    for m in re.finditer(
        r"\| Time to verify signature of message (?P<id>\d+): " + TIME_RE_GROUP + r"\n",
        log,
    ):
        id = m.group("id")
        # To find the variant and program, we need to go back from the current position
        # until we find either (up to 180 lines back):
        #   > Verify historical proof 0
        # or (up to 180 lines back):
        #   > Verify challenge1 proof
        # And until we find (even further back):
        #   > Variant poseidon.nosig
        # This is not very efficient, and can take up to a minute to process all
        # signatures.
        pos = m.start()
        m_program = find_last_match(
            r"> Verify (?P<program>challenge1|historical) proof(?: (?P<i>\d+))?\n",
            log[max(0, pos - 18000) : pos],
        )
        if m_program is None:
            raise ValueError(
                f"could not find program for signature of message {id} at position {pos}"
            )
        if m_program[0] == "challenge1":
            program = "challenge1"
        elif m_program[0] == "historical":
            program = "historical-" + m_program[1]
        else:
            raise ValueError(f"unknown program {m_program.group('program')}")
        variant = find_last_match(
            r"> Variant (?P<variant>.*)\n",
            log[max(0, pos - 1000000) : pos],
        )
        if variant is None:
            raise ValueError(
                f"could not find variant for signature of message {id} at position {pos}"
            )
        time = m.group("time")
        verify_signature.setdefault((variant, program), []).append(parse_time(time))
    # For BLS variants:
    matches = re.findall(
        r"> Verifying proof for challenge1.(?P<variant>.*)\n\| Time to verify: "
        + TIME_RE_PART
        + r"\nNumber of hashes = \d+"
        + r"\n> Verify BLS aggregated signature"
        + r"\n\| Time to verify BLS aggregated signature: "
        + TIME_RE_GROUP
        + r"\n",
        log,
    )
    for m in matches:
        variant, time = m
        verify_signature.setdefault((variant, "challenge1"), []).append(
            parse_time(time)
        )

    # Verify proof (historical):
    matches = re.findall(
        r"> Verifying proof for historical.(?P<variant>.*)-(?P<i>\d+)\n\| Time to verify: "
        + TIME_RE_GROUP
        + r"\n",
        log,
    )
    for m in matches:
        variant, i, time = m
        verify_proof.setdefault((variant, f"historical-{i}"), []).append(
            parse_time(time)
        )

    # Verify proof (challenge1):
    matches = re.findall(
        r"> Verifying proof for challenge1.(?P<variant>.*)\n\| Time to verify: "
        + TIME_RE_GROUP
        + r"\n",
        log,
    )
    for m in matches:
        variant, time = m
        verify_proof.setdefault((variant, "challenge1"), []).append(parse_time(time))

    # Verify total:
    # For most variants:
    matches1 = re.findall(
        r"> Verifying proof for challenge1.(?P<variant>.*)\n\| Time to verify: "
        + TIME_RE_PART
        + r"\n\| Time to verify everything: "
        + TIME_RE_GROUP
        + r"\n",
        log,
    )
    # For BLS variants:
    matches2 = re.findall(
        r"> Verifying proof for challenge1.(?P<variant>.*)\n\| Time to verify: "
        + TIME_RE_PART
        + r"\nNumber of hashes = \d+"
        + r"\n> Verify BLS aggregated signature"
        + r"\n\| Time to verify BLS aggregated signature: "
        + TIME_RE_PART
        + r"\n\| Time to verify everything: "
        + TIME_RE_GROUP
        + r"\n",
        log,
    )
    for m in matches1 + matches2:
        variant, time = m
        verify_total.setdefault((variant,), []).append(parse_time(time))

    return verify_total, verify_signature, verify_proof


def print_stats(
    compile,
    setup,
    compute_witness,
    generate_proof,
    aggregate_signatures,
    verify_total,
    verify_signature,
    verify_proof,
    n_runs,
):
    def check_length(phase, variant, execution, times):
        if len(times) != n_runs:
            err(
                f"number of entries for {phase},{variant},{execution} is "
                + f"{len(times)}, expected {n_runs}"
            )

    def group_same_program(times_per_variant_and_execution):
        """Convert a dict `(variant, execution) -> list[time]`, where `execution` is
        historical-0, historical-1, ..., or challenge1;
        to a dict `(variant, program) -> list[time]`, where `program` is
        historical or challenge1."""
        # Map (variant, "historical"|"challenge1") -> list[time]
        regrouped = dict()
        for (variant, execution), times in times_per_variant_and_execution.items():
            if execution.startswith("historical"):
                program = "historical"
            else:
                program = execution
            regrouped.setdefault((variant, program), []).extend(times)
        return regrouped

    def print_stat(phase, variant, execution, times):
        # Convert from ns to s
        times = [time / 1000000000 for time in times]
        avg = statistics.mean(times)
        stddev = statistics.stdev(times)
        median = statistics.median(times)
        min_ = min(times)
        max_ = max(times)
        if phase == "aggregate_signatures":
            print(f"{phase},{variant},{execution},{avg:.3f},{stddev:.3f},{min_:.3f},{median:.3f},{max_:.3f}")
        else:
            print(f"{phase},{variant},{execution},{avg:.2f},{stddev:.2f},{min_:.2f},{median:.2f},{max_:.2f}")

    print("phase,variant,program,avg,stddev,min,median,max")
    for (variant, program), times in compile.items():
        check_length("compile", variant, program, times)
        print_stat("compile", variant, program, times)
    for (variant, program), times in setup.items():
        check_length("setup", variant, program, times)
        print_stat("setup", variant, program, times)
    for (variant, program), times in group_same_program(compute_witness).items():
        check_length("compute_witness", variant, program, times)
        print_stat("compute_witness", variant, program, times)
    for (variant, program), times in group_same_program(generate_proof).items():
        check_length("generate_proof", variant, program, times)
        print_stat("generate_proof", variant, program, times)
    for (variant,), times in aggregate_signatures.items():
        check_length("aggregate_signatures", variant, "", times)
        print_stat("aggregate_signatures", variant, "", times)
    for (variant, program), times in group_same_program(verify_signature).items():
        check_length("verify_signature", variant, program, times)
        print_stat("verify_signature", variant, program, times)
    for (variant, program), times in group_same_program(verify_proof).items():
        check_length("verify_proof", variant, program, times)
        print_stat("verify_proof", variant, program, times)
    for (variant,), times in verify_total.items():
        check_length("verify_total", variant, "", times)
        print_stat("verify_total", variant, "", times)


def print_all(
    compile,
    setup,
    compute_witness,
    generate_proof,
    aggregate_signatures,
    verify_total,
    verify_signature,
    verify_proof,
    n_runs,
):
    def check_length(phase, variant, execution, times):
        if len(times) != n_runs:
            err(
                f"number of entries for {phase},{variant},{execution} is "
                + f"{len(times)}, expected {n_runs}"
            )

    def print_times(phase, variant, execution, times):
        for time in times:
            print(f"{phase},{variant},{execution},{time}")

    print("phase,variant,program,time")
    for (variant, program), times in compile.items():
        check_length("compile", variant, program, times)
        print_times("compile", variant, program, times)
    for (variant, program), times in setup.items():
        check_length("setup", variant, program, times)
        print_times("setup", variant, program, times)
    for (variant, execution), times in compute_witness.items():
        check_length("compute_witness", variant, execution, times)
        print_times("compute_witness", variant, execution, times)
    for (variant, execution), times in generate_proof.items():
        check_length("generate_proof", variant, execution, times)
        print_times("generate_proof", variant, execution, times)
    for (variant,), times in aggregate_signatures.items():
        check_length("aggregate_signatures", variant, "", times)
        print_times("aggregate_signatures", variant, "", times)
    for (variant, execution), times in verify_signature.items():
        check_length("verify_signature", variant, execution, times)
        print_times("verify_signature", variant, execution, times)
    for (variant, execution), times in verify_proof.items():
        check_length("verify_proof", variant, execution, times)
        print_times("verify_proof", variant, execution, times)
    for (variant,), times in verify_total.items():
        check_length("verify_total", variant, "", times)
        print_times("verify_total", variant, "", times)


def main(file_name: str):
    with open(file_name, "r") as f:
        log = f.read()

    n_runs = check_parameters(log)
    compile, setup = parse_compile_setup(log)
    compute_witness = parse_compute_witness(log)
    generate_proof = parse_generate_proof(log)
    aggregate_signatures = parse_aggregate_signatures(log)
    verify_total, verify_signature, verify_proof = parse_verify(log)

    # Calculate statistics and print only those:
    print_stats(
        compile,
        setup,
        compute_witness,
        generate_proof,
        aggregate_signatures,
        verify_total,
        verify_signature,
        verify_proof,
        n_runs,
    )

    # Print all results:
    # print_all(
    #     compile,
    #     setup,
    #     compute_witness,
    #     generate_proof,
    #     aggregate_signatures,
    #     verify_total,
    #     verify_signature,
    #     verify_proof,
    #     n_runs,
    # )


if __name__ == "__main__":
    file_name = sys.argv[1] if len(sys.argv) > 1 else "log"
    main(file_name)
