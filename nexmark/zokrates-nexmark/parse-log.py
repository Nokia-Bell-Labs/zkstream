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
    # We read this in for all runs, check whether they all have the same values, and
    # print those.
    # This returns the number of compilation runs and normal runs (over all programs and
    # variants).
    n_compilation_runs = len(re.findall(r"Compilation run\n", log))
    n_normal_runs = len(re.findall(r"Run (\d+)\n", log))
    n_runs = n_compilation_runs + n_normal_runs
    check_all_identical("hostname", re.findall(r"\nHostname: (.*)\n", log), n_runs)
    check_all_included("time", re.findall(r"\nTime: (.*)\n", log), n_runs)
    check_all_identical(
        "Zokrates version", re.findall(r"\nZokrates version: (.*)\n", log), n_runs
    )
    check_all_identical(
        "git revision", re.findall(r"\nGit revision: (.*)\n", log), n_runs
    )
    # check_all_identical("variants", re.findall(r"\nVARIANTS=(.*)\n", log), n_runs)
    check_all_equal_to("debug", re.findall(r"\nDEBUG=(.*)\n", log), "", n_runs)
    return (n_compilation_runs, n_normal_runs)


# Part of a regular expression that matches a time.
TIME_RE_PART = r"\d+(?:\.\d+)?(?:s|ms|µs|ns)"
# Part of a regular expression that matches a time and captures it as "time".
TIME_RE_GROUP = r"(?P<time>\d+(?:\.\d+)?(?:s|ms|µs|ns))"
# Part of a regular expression that matches the run number and captures it as "run",
# followed by ignored text.
RUN_RE_GROUP = r"Run (?P<run>\d+)\n"


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


def main(file_name: str):
    with open(file_name, "r") as f:
        log = f.read()

    N_VARIANTS = 3  # poseidon, poseidon.nosig, poseidon.nosig.bls
    N_PROGRAMS = 5  # q1, q4a, q4b, q5a, q5b, q6a, q6b, q7
    N_RUNS = 30
    (n_compilation_runs, n_normal_runs) = check_parameters(log)
    if n_compilation_runs != N_PROGRAMS * N_VARIANTS * 1:
        err(f"expected {N_PROGRAMS} * {N_VARIANTS} * {1} compilation runs, found {n_compilation_runs}")
    if n_normal_runs != N_PROGRAMS * N_VARIANTS * N_RUNS:
        err(f"expected {N_PROGRAMS} * {N_VARIANTS} * {N_RUNS} normal runs, found {n_normal_runs}")

    program = None
    variant = None
    run = None  # For compilation and setup, this is always 0; for others this starts at 1.
    # Map (program, variant, run) -> list[time]
    compilation = {}
    # Map (program, variant, run) -> list[time]
    setup = {}
    # Map (program, variant, run) -> list[time]
    compute_witness = {}
    # Map (program, variant, run) -> list[time]
    generate_proof = {}
    # Map (program, variant, run) -> list[time]
    aggregate_signatures = {}
    # Map (program, variant, run) -> list[time]
    verify_total = {}
    for line in log.split("\n"):
        if line.startswith("Program: "):
            # Looks like "Program: q1"
            program = line[len("Program: ") :]
        if line.startswith("Variant: "):
            # Looks like "Variant: poseidon.nosig; Compilation run" or
            # "Variant: poseidon.nosig; Run 1"
            variant = line[len("Variant: "):line.index(";")]
            if "Compilation" in line:
                run = 0
            else:
                run = int(line[line.index("Run ") + 4 :])

        if line.startswith("| Time to compile: "):
            # | Time to compile: 230.825704241s
            compilation.setdefault((program, variant, run), []).append(parse_time(
                line[len("| Time to compile: ") :]
            ))
        if line.startswith("| Time to setup: "):
            # | Time to setup: 1.804s
            setup.setdefault((program, variant, run), []).append(parse_time(
                line[len("| Time to setup: ") :]
            ))
        if line.startswith("| Time to compute-witness: "):
            # | Time to compute-witness: 3.6588392s
            if run == 0:  # Compilation run
                continue
            compute_witness.setdefault((program, variant, run), []).append(parse_time(
                line[len("| Time to compute-witness: ") :]
            ))
        if line.startswith("| Time to generate-proof: "):
            # | Time to generate-proof: 7.245521014s
            if run == 0:  # Compilation run
                continue
            generate_proof.setdefault((program, variant, run), []).append(parse_time(
                line[len("| Time to generate-proof: ") :]
            ))
        if line.startswith("| Time to aggregate signatures: "):
            # | Time to aggregate signatures: 197.236µs
            if run == 0:  # Compilation run
                continue
            aggregate_signatures.setdefault((program, variant, run), []).append(parse_time(
                line[len("| Time to aggregate signatures: ") :]
            ))
        if line.startswith("| Time to verify everything: "):
            # | Time to verify everything: 110.742027ms
            if run == 0:  # Compilation run
                continue
            verify_total.setdefault((program, variant, run), []).append(parse_time(
                line[len("| Time to verify everything: ") :]
            ))

    # info(compilation)
    # info(setup)
    # info(compute_witness)
    # info(generate_proof)
    # info(aggregate_signatures)
    # info(verify_total)

    def check_result_count(name, program, results, n):
        for (p, variant, run) in results:
            if p != program:
                continue
            actual = len(results[(program, variant, run)])
            if actual != n:
                err(f"expected {n} time for {name} of {program}.{variant}.{run}, got {actual}")

    def check_run_count(name, results, n):
        for (program, variant, run) in results:
            if run not in range(1, N_RUNS + 1):
                err(f"expected runs 1 to {N_RUNS} for {name} of {program}.{variant}, got {run}")

    for (program, variant, run) in compilation:
        if program in ["q1", "q7"]:
            # Check: for q1 and q7, we should have one time for compilation and setup,
            # and one time for the actual executions.
            check_result_count("compilation", program, compilation, 1)
            check_result_count("setup", program, setup, 1)
            check_result_count("compute_witness", program, compute_witness, 1)
            check_result_count("generate_proof", program, generate_proof, 1)
            check_result_count("aggregate_signatures", program, aggregate_signatures, 1)
            check_result_count("verify_total", program, verify_total, 1)
        else:
            # For the other queries, we should have two times for compilation and setup,
            # more for the actual executions (but the same for all runs), and
            # one for aggregation and verification.
            check_result_count("compilation", program, compilation, 2)
            check_result_count("setup", program, setup, 2)
            expected = len(compute_witness[(program, "poseidon", 1)])
            if variant == "poseidon" and run == 1:
                info(f"{program}: {expected}")
            check_result_count("compute_witness", program, compute_witness, expected)
            check_result_count("generate_proof", program, generate_proof, expected)
            check_result_count("aggregate_signatures", program, aggregate_signatures, 1)
            check_result_count("verify_total", program, verify_total, 1)

    # Check: there should be N_RUNS for witness, proof, aggregate signatures, and verify.
    check_run_count("compute_witness", compute_witness, N_RUNS)
    check_run_count("generate_proof", generate_proof, N_RUNS)
    check_run_count("aggregate_signatures", aggregate_signatures, N_RUNS)
    check_run_count("verify_total", verify_total, N_RUNS)

    # Now, we sum all times in a single run together.
    def sum_runs(results):
        for (program, variant, run) in results:
            results[(program, variant, run)] = sum(results[(program, variant, run)])

    sum_runs(compilation)
    sum_runs(setup)
    sum_runs(compute_witness)
    sum_runs(generate_proof)
    sum_runs(aggregate_signatures)
    sum_runs(verify_total)

    # info(compilation)
    # info(setup)
    # info(compute_witness)
    # info(generate_proof)
    # info(aggregate_signatures)
    # info(verify_total)

    def print_times(program, variant, phase, run, time):
        print(f"{program},{variant},{phase},{run},{time}")

    def print_results_per_run(name, results):
        for (program, variant, run), time in results.items():
            print_times(program, variant, name, run, time)

    def print_results_avg(name, results):
        for (program, variant), time in results.items():
            print_times(program, variant, name, "avg", time)

    # Print as CSV
    print_times("program", "variant", "phase", "run", "time")
    print_results_per_run("compilation", compilation)
    print_results_per_run("setup", setup)
    print_results_per_run("compute_witness", compute_witness)
    print_results_per_run("generate_proof", generate_proof)
    print_results_per_run("aggregate_signatures", aggregate_signatures)
    print_results_per_run("verify_total", verify_total)

    # Now, we calculate averages over all runs.
    def average_results(results):
        avg = {}
        for (program, variant, run) in results:
            avg.setdefault((program, variant), 0)
            avg[(program, variant)] += results[(program, variant, run)]
        for (program, variant) in avg:
            n_runs = len([r for (p, v, r) in results if p == program and v == variant])
            avg[(program, variant)] /= n_runs
        return avg

    compilation_avg = average_results(compilation)
    setup_avg = average_results(setup)
    compute_witness_avg = average_results(compute_witness)
    generate_proof_avg = average_results(generate_proof)
    aggregate_signatures_avg = average_results(aggregate_signatures)
    verify_total_avg = average_results(verify_total)

    # info(compilation_avg)
    # info(setup_avg)
    # info(compute_witness_avg)
    # info(generate_proof_avg)
    # info(aggregate_signatures_avg)
    # info(verify_total_avg)

    # Print as CSV
    print_results_avg("compilation", compilation_avg)
    print_results_avg("setup", setup_avg)
    print_results_avg("compute_witness", compute_witness_avg)
    print_results_avg("generate_proof", generate_proof_avg)
    print_results_avg("aggregate_signatures", aggregate_signatures_avg)
    print_results_avg("verify_total", verify_total_avg)


if __name__ == "__main__":
    file_name = sys.argv[1] if len(sys.argv) > 1 else "log"
    main(file_name)
