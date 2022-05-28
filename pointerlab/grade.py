#!/usr/bin/env python3

import os
import shutil
import subprocess
import signal

# Location of sandbox
sandbox_dir = "sandbox"

# Location of original files and the files to copy
original_dir = "."
files_to_copy = ["Makefile", "pointer.h", "test.c"]

# Handin file
handin_file = "pointer.c"

# Timeouts (seconds)
timeout_default = 2
timeout_make = 30

# Test cases
test_cases = {
    "test_static_price_object": {"args": ["./pointer", "test_static_price_object"], "timeout": timeout_default},
    "test_dynamic_price_object": {"args": ["./pointer", "test_dynamic_price_object"], "timeout": timeout_default},
    "test_polymorphism": {"args": ["./pointer", "test_polymorphism"], "timeout": timeout_default},
    "test_compare_by_quantity": {"args": ["./pointer", "test_compare_by_quantity"], "timeout": timeout_default},
    "test_compare_by_price": {"args": ["./pointer", "test_compare_by_price"], "timeout": timeout_default},
    "test_static_bulk_price": {"args": ["./pointer", "test_static_bulk_price"], "timeout": timeout_default},
    "test_dynamic_bulk_price": {"args": ["./pointer", "test_dynamic_bulk_price"], "timeout": timeout_default},
    "test_iterator_basic": {"args": ["./pointer", "test_iterator_basic"], "timeout": timeout_default},
    "test_iterator_remove": {"args": ["./pointer", "test_iterator_remove"], "timeout": timeout_default},
    "test_iterator_insert": {"args": ["./pointer", "test_iterator_insert"], "timeout": timeout_default},
    "test_max_min_avg_price": {"args": ["./pointer", "test_max_min_avg_price"], "timeout": timeout_default},
    "test_foreach": {"args": ["./pointer", "test_foreach"], "timeout": timeout_default},
    "test_length": {"args": ["./pointer", "test_length"], "timeout": timeout_default},
    "test_merge": {"args": ["./pointer", "test_merge"], "timeout": timeout_default},
    "test_split": {"args": ["./pointer", "test_split"], "timeout": timeout_default},
    "test_mergesort": {"args": ["./pointer", "test_mergesort"], "timeout": timeout_default},
}

# Score breakdown by points (points, list of tests required to get points)
point_breakdown = [
    # Object (20 pts)
    (2, ["test_static_price_object"]),
    (3, ["test_dynamic_price_object"]),
    (5, ["test_polymorphism"]),
    (2, ["test_compare_by_quantity"]),
    (3, ["test_compare_by_price"]),
    (2, ["test_static_bulk_price"]),
    (3, ["test_dynamic_bulk_price"]),
    # Iterator (30pts)
    (10, ["test_iterator_basic"]),
    (10, ["test_iterator_remove"]),
    (10, ["test_iterator_insert"]),
    # List functions (20 pts)
    (7, ["test_max_min_avg_price"]),
    (7, ["test_foreach"]),
    (6, ["test_length"]),
    # Mergesort (30 pts)
    (10, ["test_merge"]),
    (10, ["test_split"]),
    (10, ["test_mergesort"]),
]

def print_success(test):
    print("****SUCCESS: {}****".format(test))

def print_failed(test):
    print("****FAILED: {}****".format(test))

def check_includes():
    with open(handin_file, "r") as f:
        for line in f:
            if "#include" in line:
                if line.rstrip() != "#include \"pointer.h\"":
                    print_failed(line.rstrip() + " is not allowed to be included")
                    return False
    return True

def make_assignment():
    args = ["make", "clean", "all"]
    try:
        subprocess.check_output(args, stderr=subprocess.STDOUT, timeout=timeout_make)
        return True
    except subprocess.CalledProcessError as e:
        print_failed("make")
        print(e.output.decode())
    except subprocess.TimeoutExpired as e:
        print_failed("make")
        print("Failed to compile within {} seconds".format(e.timeout))
    except KeyboardInterrupt:
        print_failed("make")
        print("User interrupted compilation")
    except:
        print_failed("make")
        print("Unknown error occurred")
    return False

def grade(submission_dir, submission_file):
    result = {}

    # Check file type
    if submission_file.endswith(".c"):
        # Clear previous sandbox
        if os.path.exists(sandbox_dir):
            shutil.rmtree(sandbox_dir)
        os.makedirs(sandbox_dir)

        # Copy handin file
        shutil.copy2(os.path.join(submission_dir, submission_file), os.path.join(sandbox_dir, handin_file))

        # Copy original files
        for f in files_to_copy:
            if os.path.exists(os.path.join(sandbox_dir, f)):
                os.remove(os.path.join(sandbox_dir, f))
            shutil.copy2(os.path.join(original_dir, f), os.path.join(sandbox_dir, f))

        # Switch to sandbox
        cwd = os.getcwd()
        os.chdir(sandbox_dir)

        # Check includes and run make on the assignment
        if check_includes() and make_assignment():
            # Run test cases
            for test, config in test_cases.items():
                try:
                    output = subprocess.check_output(config["args"], stderr=subprocess.STDOUT, timeout=config["timeout"]).decode()
                    if "ALL TESTS PASSED" in output:
                        result[test] = True
                        print_success(test)
                    else:
                        result[test] = False
                        print_failed(test)
                        print(output)
                except subprocess.CalledProcessError as e:
                    result[test] = False
                    print_failed(test)
                    print(e.output.decode())
                    if e.returncode < 0:
                        if -e.returncode == signal.SIGSEGV:
                            print("Segmentation fault (core dumped)")
                        else:
                            print("Died with signal {}".format(-e.returncode))
                except subprocess.TimeoutExpired as e:
                    result[test] = False
                    print_failed(test)
                    print("Failed to complete within {} seconds".format(e.timeout))
                except KeyboardInterrupt:
                    result[test] = False
                    print_failed(test)
                    print("User interrupted test")
                except:
                    result[test] = False
                    print_failed(test)
                    print("Unknown error occurred")

        # Switch back to original directory
        os.chdir(cwd)
    else:
        print_failed("invalid file {}".format(submission_file))

    # Calculate score
    score = 0
    total_possible = 0
    for points, tests in point_breakdown:
        if all(map(lambda test : test in result and result[test], tests)):
            score += points
        total_possible += points
    return (score, total_possible)

if __name__ == "__main__":
    submission_dir = "."
    score, total_possible = grade(submission_dir, handin_file)
    print("Final score: {}/{}".format(score, total_possible))
