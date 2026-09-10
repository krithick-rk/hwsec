#!/usr/bin/env python3
"""Verify benchmark directory structure and separation rules."""

import os
import sys
import json

BENCH_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ERRORS = []
WARNINGS = []


def check_exists(path, label):
    if not os.path.exists(path):
        ERRORS.append(f"Missing: {label} at {path}")
        return False
    return True


def check_no_answer_key_in_targets():
    targets = os.path.join(BENCH_ROOT, 'benchmark_targets')
    for root, dirs, files in os.walk(targets):
        for f in files:
            if 'answer_key' in f or 'witness' in f.lower() or 'FIX_NOTES' in f:
                ERRORS.append(f"Forbidden file in benchmark_targets: {os.path.join(root, f)}")
            if f.endswith('.py') and f != 'test_app.py':
                filepath = os.path.join(root, f)
                with open(filepath, 'r') as fh:
                    content = fh.read()
                    for marker in ['VULNERABLE=true', 'CWE-', 'intentionally vulnerable',
                                   'this is vulnerable', 'exploit_payload']:
                        if marker.lower() in content.lower():
                            ERRORS.append(f"Vulnerability marker '{marker}' in {filepath}")


def check_case_structure(case_dir, case_id, is_solution=False):
    required_files = ['app.py', 'requirements.txt', 'test_app.py', 'run.sh', 'README.md']
    if is_solution:
        required_files.append('FIX_NOTES.md')
    
    for f in required_files:
        path = os.path.join(case_dir, f)
        if not os.path.exists(path):
            ERRORS.append(f"Missing {f} in {case_dir}")


def check_all_cases():
    base = os.path.join(BENCH_ROOT, 'benchmark_targets')
    sol_base = os.path.join(BENCH_ROOT, 'solutions')
    
    cases = {
        'easy': ['CASE-E01', 'CASE-E02', 'CASE-E03'],
        'medium': ['CASE-M01', 'CASE-M02', 'CASE-M03'],
        'hard': ['CASE-H01', 'CASE-H02', 'CASE-H03'],
    }
    
    for level, case_ids in cases.items():
        for case_id in case_ids:
            target_dir = os.path.join(base, level)
            sol_dir = os.path.join(sol_base, level)
            
            found_target = False
            found_solution = False
            
            if os.path.isdir(target_dir):
                for d in os.listdir(target_dir):
                    if d.startswith(case_id):
                        check_case_structure(os.path.join(target_dir, d), case_id)
                        found_target = True
                        break
            
            if os.path.isdir(sol_dir):
                for d in os.listdir(sol_dir):
                    if d.startswith(case_id):
                        check_case_structure(os.path.join(sol_dir, d), case_id, is_solution=True)
                        found_solution = True
                        break
            
            if not found_target:
                ERRORS.append(f"Missing vulnerable case: {case_id} in {target_dir}")
            if not found_solution:
                ERRORS.append(f"Missing fixed solution: {case_id} in {sol_dir}")


def check_answer_key():
    ak = os.path.join(BENCH_ROOT, 'answer_key')
    check_exists(os.path.join(ak, 'benchmark_manifest.json'), 'benchmark_manifest.json')
    check_exists(os.path.join(ak, 'expected_findings.md'), 'expected_findings.md')
    check_exists(os.path.join(ak, 'witness_catalog.md'), 'witness_catalog.md')


def check_scripts():
    check_exists(os.path.join(BENCH_ROOT, 'scripts', 'run_all_safe_checks.sh'), 'run_all_safe_checks.sh')
    check_exists(os.path.join(BENCH_ROOT, 'scripts', 'verify_structure.py'), 'verify_structure.py')


def main():
    check_exists(os.path.join(BENCH_ROOT, 'benchmark_targets'), 'benchmark_targets/')
    check_exists(os.path.join(BENCH_ROOT, 'solutions'), 'solutions/')
    check_exists(os.path.join(BENCH_ROOT, 'answer_key'), 'answer_key/')
    check_exists(os.path.join(BENCH_ROOT, 'scripts'), 'scripts/')
    check_exists(os.path.join(BENCH_ROOT, 'README.md'), 'root README.md')
    
    check_no_answer_key_in_targets()
    check_all_cases()
    check_answer_key()
    check_scripts()
    
    print("=== Structure Verification ===")
    if ERRORS:
        print(f"\nERRORS ({len(ERRORS)}):")
        for e in ERRORS:
            print(f"  [ERROR] {e}")
    
    if WARNINGS:
        print(f"\nWARNINGS ({len(WARNINGS)}):")
        for w in WARNINGS:
            print(f"  [WARN]  {w}")
    
    if not ERRORS:
        print("\n[PASS] All structure checks passed.")
        sys.exit(0)
    else:
        print(f"\n[FAIL] {len(ERRORS)} error(s) found.")
        sys.exit(1)


if __name__ == '__main__':
    main()
