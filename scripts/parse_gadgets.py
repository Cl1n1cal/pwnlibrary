#!/usr/bin/python3

import sys
import os


if len(sys.argv) != 2:
    print("Error in parse_gadgets.py")
    print("Usage: python3 parse_gadgets.py <rop_gadgets_file.txt>")
    exit(1)

input_file = sys.argv[1]
input_name, ext = os.path.splitext(input_file)
output_file = f"{input_name}_results.txt"

results = []

try:
    with open(input_file, "r") as file:
        results.append("Found rop gadgets")
        for line in file:
            if "pop rdi" in line:
                if "ret" in line:
                    results.append(line.strip())
            
            if "pop rsi" in line:
                if "ret" in line:
                    results.append(line.strip())

            if "pop rdx" in line:
                if "ret" in line:
                    results.append(line.strip())

            if "pop rax" in line:
                if "ret" in line:
                    results.append(line.strip())

            if "syscall" in line:
                results.append(line.strip())

            if "mov qword ptr [rax]" in line:
                if "ret" in line:
                    results.append(line.strip())

   # Write results to the dynamically named output file
    with open(output_file, "w") as file:
        for result in results:
            file.write(result + "\n")
            
except FileNotFoundError:
    print(f"Error: The file '{input_file}' does not exist.")
    exit(1)

except Exception as e:
    print(f"An unexpected error occurred: {e}")
    exit(1)