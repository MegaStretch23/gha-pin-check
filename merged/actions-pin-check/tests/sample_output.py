"""Prints the README quickstart transcript: runs the CLI on tests/samples/node.js.yml (a real public workflow, see SOURCE.txt). No network.
Run:  python3 -I tests/sample_output.py"""
import os, subprocess, sys
here = os.path.dirname(os.path.abspath(__file__))

def main():
    cli = os.path.join(os.path.dirname(here), "actions_pin_check.py")
    p = subprocess.run([sys.executable, "-I", cli, "node.js.yml"], capture_output=True, text=True, cwd=os.path.join(here, "samples"))
    print("$ python3 -I actions_pin_check.py node.js.yml"); print(p.stdout.rstrip()); print(f"(exit code {p.returncode})")

if __name__ == "__main__":
    main()
