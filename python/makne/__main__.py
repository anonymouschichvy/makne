import sys
import subprocess
from makne import get_executable_path

def main():
    try:
        exe_path = get_executable_path()
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
        
    result = subprocess.run([str(exe_path)] + sys.argv[1:])
    sys.exit(result.returncode)

if __name__ == "__main__":
    main()
