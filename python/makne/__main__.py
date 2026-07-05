import sys
import subprocess
import pathlib

def main():
    pkg_dir = pathlib.Path(__file__).parent.resolve()
    exe_names = ["makne.exe", "makne"]
    exe_path = None
    for name in exe_names:
        path = pkg_dir / name
        if path.exists():
            exe_path = path
            break
            
    if not exe_path:
        for path in pkg_dir.rglob("makne*"):
            if path.is_file() and not path.suffix == ".lib" and not path.suffix == ".exp":
                exe_path = path
                break
                
    if not exe_path:
        print("Error: Compiled makne executable not found in package.", file=sys.stderr)
        sys.exit(1)
        
    result = subprocess.run([str(exe_path)] + sys.argv[1:])
    sys.exit(result.returncode)

if __name__ == "__main__":
    main()
