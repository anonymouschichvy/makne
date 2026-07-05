import subprocess
import pathlib
import sys
from typing import List

__version__ = "1.0.0"

def get_executable_path() -> pathlib.Path:
    pkg_dir = pathlib.Path(__file__).parent.resolve()
    exe_names = ["makne.exe", "makne"]
    for name in exe_names:
        path = pkg_dir / name
        if path.exists():
            return path
        # Try recursive search (e.g. in bin/)
        for p in pkg_dir.rglob(name):
            if p.is_file():
                return p
    raise FileNotFoundError("makne executable not found in package.")

def obfuscate(input_path: str, output_path: str, options: List[str] = None) -> int:
    """
    Run the makne engine to obfuscate a PE binary.
    
    :param input_path: Path to the input PE binary.
    :param output_path: Path to the output PE binary.
    :param options: List of command-line options/flags (e.g. ['--polymorphic', '--substitution']).
    :return: Return code of the process (0 for success).
    """
    exe_path = get_executable_path()
    args = [str(exe_path), input_path, output_path]
    if options:
        args.extend(options)
    
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
    return result.returncode
