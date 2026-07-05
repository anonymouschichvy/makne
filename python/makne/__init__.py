import subprocess
import pathlib
import sys
from typing import List

__version__ = "1.0.0"

def get_executable_path() -> pathlib.Path:
    pkg_dir = pathlib.Path(__file__).parent.resolve()
    exe_names = ["makne.exe", "makne"]
    
    # 1. Try using importlib.metadata (best for standard and editable installs)
    try:
        import importlib.metadata
        for f in importlib.metadata.files("makne"):
            if f.name in exe_names:
                resolved_path = f.locate().resolve()
                # Ensure it's the package binary, not the CLI entrypoint script in Scripts/bin
                if resolved_path.is_file() and resolved_path.parent.name == "makne":
                    return resolved_path
    except Exception:
        pass
        
    # 2. Search directly inside the package directory (fallback)
    for name in exe_names:
        path = pkg_dir / name
        if path.exists():
            return path
            
    # 3. Search recursively inside the package directory (subdirectories)
    for name in exe_names:
        for p in pkg_dir.rglob(name):
            if p.is_file():
                return p

    # 4. Search in standard build output directories relative to project root (local editable dev fallback)
    project_root = pkg_dir.parent.parent
    search_dirs = [
        project_root / "build",
        project_root / "build" / "Release",
        project_root / "build" / "Debug",
        project_root / "build" / "MinSizeRel",
        project_root / "build" / "RelWithDebInfo",
    ]
    
    for name in exe_names:
        for sdir in search_dirs:
            if sdir.exists():
                path = sdir / name
                if path.exists():
                    return path
                for p in sdir.rglob(name):
                    if p.is_file():
                        return p

    # 5. Search in parent directory tree (generic fallback for other layouts)
    curr = pkg_dir
    while curr != curr.parent:
        for name in exe_names:
            build_folder = curr / "build"
            if build_folder.is_dir():
                for p in build_folder.rglob(name):
                    if p.is_file():
                        return p
        curr = curr.parent

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
