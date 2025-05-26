from importlib.metadata import version, PackageNotFoundError

def get_version(package_name="accuknox-aspm-scanner"):
    try:
        return version(package_name)
    except PackageNotFoundError:
        return "unknown"