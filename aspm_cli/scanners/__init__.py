from .iac_scanner import IACScanner
from .sast_scanner import SASTScanner
from .sq_sast_scanner import SQSASTScanner
from .secret_scanner import SecretScanner
from .container_scanner import ContainerScanner
from .dast_scanner import DASTScanner

scanner_registry = {
    "IAC": IACScanner,
    "SAST": SASTScanner,
    "SQ-SAST": SQSASTScanner,
    "SECRET": SecretScanner,
    "CONTAINER": ContainerScanner,
    "DAST": DASTScanner,
}