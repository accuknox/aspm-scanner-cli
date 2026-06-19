from .iac_scanner import IACScanner
from .sast_scanner import SASTScanner
from .sq_sast_scanner import SQSASTScanner
from .secret_scanner import SecretScanner
from .container_scanner import ContainerScanner
from .dast_scanner import DASTScanner
from .sca_scanner import SCAScanner
from .ml_scan_scanner import MLScanScanner
from .api_discovery_scanner import APIDiscoveryScanner

scanner_registry = {
    "IAC": IACScanner,
    "SAST": SASTScanner,
    "SQ-SAST": SQSASTScanner,
    "SECRET": SecretScanner,
    "CONTAINER": ContainerScanner,
    "DAST": DASTScanner,
    "SCA": SCAScanner,
    "ML-SCAN": MLScanScanner,
    "API-DISCOVERY": APIDiscoveryScanner,
}
