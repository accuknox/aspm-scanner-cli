import yaml
import operator as op

from aspm_cli.utils.logger import Logger

OPERATORS = {
    "greater_than": op.gt,
    "less_than": op.lt,
    "greater_or_equal": op.ge,
    "less_or_equal": op.le,
    "equals": op.eq
}


def policy_threshold_triggered(findings):
    """
    Evaluate a list of findings against thresholds in a policy YAML.

    Args:
        findings (list): List of dicts, each with at least a 'severity' key.
    Returns:
        bool: True if any FAIL action is triggered by the policy.
    """
    policy_file: str = "policy.yaml"
    try:
        with open(policy_file, 'r') as pf:
            policy = yaml.safe_load(pf)

        rules = policy.get("rules", {})
        severity_counts = {}

        # Count findings per severity
        for finding in findings:
            severity = finding.get("severity", "").lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Evaluate thresholds
        for severity, rule in rules.items():
            count = severity_counts.get(severity, 0)
            condition = rule.get("condition", {})
            operator_func = OPERATORS.get(condition.get("operator"))

            if operator_func and operator_func(count, condition.get("value", 0)):
                if rule.get("action", "").upper() == "FAIL":
                    Logger.get_logger().warning(f"Policy violation: {severity.upper()} count = {count}")
                    return True

        return False

    except Exception as e:
        Logger.get_logger().error(f"Error evaluating policy: {e}")
        raise
