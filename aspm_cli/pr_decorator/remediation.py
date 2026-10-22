"""
Optional LLM-generated remediation for SAST findings that have no native
`fix` (~10% of the scanner rules carry one - see render.load_findings). Ported
from PR-Decorator's generate_remediation.py, swapping urllib for `requests`
(already a dependency here, see utils/common.py).

No --llm-api-key / LLM_API_KEY set -> enrich_with_remediation() is a no-op:
no LLM call, no cost, findings post as-is. That's the point, not a fallback
- a repo turns this on with one secret and nothing else, same as the
original composite action's `llm-api-key` input.
"""
import json

import requests

from aspm_cli.utils.logger import Logger

DEFAULT_BASE_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "openai/gpt-4o-mini"
_TIMEOUT = 30


def _build_prompt(result):
    extra = result["extra"]
    return (
        "You are generating a remediation suggestion for a static analysis finding.\n\n"
        f"Rule: {result['check_id']}\n"
        f"File: {result['path']}\n"
        f"Issue: {extra.get('message', '')}\n\n"
        f"Code:\n```\n{extra.get('lines', '')}\n```\n\n"
        "Reply with ONLY the corrected code snippet - no explanation, "
        "no markdown fences, just the fixed lines."
    )


def _call_llm(base_url, api_key, prompt, model):
    resp = requests.post(
        base_url,
        json={"model": model, "messages": [{"role": "user", "content": prompt}], "max_tokens": 300},
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            # OpenRouter-specific attribution headers - harmless no-ops on any other
            # OpenAI-compatible endpoint (OpenAI, Azure OpenAI, self-hosted vLLM/Ollama, ...).
            "HTTP-Referer": "https://github.com/accuknox/aspm-scanner-cli",
            "X-Title": "AccuKnox PR Decorator",
        },
        timeout=_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"].strip()


def enrich_with_remediation(sast_result_path, changed_files=None, api_key=None,
                             model=DEFAULT_MODEL, base_url=DEFAULT_BASE_URL):
    """Mutates the SAST result file in place, adding extra.remediation to
    every in-scope finding that has no native fix - which render.load_findings
    already reads via `extra.get("fix") or extra.get("remediation")`, so
    nothing downstream needs to change to pick it up.

    Returns the number of remediations generated. No-op (returns 0) without
    an api_key - callers never need to check that themselves first."""
    logger = Logger.get_logger()
    if not api_key:
        logger.debug("No LLM API key set - skipping AI remediation.")
        return 0

    with open(sast_result_path) as f:
        data = json.load(f)

    generated = 0
    for r in data.get("results", []):
        if changed_files is not None and r["path"] not in changed_files:
            continue
        if r.get("fix") or r["extra"].get("fix"):
            continue
        try:
            r["extra"]["remediation"] = _call_llm(base_url, api_key, _build_prompt(r), model)
            generated += 1
        except requests.RequestException as e:
            logger.warning(f"AI remediation failed for {r['check_id']} @ {r['path']}: {e}")
            r["extra"]["remediation"] = None

    if generated:
        with open(sast_result_path, "w") as f:
            json.dump(data, f, indent=2)
        logger.info(f"Generated {generated} AI remediation suggestion(s).")
    return generated
