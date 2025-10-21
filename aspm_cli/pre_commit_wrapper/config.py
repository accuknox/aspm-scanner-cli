from pre_commit.commands.install_uninstall import install, uninstall
from pre_commit.store import Store
from pre_commit import git
from pre_commit.constants import CONFIG_FILE
import os

PRE_COMMIT_CONTENT = """repos:
  - repo: local
    hooks:
      - id: accuknox-secret-scan
        name: AccuKnox Secret Scan
        entry:  accuknox-aspm-scanner scan --skip-upload secret --command "git file://." --container-mode
        language: system
        stages: [pre-commit]
        types: [text]
        pass_filenames: false
"""

def handle_pre_commit(args):

    try:
        store = Store()
        git.check_for_cygwin_mismatch()

        # create .pre-commit-config.yaml
        with open(CONFIG_FILE, "w") as f:
            f.write(PRE_COMMIT_CONTENT)

        if args.precommit_cmd == "install":
            exit_code = install(
                CONFIG_FILE,
                store,
                hook_types=None,
                overwrite=True,
                hooks=True,
                # global_install if later supported
                # global_install=args.global
            )
        elif args.precommit_cmd == "uninstall":
            exit_code = uninstall(config_file=CONFIG_FILE, hook_types=None)
        else:
            exit_code = 1

    except Exception as e:
        print(f"Pre-commit failed: {e}")