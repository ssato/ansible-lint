"""Constants used by AnsibleLint."""
import os.path


DEFAULT_RULESDIR = os.path.join(os.path.dirname(__file__), 'rules')
DEFAULT_CUSTOM_RULESDIR = os.path.join(DEFAULT_RULESDIR, "custom")

INVALID_CONFIG_RC = 2
ANSIBLE_FAILURE_RC = 3
