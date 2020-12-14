"""
Unit tests for vcs_ library.

While some tests are implemented for a specific backend, a huge number
is completely independent of the underlying backend.

For such independent tests a base testing class is implemented, and
backend-specific test classes are defined. These sub-classes simply
need to set the correct backend to use by setting the
``backend_alias`` property, which should correspond to one of the keys
from ``vcs.backends.BACKENDS``.
"""

import os


# Base directory for the VCS tests.
VCS_TEST_MODULE_BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Path to user configuration file used during tests.
TEST_USER_CONFIG_FILE = os.path.join(VCS_TEST_MODULE_BASE_DIR, 'aconfig')
