import os
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Annotated
from typing import Literal
from typing import Optional
from typing import TextIO

import tyro
from mininterface import Validation
from mininterface.validators import not_empty
from tyro.conf import arg
from tyro.conf import Positional
from tyro.conf import UseCounterAction

from ..core import constants
from ..core.extension_loader import Manager


class Level(Enum):
    ALL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4

    @classmethod
    def get_annotation(cls):
        return Optional[
            Literal[tuple(s.lower() for s in Level._member_names_)]
        ]

    @classmethod
    def get(cls, key: str):
        return cls[key.upper()]


def get_env(extension_mgr: Manager):

    output_format_default = (
        "screen"
        if (
            sys.stdout.isatty()
            and os.getenv("NO_COLOR") is None
            and os.getenv("TERM") != "dumb"
        )
        else "txt"
    )

    MutexSev = tyro.conf.create_mutex_group(required=False)
    MutexConfid = tyro.conf.create_mutex_group(required=False)
    MutexVerbosity = tyro.conf.create_mutex_group(required=False)

    @dataclass
    class Env:
        targets: Annotated[Positional[list[Path]], Validation(not_empty)]
        """Source file(s) or directory(s) to be tested"""

        recursive: Annotated[bool, arg(aliases=["-r"])] = False
        """Find and process files in subdirectories"""

        aggregate: Annotated[Literal["file", "vuln"], arg(aliases=["-a"])] = (
            "file"
        )
        """Aggregate output by vulnerability (default) or by filename"""

        context_lines: Annotated[int, arg(aliases=["-n"])] = 3
        """Maximum number of code lines to output for each issue"""

        configfile: Annotated[Optional[Path], arg(aliases=["-c"])] = None
        """Optional config file to use for selecting plugins and overriding defaults"""

        profile: Annotated[Optional[str], arg(aliases=["-p"])] = None
        """Profile to use (defaults to executing all tests)"""

        tests: Annotated[Optional[str], arg(aliases=["-t"])] = None
        """Comma-separated list of test IDs to run"""

        skips: Annotated[Optional[str], arg(aliases=["-s"])] = None
        """Comma-separated list of test IDs to skip"""

        level: Annotated[
            UseCounterAction[int], arg(aliases=["-l"]), MutexSev
        ] = 1
        """Report only issues of a given severity level or higher (-l for LOW, -ll for MEDIUM, -lll for HIGH)"""

        severity_level: Annotated[Level.get_annotation(), MutexSev] = None
        """Report only issues of a given severity level or higher ('all', 'low', 'medium', 'high')"""

        confidence: Annotated[
            UseCounterAction[int], arg(aliases=["-i"]), MutexConfid
        ] = 1
        """Report only issues of a given confidence level or higher (-i for LOW, -ii for MEDIUM, -iii for HIGH)"""

        confidence_level: Annotated[Level.get_annotation(), MutexConfid] = None
        """Report only issues of a given confidence level or higher ('all', 'low', 'medium', 'high')"""

        format: Annotated[
            Literal[tuple(sorted(extension_mgr.formatter_names))],
            arg(aliases=["-f"]),
        ] = output_format_default
        """Specify output format"""

        msg_template: Optional[str] = None
        """Specify output message template (only usable with --format custom)"""

        output: Annotated[
            Optional[Path], arg(aliases=["-o"], help_behavior_hint="")
        ] = None
        """Write report to filename (defaults to stdout)"""

        verbose: Annotated[bool, MutexVerbosity, arg(aliases=["-v"])] = False
        """Output extra information like excluded and included files"""

        debug: Annotated[bool, MutexVerbosity, arg(aliases=["-d"])] = False
        """Turn on debug mode"""

        quiet: Annotated[
            bool, MutexVerbosity, arg(aliases=["-q", "--silent"])
        ] = False
        """Only show output in the case of an error"""

        ignore_nosec: Annotated[
            bool, MutexVerbosity, arg(aliases=["--ignore-nosec"])
        ] = False
        """Do not skip lines with # nosec comments"""

        excluded_paths: Annotated[tuple, arg(aliases=["-x", "--exclude"])] = (
            constants.EXCLUDE
        )
        """List of paths (glob patterns supported) to exclude from scan (note that these are in addition to the excluded paths provided in the config file)"""
        # TODO mají se přidat, ne nahradit
        # TODO zus to pustit

        baseline: Annotated[Optional[str], arg(aliases=["-b"])] = None
        """Path of a baseline report to compare against (only JSON-formatted files)"""

        ini_path: Annotated[Optional[Path], arg(aliases=["--ini"])] = None
        """Path to a .bandit file that supplies command line arguments"""

        exit_zero: bool = False
        """Exit with 0, even with results found"""

    return Env
