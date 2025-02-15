# SPDX-License-Identifier: Apache-2.0
from datetime import datetime
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join("..", "..")))
# -- General configuration ----------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom ones.
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.doctest",
    "sphinx.ext.coverage",
    "sphinx.ext.viewcode",
    "sphinx_copybutton",
]

# autodoc generation is a bit aggressive and a nuisance when doing heavy
# text edit cycles.
# execute "export SPHINX_DEBUG=1" in your terminal to disable

# The suffix of source filenames.
source_suffix = ".rst"

# The root toctree document.
root_doc = "index"

# General information about the project.
project = "Bandit"
copyright = f"{datetime.now():%Y}, Bandit Developers"

# If true, '()' will be appended to :func: etc. cross-reference text.
add_function_parentheses = True

# If true, the current module name will be prepended to all description
# unit titles (such as .. function::).
add_module_names = True

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = "sphinx"

modindex_common_prefix = ["bandit."]

# -- Options for man page output --------------------------------------------

# Grouping the document tree for man pages.
# List of tuples 'sourcefile', 'target', u'title', u'Authors name', 'manual'

man_pages = [
    (
        "man/bandit",
        "bandit",
        "Python source code security analyzer",
        ["PyCQA"],
        1,
    )
]

# -- Options for HTML output --------------------------------------------------

# The theme to use for HTML and HTML Help pages.  Major themes that come with
# Sphinx are currently 'default' and 'sphinxdoc'.
# html_theme_path = ["."]
html_theme = "sphinx_rtd_theme"
# html_static_path = ['static']
html_theme_options = {}

# Output file base name for HTML help builder.
htmlhelp_basename = f"{project}doc"

# Grouping the document tree into LaTeX files. List of tuples
# (source start file, target name, title, author, documentclass
# [howto/manual]).
latex_documents = [
    (
        "index",
        f"{project}.tex",
        f"{project} Documentation",
        "PyCQA",
        "manual",
    ),
]

# Example configuration for intersphinx: refer to the Python standard library.
# intersphinx_mapping = {'http://docs.python.org/': None}
