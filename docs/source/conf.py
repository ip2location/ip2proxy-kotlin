# Configuration file for the Sphinx documentation builder.
# Read https://www.sphinx-doc.org/en/master/usage/configuration.html for more options available

# -- Project information

project = 'IP2Proxy Kotlin'
copyright = '2025, IP2Location'
author = 'IP2Location'

release = '0.1.0'
version = '0.1.0'

# -- General configuration

extensions = [
    'sphinx.ext.duration',
    'sphinx.ext.doctest',
    'myst_parser',
    'sphinx_copybutton',
]

# https://myst-parser.readthedocs.io/en/latest/syntax/optional.html

myst_enable_extensions = [
    "colon_fence",
    "deflist",
    "fieldlist",
]

# https://myst-parser.readthedocs.io/en/latest/configuration.html#setting-html-metadata
myst_html_meta = {
    "description": "IP2Proxy Kotlin can be used to find the IP addresses which are used as VPN anonymizer, open proxies, web proxies and Tor exits.",
    "keywords": "IP2Proxy, Proxy, IP location, Kotlin",
    "google-site-verification": "DeW6mXDyMnMt4i61ZJBNuoADPimo5266DKob7Z7d6i4",
}

# templates_path = ['_templates']

# -- Options for HTML output

html_theme = 'sphinx_book_theme'

html_theme_options = {
    "use_edit_page_button": False,
    "use_source_button": False,
    "use_issues_button": False,
    "use_download_button": False,
    "use_sidenotes": False,
}

# The name of an image file (relative to this directory) to place at the top
# of the sidebar.
html_logo = 'images/ipl-logo-square-1200.png'

# Favicon
html_favicon = 'images/favicon.ico'

html_title = "IP2Proxy Kotlin"

# html_baseurl = "https://ip2proxy-java.readthedocs.io/en/latest/"