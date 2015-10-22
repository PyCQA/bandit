
use_of_mako_templates
=====================

Description
-----------
Mako is a Python templating system often used to build web applications. It is
the default templating system used in Pylons and Pyramid. Unlike Jinja2 (an
alternative templating system), Mako has no environment wide variable escaping
mechanism. Because of this, all input variables must be carefully escaped before
use to prevent possible vulnerabilities to Cross Site Scripting (XSS) attacks.

See also:

- :doc:`jinja2_autoescape_false`.


Available Since
---------------
 - Bandit v0.10.0

Config Options
--------------
None

Sample Output
-------------
.. code-block:: none

    >> Issue: Mako templates allow HTML/JS rendering by default and are
    inherently open to XSS attacks. Ensure variables in all templates are
    properly sanitized via the 'n', 'h' or 'x' flags (depending on context).
    For example, to HTML escape the variable 'data' do ${ data |h }.
       Severity: Medium   Confidence: High
       Location: ./examples/mako_templating.py:10
    9
    10  mako.template.Template("hern")
    11  template.Template("hern")


References
----------
- http://www.makotemplates.org/
- https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)
- https://security.openstack.org
- https://security.openstack.org/guidelines/dg_cross-site-scripting-xss.html

