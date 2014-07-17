##
# tests targeting Import and ImportFrom nodes in the AST
##


def import_name_match(context):
    info_on_import = ['pickle', 'subprocess', 'Crypto']
    for module in info_on_import:
        if context['module'] == module:
            return('INFO',
                   "Consider possible security implications"
                   " associated with '%s' module" % module)


def import_name_telnetlib(context):
    if context['module'] == 'telnetlib':
        return('ERROR', "Telnet is considered insecure. Use SSH or some"
               " other encrypted protocol.")
