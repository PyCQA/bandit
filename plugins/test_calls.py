##
# generic tests against Call nodes
##

from bandit import utils
import _ast
import stat

def call_bad_names(context):
    bad_name_sets = [
        (['pickle.loads', 'pickle.dumps', ],
         'Pickle library appears to be in use, possible security issue.'),
        (['hashlib.md5', ],
         'Use of insecure MD5 hash function.'),
        (['subprocess.Popen', ],
         'Use of possibly-insecure system call function '
         '(subprocess.Popen).'),
        (['subprocess.call', ],
         'Use of possibly-insecure system call function '
         '(subprocess.call).'),
        (['tempfile.mktemp', 'mktemp' ],
         'Use of insecure and deprecated function (mktemp).'),
        (['eval', ],
         'Use of possibly-insecure function - consider using the safer '
         'ast.literal_eval().'),
    ]

    # test for 'bad' names defined above
    for bad_name_set in bad_name_sets:
        for bad_name in bad_name_set[0]:
            # if name.startswith(bad_name) or name.endswith(bad_name):
            if context['qualname'] == bad_name:
                return('WARN', "%s  %s" %
                       (bad_name_set[1],
                        utils.ast_args_to_str(context['call'].args)))


def call_subprocess_popen(context):
    if context['qualname'] == 'subprocess.Popen':
        if hasattr(context['call'], 'keywords'):
            for k in context['call'].keywords:
                if k.arg == 'shell' and isinstance(k.value, _ast.Name):
                    if k.value.id == 'True':
                        return('ERROR', 'Popen call with shell=True '
                               'identified, security issue.  %s' %
                               utils.ast_args_to_str(context['call'].args))


def call_no_cert_validation(context):
    if 'requests' in context['qualname'] and ('get' in context['name'] or
                                          'post' in context['name']):
        if hasattr(context['call'], 'keywords'):
            for k in context['call'].keywords:
                if k.arg == 'verify' and isinstance(k.value, _ast.Name):
                    if k.value.id == 'False':
                        return('ERROR',
                               'Requests call with verify=False '
                               'disabling SSL certificate checks, '
                               'security issue.   %s' %
                               utils.ast_args_to_str(context['call'].args))

def call_bad_permissions(context):
    if 'chmod' in context['name']:
        if (hasattr(context['call'], 'args')):
            args = context['call'].args
            if len(args) == 2 and isinstance(args[1],  _ast.Num):
                if ((args[1].n & stat.S_IWOTH) or
                   (args[1].n & stat.S_IXGRP)):
                    filename = args[0].s if hasattr(args[0], 's') else 'NOT PARSED'
                    return('ERROR',
                           'Chmod setting a permissive mask '
                           '%s on file (%s).' %
                           (oct(args[1].n), filename))

def call_wildcard_injection(context):
    system_calls = ['os.system', 'subprocess.Popen', 'os.popen']
    vulnerable_funcs = ['chown', 'chmod', 'tar', 'rsync']
    
    for system_call in system_calls:
        if system_call in context['qualname']:
            if(hasattr(context['call'], 'args') and 
                    len(context['call'].args)==1 and
                    hasattr(context['call'].args[0], 's')):
                call_argument = context['call'].args[0].s
                for vulnerable_func in vulnerable_funcs:
                    if vulnerable_func in call_argument and '*' in call_argument:
                        return('ERROR', 'Possible wildcard injection in call: %s' % context['qualname'])
