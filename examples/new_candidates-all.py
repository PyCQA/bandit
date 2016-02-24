import xml
import yaml

def subprocess_shell_cmd():
    # sample function with known subprocess shell cmd candidates
    # candidate #1
    subprocess.Popen('/bin/ls *', shell=True)
    # candidate #2
    subprocess.Popen('/bin/ls *', shell=True) # nosec

def yaml_load():
    # sample function with known yaml.load candidates
    temp_str = yaml.dump({'a': '1', 'b': '2'})
    # candidate #3
    y = yaml.load(temp_str)
    # candidate #4
    y = yaml.load(temp_str) # nosec

def xml_sax_make_parser():
    # sample function with known xml.sax.make_parser candidates
    # candidate #5
    xml.sax.make_parser()
    # candidate #6
    xml.sax.make_parser() # nosec
