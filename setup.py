from distutils.core import setup
import glob, sys

NAME='nagios-plugins-argo'
NAGIOSPLUGINS='/usr/lib64/nagios/plugins/argo/'

def get_ver():
    try:
        for line in open(NAME+'.spec'):
            if "Version:" in line:
                return line.split()[1]
    except IOError:
        print "Make sure that %s is in directory"  % (NAME+'.spec')
        sys.exit(1)


setup(name=NAME,
      version=get_ver(),
      license='ASL 2.0',
      author='SRCE, GRNET',
      author_email='dvrcic@srce.hr, themis@grnet.gr',
      description='Package include probes for ARGO components',
      platforms='noarch',
      long_description='''
      This package includes probes for ARGO components.
      Currently it supports the following components:
        - ARGO Web API
        - POEM
      ''',
      url='http://argoeu.github.io/',
      data_files=[(NAGIOSPLUGINS, glob.glob('src/*'))],
      packages=['nagios_plugins_argo'],
      package_dir={'nagios_plugins_argo': 'modules/'},
      )
