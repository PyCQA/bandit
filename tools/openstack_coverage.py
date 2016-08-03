#!/usr/bin/env python
#
# Copyright 2015 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Tool for reporting Bandit coverage over OpenStack.

Intended for execution against specific Jenkins and Zuul configuration files
within the openstack-infra/project-config repository.
Parses out Bandit jobs and tests as defined within these configurations.
Prints the summary of results.

If the '-t' (test) option is provided, this tool will attempt to git clone any
project that defines a Bandit job.  Once cloned, it will use tox to run the
defined Bandit job and capture logs for any failures.

TODO: Add detection / handling of bandit.yaml for each project.
TODO: Deal with different branch definitions in the Zuul layout.yaml.
"""

import argparse
import datetime
import os
import requests
import subprocess
import yaml


BASE_URL = "https://git.openstack.org/cgit/"
GIT_BASE = "https://git.openstack.org/"

PATH_INFRA = "openstack-infra/project-config/plain/"
PATH_JENKINS = "jenkins/jobs/projects.yaml"
PATH_PROJECT_LIST = "openstack/governance/plain/reference/projects.yaml"
PATH_ZUUL = "zuul/layout.yaml"

TITLE = "OpenStack Bandit Coverage Report -- {0} UTC".format(
    datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
)

TEST_TYPES = ['experimental', 'check', 'gate']


def get_yaml(url):
    r = requests.get(url)
    if r.status_code == 200:
        data = yaml.load(r.content)
        return(data)
    raise SystemError(
        "Could not obtain valid YAML from specified source ({0})"
        .format(url)
    )


def list_projects(conf_jenkins):
    data = get_yaml("{0}{1}{2}".format(BASE_URL, PATH_INFRA, conf_jenkins))
    # parse data
    bandit_projects = []
    for project in data:
        project_name = project['project']['name']
        project_jobs = project['project']['jobs']
        for job in project_jobs:
            if type(job) == dict and 'gate-{name}-tox-{envlist}' in job:
                if 'bandit' in job['gate-{name}-tox-{envlist}']['envlist']:
                    bandit_projects.append(project_name)

    # output results
    print("Bandit jobs have been defined in the following OpenStack projects:")
    for project in sorted(bandit_projects):
        print(" - {0}".format(project))
    print("\n(Configuration from {0}{1}{2})\n".format(
        BASE_URL, PATH_INFRA, conf_jenkins
    ))
    return bandit_projects


def coverage_zuul(conf_zuul):
    data = get_yaml("{0}{1}{2}".format(BASE_URL, PATH_INFRA, conf_zuul))
    # parse data
    bandit_jobs = {}
    bandit_tests = {key: set() for key in TEST_TYPES}
    for job in data['jobs']:
        if 'bandit' in job['name']:
            if job.get('voting', True) is False:
                bandit_jobs[job['name']] = False
            else:
                bandit_jobs[job['name']] = True
    for project in data['projects']:
        project_name = project['name']
        for test_type in bandit_tests.keys():
            for test in project.get(test_type, []):
                if str(test).endswith('bandit'):
                    voting = bandit_jobs.get(test, False)
                    bandit_tests[test_type].add((project_name, voting))
    # output results
    for test_type in bandit_tests:
        print(
            "\n{0} tests exist for the following OpenStack projects:"
            .format(test_type.capitalize())
        )
        for project in sorted(bandit_tests[test_type]):
            if project[1] is False:
                print(" - {0}".format(project[0]))
            else:
                print(" - {0} (VOTING)".format(project[0]))
    print("\n(Configuration from {0}{1}{2})\n".format(
        BASE_URL, PATH_INFRA, conf_zuul
    ))


def _print_title():
    print("{0}\n{1}\n{0}\n".format(
        "=" * len(TITLE),
        TITLE,
        "=" * len(TITLE)
    ))


def _parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('-t', '--test', dest='do_test', action='store_true',
                        help='Test upstream project Bandit gates.  This will '
                             'clone each upstream project, run Bandit as '
                             'configured in the tox environment, display pass '
                             'status, and save output.')

    parser.set_defaults(do_test=False)

    return parser.parse_args()


def _get_repo_names(project_list):
    # take a list of project names, like ['anchor', 'barbican'], get the
    # corresponding repos for each.  Return a dictionary with the project
    # as the key and the repo as the value.
    project_repos = {key: None for key in project_list}

    yaml_data = get_yaml("{0}{1}".format(BASE_URL, PATH_PROJECT_LIST))

    for project in yaml_data:

        try:
            # if one of the projects we're looking for is listed as a
            # deliverable for this project, look for the first listed repo
            # for that deliverable
            for deliverable in yaml_data[project]['deliverables']:

                if deliverable in project_list:
                    # the deliverable name is the project we're looking for,
                    # store the listed repo name for it
                    project_repos[deliverable] = (yaml_data[project]
                                                  ['deliverables']
                                                  [deliverable]['repos'][0])

        except (KeyError, IndexError):
            # improperly formatted entry, keep going
            pass

    return project_repos


def clone_projects(project_list):
    # clone all of the projects, return the directory name they are cloned in
    project_locations = _get_repo_names(project_list)

    orig_dir = os.path.abspath(os.getcwd())

    # create directory for projects
    try:
        dir_name = 'project-source-{}'.format(datetime.datetime.utcnow().
                                              strftime('%Y-%m-%d-%H-%M-%S'))
        os.mkdir(dir_name)
        os.chdir(dir_name)
    except OSError:
        print("Unable to create directory for cloning projects")
        return None

    for project in project_locations:
        print '=' * len(TITLE)
        print("Cloning project: {} from repo {} into {}".
              format(project, project_locations[project], dir_name))

        try:
            subprocess.check_call(['git', 'clone',
                                   GIT_BASE + project_locations[project]])

        except subprocess.CalledProcessError:
            print("Unable to clone project from repo: {}".
                  format(project_locations[project]))

    os.chdir(orig_dir)

    return os.path.abspath(dir_name)


def run_bandit(source_dir):
    # go through each source directory in the directory which contains source,
    # run Bandit with the established tox job, save results
    orig_dir = os.path.abspath(os.getcwd())

    try:
        fail_results_dir = os.path.abspath('fail_results')
        os.mkdir(fail_results_dir)
    except OSError:
        print("Unable to make results directory")

    os.chdir(source_dir)

    run_success = {}

    for d in os.listdir(os.getcwd()):
        os.chdir(d)

        print '=' * len(TITLE)
        print 'Running tox Bandit in directory {}'.format(d)

        try:
            subprocess.check_output(['tox', '-e', 'bandit'],
                                    stderr=subprocess.STDOUT)

        except subprocess.CalledProcessError as exc:
            run_success[d] = False

            # write log containing the process output
            fail_log_path = fail_results_dir + '/' + d
            with open(fail_log_path, 'w') as f:
                f.write(exc.output)
            print("Bandit tox failed, wrote failure log to {}".
                  format(fail_log_path))

        else:
            run_success[d] = True

        os.chdir(source_dir)

    os.chdir(orig_dir)

    return run_success


def main():
    _print_title()

    args = _parse_args()

    project_list = list_projects(PATH_JENKINS)
    coverage_zuul(PATH_ZUUL)
    print("=" * len(TITLE))

    if args.do_test:
        source_dir = clone_projects(project_list)
        if source_dir:
            results = run_bandit(source_dir)

            # output results table
            print "-" * 50
            print "{:40s}{:10s}".format("Project", "Passed")
            print "-" * 50
            for project in results:
                print "{:40s}{:10s}".format(project, str(results[project]))


if __name__ == "__main__":
    main()
