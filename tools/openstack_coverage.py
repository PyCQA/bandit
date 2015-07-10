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

TODO: Add detection / handling of bandit.yaml for each project.
TODO: Deal with different branch definitions in the Zuul layout.yaml.
"""

import datetime
import requests
import yaml


BASE_URL = "https://git.openstack.org/cgit/"
PATH_INFRA = "openstack-infra/project-config/plain/"

PATH_JENKINS = "jenkins/jobs/projects.yaml"
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


def coverage_jenkins(conf_jenkins):
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
                if test.endswith('bandit'):
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


def main():
    print("{0}\n{1}\n{0}\n".format(
        "=" * len(TITLE),
        TITLE,
        "=" * len(TITLE)
    ))
    coverage_jenkins(PATH_JENKINS)
    coverage_zuul(PATH_ZUUL)
    print("=" * len(TITLE))


if __name__ == "__main__":
    main()
