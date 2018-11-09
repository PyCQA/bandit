#!/bin/bash

if [[ $TRAVIS_OS_NAME == 'osx' ]]; then
    brew update
    brew upgrade pyenv

    case "${TOXENV}" in
        py27)
            pyenv install 2.7
            pyenv local 2.7
            ;;
        py35)
            pyenv install 3.5.6
            pyenv local 3.5.6
            ;;
        py36)
            pyenv install 3.6.7
            pyenv local 3.6.7
            ;;
        py37)
            pyenv install 3.7.1
            pyenv local 3.7.1
            ;;
        pypy)
            pyenv install pypy3.5-6.0.0
            pyenv local pypy3.5-6.0.0
            ;;
    esac

    brew install pyenv-virtualenv

fi
