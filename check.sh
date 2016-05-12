#!/bin/bash
if [ ! $# == 2 ]; then
  echo "Usage: $0 path_name branch_name"
  exit
fi

path="$1"
brch="$2"

if [ ! -d "manifest" ]; then
  git clone gitadmin@gitsrv01.spreadtrum.com:android/platform/manifest.git
fi

cd 'manifest'

for branch in `git branch -a | grep remotes | grep -v HEAD | grep -v master`; do
  git branch --track ${branch#remotes/origin/} $branch >> /dev/null 2>&1
done

git pull --all

for search in `git branch | cut -c 3-`; do
  if [ ${search:1:11} == ${brch:1:11} ]; then
    #echo "$search"
    result=`git grep -e ''$path'' --and -e ''$brch'' "refs/heads/$search"`
    if [ -n "$result" ]; then
      echo "$result"
      echo -n 'Caution! '
      echo -en '\E[35;40m'$search''; tput sgr0
      echo -en ' also use ' 
      echo -e '\E[35;40m'$brch''; tput sgr0
    fi
  fi
done

cd '..'
