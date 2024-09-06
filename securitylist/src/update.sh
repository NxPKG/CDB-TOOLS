#!/bin/bash

CDBLIST=~/cdb/cdb-database
CVELIST=~/cdb/cvelist

pushd .
# Check out or update the repos
cd $CDBLIST && git pull
cd $CVELIST && git pull
# Update NVD
popd
./update_nvd.py $CDBLIST
./update_gitlab.py $CDBLIST
# Update cvelist
./update_repo.py $CDBLIST $CVELIST "cve.org"
