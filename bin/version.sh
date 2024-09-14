#!/bin/sh
set -eux

# Update the version in the package.yaml file
sed -e "s/version:\(\s\+\).*/version:\1$1/g" < package.yaml > package.yaml.tmp
mv package.yaml.tmp package.yaml

# Update the version in the kustomization.yaml file
(cd deploy && kustomize edit set image "images.home.mtaylor.io/iam-mtaylor-io:$1")
