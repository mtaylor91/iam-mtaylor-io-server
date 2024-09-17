#!/bin/sh
set -eux

# Update the version in the package.yaml file
sed -e "s/version:\(\s\+\).*/version:\1$1/g" < package.yaml > package.yaml.tmp
mv package.yaml.tmp package.yaml

# Update the source code with the new version
cat <<EOF > src/IAM/Server/Version.hs
{-# LANGUAGE OverloadedStrings #-}
module IAM.Server.Version (version) where
import Data.Text (Text)
version :: Text
version = "$1"
EOF
