#!/bin/sh
set -eux
api-mtaylor-io server --admin-email $ADMIN_EMAIL --admin-public-key $ADMIN_PUBLIC_KEY
