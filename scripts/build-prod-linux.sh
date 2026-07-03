#!/usr/bin/env sh
set -eu
export SHADOW_SSH_BUILD_CHANNEL=production
export NODE_ENV=production
npm run build:prod-linux
