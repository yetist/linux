#!/bin/bash
set -x
name=linux
version=6.3
tarballs=$name-$version-`date +%Y%m%d`.tar.xz

git archive --format=tar.xz --prefix=$name-$version/ -o $tarballs HEAD

if mountpoint /archlinux/ >/dev/null 2>&1;then
    cp $tarballs /archlinux/sources
fi
