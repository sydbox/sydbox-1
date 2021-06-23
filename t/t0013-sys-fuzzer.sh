#!/bin/sh
# Copyright 2021 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

test_description='test fuzzing system calls under SydBox'
. ./test-lib.sh

save_SYDBOX_TEST_OPTIONS="$SYDBOX_TEST_OPTIONS"
SYDBOX_TEST_OPTIONS=''
export SYDBOX_TEST_OPTIONS

for syscall_name in \
        mmap{,2} mprotect ioctl lstat statx \
        access faccessat{,2} open openat{,2} \
        creat chmod fchmodat chown lchown \
        fchownat mkdir{,at} mknod{,at} \
        rmdir truncate utime utimes utimensat \
        futimesat unlink{,at} link{,at} \
        rename renameat{,2} symlink{,at} \
        execve execveat \
        bind connect sendto listen accept{,4} \
        getsockname sendmsg recvmsg \
        {,l}listxattr {,l}setxattr {,l}removexattr \
        mount umount{,2}
do
    for memory_access in 0 1; do
        test_expect_success EXPENSIVE,TRINITY \
            "fuzzing $syscall_name does not generate any failures [memory_access:$memory_access]" '
        sydbox \
            -M '$memory_access' \
            -c "${TEST_DIRECTORY}/test-data/trinity.syd-2" \
            -m "allowlist/write+${HOMER}/***" \
            -- timeout -k3 15 trinity -q --stats -l off -N64 -c '$syscall_name'
'
    done
done

test_done
