COMMANDS="-ex 'set follow-fork-mode child' -ex 'catch fork'"
COMMANDS=${COMMANDS}" -ex r"
# COMMANDS=${COMMANDS}" -ex c"
# COMMANDS=${COMMANDS}" -ex 'set follow-fork-mode parent'"

echo "executing: doas egdb ${COMMANDS} dh6client"
doas egdb ${COMMANDS} dh6client
