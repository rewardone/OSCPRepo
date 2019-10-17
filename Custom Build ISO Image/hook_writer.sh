#!/bin/bash

#usage: hook_writer.sh Name_of_Hook directory git_repo

cat << EOF > $1
#!/bin/bash
mkdir -p $2 2>/dev/null
git clone $3 $2
EOF
