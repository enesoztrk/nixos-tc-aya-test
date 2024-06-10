


#!/bin/bash
rm -rf target
# Default values
hook="ingress"
build_type="debug"
program_type="block_ip"
log="true"
file="file.txt"
#cargo xtask run -- $1 $2 $3 $4
#sudo route del -net 192.168.58.0 gw 0.0.0.0 netmask 255.255.255.0 dev enp0s3
# Function to display usage information
usage() {
    echo "Usage: $0 [-h] [-k hook] [-b build_type] [-p program_type]"
    echo "Options:"
    echo "  -h               Display this help message"
    echo "  -k hook          Set the hook (ingress/egress) [default: ingress]"
    echo "  -b build_type    Set the build type (debug/release) [default: debug]"
    echo "  -p program_type  Set the program type (block_ip/sync_flood) [default: block_ip]"
    echo "  -f file          Set the file name"
    echo "  -l log           Set the log functionality"
    exit 1
}

# Parse command-line options
while getopts ":hk:b:p:f:l:" opt; do
    case $opt in
        h) usage ;;
        k) hook="$OPTARG" ;;
        b) build_type="$OPTARG" ;;
        p) program_type="$OPTARG" ;;
        f) file="$OPTARG" ;;
        l) log="$OPTARG" ;;
        \?) echo "Invalid option: -$OPTARG" >&2; usage ;;
        :) echo "Option -$OPTARG requires an argument." >&2; usage ;;
    esac
done

# Shift to get rid of the parsed options
shift $((OPTIND -1))
# Now you can use $hook, $build_type, and $program_type variables as needed
echo "Hook: $hook"
echo "Build type: $build_type"
echo "Program type: $program_type"

./build.sh -k $hook -b $build_type -p $program_type || exit 1
sudo ./target/$build_type/tc-aya --log "$log" --file "$file"  || exit 1

exit 0


 
# Run cargo commands with options
if [ "$build_type" == "release" ]; then
    cargo xtask run  --release --features "$hook $program_type"  -- --log $log --file $file
else
    cargo xtask run  --features "$hook $program_type" --  --log "$log" --file "$file" 
fi