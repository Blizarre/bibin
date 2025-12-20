#!/bin/bash

# These are integration smoketests. They should be moved into a proper test framework, along with unit
# tests. The goal for now is just to have some basic things tested in a github workflow.

set -euo pipefail

function exit_script {
  if [[ ${bibin_pid-} != "" ]]; then
    echo "Cleaning up $bibin_pid"
    kill "$bibin_pid"
  else
    echo "No server was started"
  fi
}

function error_script {
  echo "ERROR on line ${BASH_LINENO[0]}"
}

function assert_equal {
    if ! test "$1" = "$2"; then
      echo "'$1' != '$2'"
      exit 1
    fi
}

trap error_script ERR
trap exit_script EXIT
type=${1-full}

prefix=http://localhost:8000
password=delimiter3
browser_agent="Mozilla/5.0 (X11; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0"

DB_FILE=tests.db
rm -f "$DB_FILE"{,-shm,-wal}
env "ROCKET_SECRET_KEY=jhqTG1chy13SzpyT1whkK+oIpfmN+RQRzA60DxkTG64="\
    "ROCKET_PASSWORD_HASH=\$argon2id\$v=19\$m=19456,t=2,p=1\$8UejUJOkJFwAYhlotVYv5A\$SmVAPeWAChwch78ooZu9zTmhskiijez2tZ9P2cDmnXI"\
    "ROCKET_MAX_ENTRIES"=10000\
    "ROCKET_ID_LENGTH"=4\
    "ROCKET_DATABASE_FILE=$DB_FILE"\
    "ROCKET_PREFIX=$prefix"\
    cargo run --release --bin bibin&

bibin_pid=$!

while ! curl -fs "$prefix" > /dev/null; do
  sleep 0.5
done
echo "Bibin started, testing"

echo "#### Check that after uploading some data with curl (X-API-Key header), we can get it back as text with curl"
sample_data1="hello world"
url="$(curl -X PUT -H "X-API-Key: $password" --data "$sample_data1" "$prefix")"
assert_equal "$(curl -fs "$url")" "$sample_data1"

echo "#### Check that we can override values given an id"
sample_dataX="hello world 1111"
sample_dataY="hello world 2222"
url="$(curl -X PUT -u":$password" --data "$sample_dataX" $prefix/q)"
assert_equal "$(curl -fs "$url")" "$sample_dataX"
assert_equal "$url" "$prefix/q"
curl -X POST -d "val=$sample_dataY" -d "password=$password" "$prefix/q"
assert_equal "$(curl -fs "$url")" "$sample_dataY"

echo "#### Check that after uploading some data with curl (Authorization header), we can delete it"
url="$(curl -X PUT -u "a:$password" --data "$sample_data1" "$prefix")"
curl -X DELETE -u "a:$password" "$url"
# Retrieving or deleting it should fail now
if curl -fs "$url"; then false; fi
if curl -fs -X DELETE -u "a:$password" "$url"; then false; fi

echo "#### Check that after uploading some data with curl (Authorization header), we can get it back as text with curl"
url="$(curl -X PUT -u "a:$password" --data "$sample_data1" "$prefix")"
assert_equal "$(curl -fs "$url")" "$sample_data1"

echo "#### Check that after uploading some data with curl, we can get it back as html with a browser"
assert_equal "$(curl -H "User-Agent: $browser_agent" -fs "$url" | head -n1)"  "<!DOCTYPE html>"

echo "#### Check that after uploading some data with curl, we can get the URL of the post back as a qr code (png file)"
assert_equal "$(curl -fs "$url/qr" | head -c 8)"  "$(echo -ne "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A")"

echo "#### Check that after uploading some data with curl, we can get it back as a qr code (png file)"
assert_equal "$(curl -fs "$url.qr" | head -c 8)"  "$(echo -ne "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A")"

echo "#### Check that after uploading some data with a browser (POST), we can get it back as text with curl"
sample_data2="hello world 2"
data_after_redirect="$(curl -L -fs \
            -d password="$password" -d val="$sample_data2" "$prefix")"
assert_equal "$data_after_redirect" "$sample_data2"


if [[ $type == full ]]; then
    echo "#### Check that it can handle 10'000 requests (There will be ID collisions)"
    num=0
    while test "$num" -lt 2500; do
        curl -L -fs -d password="$password" -d val="$sample_data1 - $num" "$prefix" > /dev/null&
        bg_process1="$!"

        curl -L -fs -d password="$password" -d val="$sample_data1 - $num" "$prefix" > /dev/null&
        bg_process2="$!"

        curl -L -fs -d password="$password" -d val="$sample_data1 - $num" "$prefix" > /dev/null&
        bg_process3="$!"

        url="$(curl -fs -X PUT -H "X-API-Key: $password" --data "$sample_data2 - $num" "$prefix")"
        assert_equal "$(curl -fs "$url")" "$sample_data2 - $num"
        wait "$bg_process1" "$bg_process2" "$bg_process3"
        num="$(( num + 1 ))"
        echo "*** $(date +'%T') Done round $num"
    done
fi

echo "#### Testing invalid credentials"
if curl -fs -X PUT -H "X-API-Key: dummy" --data "$sample_data2" "$prefix"; then false; fi
if curl -fs -X PUT -H "X-API-Key" --data "$sample_data2" "$prefix"; then false; fi
if curl -fs -X PUT -H "Authorization: basic ffffffff" --data "$sample_data2" "$prefix"; then false; fi
if curl -fs -X PUT -u "b:" --data "$sample_data2" "$prefix"; then false; fi
if curl -fs -X PUT -H "X-API-Key: $password\0" --data "$sample_data2" "$prefix"; then false; fi

echo "All tests OK"
