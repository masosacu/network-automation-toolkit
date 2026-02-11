#!/bin/bash

# URLs to curl
url1="https://www.facebook.com/"
url2="https://www.dropbox.com/"
url3="https://www.atlassian.com/"
url4="https://slack.com/"
url5="https://www.addictinggames.com/"
url6="https://www.pinterest.com/"
url7="https://www.bbc.com/"
url8="https://www.duolingo.com/"
url9="https://www.bloomberg.com/"
url10="https://example.com/"

# Loading bar
show_loading_bar() {
  local current_set="$1"
  local total_sets="$2"
  local percentage=$((current_set * 100 / total_sets))
  local width=40
  local fill=$(($percentage * $width / 100))
  local empty=$(($width - $fill))
  
  # Create the loading bar
  printf "["
  printf "%${fill}s" "#" | tr ' ' '#'
  printf "%${empty}s" " "
  printf "] $percentage%%\r"
}

# Run curl commands and check for success
run_curl_commands() {
  curl -I -k -s "$url1" > /dev/null
  curl_exit_code_1=$?
  curl -I -k -s "$url2" > /dev/null
  curl_exit_code_2=$?
  curl -I -k -s "$url3" > /dev/null
  curl_exit_code_3=$?
  curl -I -k -s "$url4" > /dev/null
  curl_exit_code_4=$?
  curl -I -k -s "$url5" > /dev/null
  curl_exit_code_5=$?
  curl -I -k -s "$url6" > /dev/null
  curl_exit_code_6=$?
  curl -I -k -s "$url7" > /dev/null
  curl_exit_code_7=$?
  curl -I -k -s "$url8" > /dev/null
  curl_exit_code_8=$?
  curl -I -k -s "$url9" > /dev/null
  curl_exit_code_9=$?
  curl -I -k -s "$url10" > /dev/null
  curl_exit_code_10=$?
  
  if [ $curl_exit_code_1 -eq 0 ] && [ $curl_exit_code_2 -eq 0 ] && [ $curl_exit_code_3 -eq 0 ] && [ $curl_exit_code_4 -eq 0 ] && [ $curl_exit_code_5 -eq 0 ] && [ $curl_exit_code_6 -eq 0 ] && [ $curl_exit_code_7 -eq 0 ] && [ $curl_exit_code_8 -eq 0 ] && [ $curl_exit_code_9 -eq 0 ] && [ $curl_exit_code_10 -eq 0 ]; then
    return 0  # Successful
  else
    return 1  # Failed
  fi
}

# Set initial values
successful_sets=0
total_sets=3  # Total sets of curl commands to run
progress_updated=false

while [ $successful_sets -lt $total_sets ]; do
  if run_curl_commands; then
    successful_sets=$((successful_sets + 1))
    show_loading_bar $successful_sets $total_sets
    progress_updated=true
  else
    echo "One or more curl commands in set $((successful_sets + 1)) failed."
  fi
  
  # Wait for one minute between the first and second sets, and five seconds between the second and third set
  if [ $successful_sets -lt $total_sets ]; then
    if [ $successful_sets -eq 1 ]; then
      sleep 30
    elif [ $successful_sets -eq 2 ]; then
      sleep 5
    fi
  fi
done

# Check if all sets of curl commands were successful
if [ $progress_updated ]; then
  echo "\nThe traffic was successfully generated."
else
  echo "\nNo sets of curl commands were successful."
fi

