IFS=, read -ra tag <<< "$(/opt/CrowdStrike/falconctl -g --tags | sed "s/^Sensor grouping tags are not set//; s/^tags=//; s/.$//"),$1"
IFS=$'\n' uniq=($(printf "%s\n" ${tag[*]} | sort -u | xargs))
uniq="$(echo ${uniq[*]} | tr " " ",")"
/opt/CrowdStrike/falconctl -d -f --tags
/opt/CrowdStrike/falconctl -s --tags="$uniq"
/opt/CrowdStrike/falconctl -g --tags | sed "s/^Sensor grouping tags are not set//; s/^tags=//; s/.$//"