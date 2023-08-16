IFS=, && read -ra del <<< "$1" && read -ra tag <<< "$(/opt/CrowdStrike/falconctl -g --tags | sed "s/^Sensor grouping tags are not set.//; s/^tags=//; s/.$//")"
if [[ ${tag[@]} ]]; then
  /opt/CrowdStrike/falconctl -d -f --tags
  for i in ${del[@]}; do tag=(${tag[@]/$i}); done
  IFS=$'\n' && val=($(printf "%s\n" ${tag[*]} | xargs)) && val="$(echo ${val[*]} | tr " " ",")"
  /opt/CrowdStrike/falconctl -s --tags="$val"
fi
/opt/CrowdStrike/falconctl -g --tags | sed "s/^Sensor grouping tags are not set.//; s/^tags=//; s/.$//"