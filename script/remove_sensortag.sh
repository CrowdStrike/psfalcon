IFS=, && read -ra del <<< "$1" && read -ra tag <<< "$(/opt/CrowdStrike/falconctl -g --tags | sed "s/^Sensor grouping tags are not set.//; s/^tags=//; s/.$//")"
if [[ ${tag[@]} ]]; then
  /opt/CrowdStrike/falconctl -d -f --tags
  for todelete in ${del[@]}
  do
    for i in "${!tag[@]}"
    do
      if [ ${tag[i]} = $todelete ]
      then
        unset 'tag[i]'
      fi
    done
  done
  val="$(echo ${tag[@]} | tr ' ' ',')"
  /opt/CrowdStrike/falconctl -s --tags="$val"
fi
/opt/CrowdStrike/falconctl -g --tags | sed "s/^Sensor grouping tags are not set.//; s/^tags=//; s/.$//"