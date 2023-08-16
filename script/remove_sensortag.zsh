IFS=, tag=($(/Applications/Falcon.app/Contents/Resources/falconctl grouping-tags get | sed "s/^No grouping tags set//; s/^Grouping tags: //"))
del=("${(@s/,/)1}")
for i in ${del[@]}
  do tag=("${tag[@]/$i}")
done
tag=$(echo "${tag[@]}" | xargs | tr " " "," | sed "s/,$//")
/Applications/Falcon.app/Contents/Resources/falconctl grouping-tags clear &> /dev/null
/Applications/Falcon.app/Contents/Resources/falconctl grouping-tags set "$tag" &> /dev/null
/Applications/Falcon.app/Contents/Resources/falconctl grouping-tags get | sed "s/^No grouping tags set//; s/^Grouping tags: //"'