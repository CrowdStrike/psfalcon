IFS=, tag=($(/Applications/Falcon.app/Contents/Resources/falconctl grouping-tags get | sed "s/^No grouping tags set//; s/^Grouping tags: //"))
tag+=($1)
uniq=$(echo "${tag[@]}" | tr " " "\n" | sort -u | tr "\n" "," | sed "s/,$//")
/Applications/Falcon.app/Contents/Resources/falconctl grouping-tags clear &> /dev/null
/Applications/Falcon.app/Contents/Resources/falconctl grouping-tags set "$uniq" &> /dev/null
/Applications/Falcon.app/Contents/Resources/falconctl grouping-tags get | sed "s/^No grouping tags set//; s/^Grouping tags: //"'