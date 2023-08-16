manager=("$(if [[ $(command -v apt) ]]; then echo "apt-get purge falcon-sensor -y"; elif [[ $(command -v yum) ]]; then echo "yum remove falcon-sensor -y"; elif [[ $(command -v zypper) ]]; then echo "zypper remove -y falcon-sensor"; fi)")
if [[ ${manager} ]]
then
  echo "Started removal of the Falcon sensor"
  eval "sudo ${manager} &" &>/dev/null
else
  echo "apt, yum or zypper must be present to begin removal"
fi