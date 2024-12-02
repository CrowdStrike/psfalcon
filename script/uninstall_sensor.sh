pkg="falcon-sensor"
if [! -d /run/systemd/system ]; then
  echo "systemd is required for uninstallation of $pkg" 1>&2
  exit 1
fi
echo "Starting removal of $pkg"
if type dnf >/dev/null 2>&1; then
  systemd-run dnf remove -q -y "$pkg"
elif type yum >/dev/null 2>&1; then
  systemd-run yum remove -q -y "$pkg"
elif type zypper >/dev/null 2>&1; then
  systemd-run zypper --quiet remove -y "$pkg"
elif type apt >/dev/null 2>&1; then
  systemd-run apt purge -y "$pkg"
else
  systemd-run rpm -e --nodeps "$pkg"
fi