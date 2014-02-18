define security::access (
  $permission,
  $entity     = $title,
  $origin,
  $ensure     = present,
  $priority   = '10'
) {
  include security

  if ! ($::osfamily in ['Debian', 'RedHat', 'Suse']) {
    fail("security::access does not support osfamily $::osfamily")
  }

  if ! ($permission in ['+', '-']) {
    fail("Permission must be + or - ; recieved $permission")
  }

  realize Concat['/etc/security/access.conf']

  concat::fragment { "security::access $permission$entity$origin":
    ensure  => $ensure,
    target  => '/etc/security/access.conf',
    content => "${permission}:${entity}:${origin}\n",
    order   => $priority,
  }

}
