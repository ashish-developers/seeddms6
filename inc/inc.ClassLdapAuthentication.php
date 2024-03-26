<?php
/**
 * Implementation of user authentication
 *
 * @category  DMS
 * @package   SeedDMS
 * @author    Uwe Steinmann <uwe@steinmann.cx>
 * @license   GPL 2
 * @version   @version@
 * @copyright 2010-2016 Uwe Steinmann
 * @version   Release: @package_version@
 */

require_once "inc.ClassAuthentication.php";

/**
 * Abstract class to authenticate user against ldap server
 *
 * @category  DMS
 * @package   SeedDMS
 * @author    Uwe Steinmann <uwe@steinmann.cx>
 * @copyright 2010-2016 Uwe Steinmann
 * @version   Release: @package_version@
 */
class SeedDMS_LdapAuthentication extends SeedDMS_Authentication {

  var $dms;

	var $settings;

	protected function addUser($username, $info) {
		return $this->dms->addUser($username, null, $info['cn'][0], isset($info['mail']) ? $info['mail'][0] : '', $this->settings->_language, $this->settings->_theme, "User was added from LDAP");
	}

	protected function updateUser($user, $info) {
		if(isset($info['cn'][0]) && ($info['cn'][0] != $user->getFullName())) {
			$user->setFullName($info['cn'][0]);
		}
		if(isset($info['mail'][0]) && ($info['mail'][0] != $user->getEmail())) {
			$user->setEmail($info['mail'][0]);
		}
	}

	protected function syncGroups($user, $ldapgroups) {
		$groupnames = [];
		$count = 0;
		if(isset($ldapgroups['count']))
			$count = (int) $ldapgroups['count'];
		for ($i = 0; $i < $count; $i++) {
			$tmp = ldap_explode_dn($ldapgroups[$i], 1);
			if (!in_array($tmp[0], $groupnames)) {
				$groupnames[] = $tmp[0];
			}
		}

		/* Remove user from all groups not listed in LDAP */
		$usergroups = $user->getGroups();
		foreach($usergroups as $usergroup) {
			if(!in_array($usergroup->getName(), $groupnames))
				$user->leaveGroup($usergroup);
		}

		/* Add new groups and make user a member of it */
		if($groupnames) {
			foreach($groupnames as $groupname) {
				$group = $this->dms->getGroupByName($groupname);
				if($group) { /* Group already exists, just join it */
					$user->joinGroup($group);
				} else { /* Add group and join it */
					$newgroup = $this->dms->addGroup($groupname, 'Added during LDAP Authentication');
					if($newgroup) {
						$user->joinGroup($newgroup);
					}
				}
			}
		}
	}

  public function __construct($dms, $settings) { /* {{{ */
    $this->dms = $dms;
    $this->settings = $settings;
  } /* }}} */

	/**
	 * Do ldap authentication
	 *
	 * This method supports active directory and open ldap servers. Others may work but
	 * are not tested.
	 * The authentication is done in two steps.
	 * 1. First an anonymous bind is done and the user who wants to login is searched
	 * for. If it is found the cn of that user will be used for the bind in step 2.
	 * If the user cannot be found the second step will use a cn: cn=<username>,<basedn>
	 * 2. A second bind with a password and cn will be executed. This is the actuall
	 * authentication. If that succeeds the user is logged in. If the user doesn't
	 * exist in the database, it will be created.
	 *
	 * @param string $username name of user to authenticate
	 * @param string $password password of user to authenticate
	 * @return object|boolean user object if authentication was successful otherwise false
	 */
	public function authenticate($username, $password) { /* {{{ */
		$settings = $this->settings;
		$dms = $this->dms;

		if (isset($settings->_ldapPort) && is_int($settings->_ldapPort)) {
			$ds = ldap_connect($settings->_ldapHost, $settings->_ldapPort);
		} else {
			$ds = ldap_connect($settings->_ldapHost);
		}

		if (!is_bool($ds)) {
			/* Check if ldap base dn is set, and use ldap server if it is */
			/* $tmpDN will be set to a 'wild' guess how the user's dn might
			 * look like if searching for that user didn't return a dn.
			 */
			if (isset($settings->_ldapBaseDN)) {
				$ldapSearchAttribut = "uid=";
				$tmpDN = "uid=".$username.",".$settings->_ldapBaseDN;
			}

			/* Active directory has a different base dn */
			if (isset($settings->_ldapType)) {
				if ($settings->_ldapType==1) {
					$ldapSearchAttribut = "sAMAccountName=";
					$tmpDN = $username.'@'.$settings->_ldapAccountDomainName;
					// Add the following if authentication with an Active Dir doesn't work
					// See https://sourceforge.net/p/seeddms/discussion/general/thread/19c70d8d/
					// and http://stackoverflow.com/questions/6222641/how-to-php-ldap-search-to-get-user-ou-if-i-dont-know-the-ou-for-base-dn
					ldap_set_option($ds, LDAP_OPT_REFERRALS, 0);
				}
			}

			// Ensure that the LDAP connection is set to use version 3 protocol.
			// Required for most authentication methods, including SASL.
			ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3);

			// try an authenticated/anonymous bind first.
			// If it succeeds, get the DN for the user and use it for an authentication
			// with the users password.
			$bind = false;
			if (!empty($settings->_ldapBindDN)) {
				$bind = @ldap_bind($ds, $settings->_ldapBindDN, $settings->_ldapBindPw);
			} else {
				$bind = @ldap_bind($ds);
			}
			$dn = false;
			/* If bind succeed, then get the dn of the user. If a filter
			 * is set, it will be used to allow only those users to log in
			 * matching the filter criteria. Depending on the type of server, 
			 * (AD or regular LDAP), the search attribute is already set to
			 * 'sAMAccountName=' or 'uid='. All other filters are ANDed.
			 * A common filter is '(mail=*)' to ensure a user has an email
			 * address.
			 */
			if ($bind) {
				if (!empty($settings->_ldapFilter)) {
					$search = ldap_search($ds, $settings->_ldapBaseDN, "(&(".$ldapSearchAttribut.$username.")".$settings->_ldapFilter.")");
				} else {
					$search = ldap_search($ds, $settings->_ldapBaseDN, $ldapSearchAttribut.$username);
				}
				if (!is_bool($search)) {
					$info = ldap_get_entries($ds, $search);
					if (!is_bool($info) && $info["count"]>0) {
						$dn = $info[0]['dn'];
					}
				}
			}

			/* If the previous bind failed, try it with the users creditionals
			 * by simply setting $dn to a guessed dn (see above)
			 * Don't do this if a filter is set because users filtered out
			 * may still be able to authenticate, because $tmpDN could be a
			 * valid DN which do not match the filter criteria.
			 * Example: if baseDN is 'dc=seeddms,dc=org' and the
			 * user 'test' logs in, then $tmpDN will be 'uid=test,dc=seeddms,dc=org'
			 * If that user was filtered out, because filter was set to '(mail=*)'
			 * and the user doesn't have a mail address, then $dn will not be
			 * set and $tmpDN will be used instead, allowing a successfull bind.
			 */
			if (is_bool($dn) && empty($settings->_ldapFilter)) {
				$dn = $tmpDN;
			}

			/* Without a dn don't even try to bind. It won't work anyway */
			if(!$dn) {
				ldap_close($ds);
				return null;
			}

			/* Check if user already exists in the database. Return with an error
			 * only if the sql statements fails, but not if no user was found.
			 */
			$user = $dms->getUserByLogin($username);
			if($user === false) {
				ldap_close($ds);
				return false;
			}

			/* Now do the actual authentication of the user */
			$bind = @ldap_bind($ds, $dn, $password);
			if (!$bind) {
				ldap_close($ds);
				return null;
			}

			// Successfully authenticated. Now check to see if the user exists within
			// the database. If not, add them in if _restricted is not set,
			// but do not add their password.
			if (!$settings->_restricted) {
				// Retrieve the user's LDAP information.
				if (isset($settings->_ldapFilter) && strlen($settings->_ldapFilter) > 0) {
					$search = ldap_search($ds, $settings->_ldapBaseDN, "(&(".$ldapSearchAttribut.$username.")".$settings->_ldapFilter.")");
				} else {
					$search = ldap_search($ds, $settings->_ldapBaseDN, $ldapSearchAttribut.$username);
				}

				if (!is_bool($search)) {
					$info = ldap_get_entries($ds, $search);

					if (!is_bool($info) && $info["count"]==1 && $info[0]["count"]>0) {
						if (is_null($user)) {
							$user = $this->addUser($username, $info[0]);
						} else {
							$this->updateUser($user, $info[0]);
						}
						/*
						$this->syncGroups($user, [
							'count'=>4,
							0=>'CN=group1,OU=groups,DC=seeddms,DC=org',
							1=>'CN=group2,OU=groups,DC=seeddms,DC=org',
							2=>'CN=group3,OU=groups,DC=seeddms,DC=org',
							3=>'CN=group4,OU=groups,DC=seeddms,DC=org'
						]
						);
						 */
						if(!empty($settings->_ldapGroupField) && !empty($info[0][$settings->_ldapGroupField])) {
							$this->syncGroups($user, $info[0][$settings->_ldapGroupField]);
						}
					}
				}
			}
			ldap_close($ds);

			return $user;
		} else {
			return false;
		}
	} /* }}} */
}
