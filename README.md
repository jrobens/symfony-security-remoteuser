# symfony-security-remoteuser
The Symfony 2 PreAuthenticatedAuthenticationProvider doesn't handle the switch user (masquerade) functionality.

This fix involves adapting AbstractPreAuthenticatedListener to check for the existence of the standard token that matches the logged in user, and if not a customised token that has stored the logged in user, but is attached to the 'switched to' userid.

This is the important (non copied) part of the code:

```if (null !== $token = $this->securityContext->getToken()) {
  if ($token instanceof PreAuthenticatedToken && $this->providerKey == $token->getProviderKey() && $token->isAuthenticated() && $token->getUsername() === $user) {
    return;
  }
  // Switch user token. Check the original token.
  if ($token instanceof PreAuthenticatedSwitchUserToken && $this->providerKey == $token->getProviderKey() && $token->isAuthenticated() && $token->getOriginalUsername() === $user) {
    return;
  }
}
```

The token stores the logged in user and returns it with getOriginalUsername.

Store the existing authentication data (passed in $preAuthenticatedData)

/**
 * Constructor.
 */
public function __construct($user, $credentials, $providerKey, array $roles = array(), $preAuthenticatedData) { parent::__construct($roles);

if (empty($providerKey)) {
  throw new \InvalidArgumentException('$providerKey must not be empty.');
}

$this->setUser($user);
$this->credentials = $credentials;
$this->providerKey = $providerKey;

if (!is_array($preAuthenticatedData) && count($preAuthenticatedData) > 0) {
  throw new \InvalidArgumentException('No preauthenticated data. Must have the server login credentials.');

}
$this->original_username = $preAuthenticatedData[0];

if ($roles) {
  $this->setAuthenticated(true);
}
}

Getter

public function getOriginalUsername() {
  return $this->original_username;
}
Stash changes

/**
 * {@inheritdoc}
 */
public function serialize()
{
  return serialize(array($this->credentials, $this->providerKey, $this->original_username, parent::serialize()));
}

/**
 * {@inheritdoc}
 */
 public function unserialize($str)
 {
   list($this->credentials, $this->providerKey, $this->original_username, $parentStr) = unserialize($str);
   parent::unserialize($parentStr);
 }
These changes fit into the context of broader customisation of the Symfony security system. The source code for this is in github.

### services.yml

Set account.security_listener, security.authentication.switchuser_listener and security.authentication.listener.remote_user_switch

This is in addition to the expected user provider.

### security.yml

Use this security provider

secured_area:
  switch_user: { role: ROLE_ALLOWED_TO_SWITCH, parameter: _masquerade }
  pattern:    ^/

  remote_user_switch:
    provider: webservice_user_provider

### Check that the user provider loads the backing data for your user.

### Install security files.

* RemoteUserSwitchFactory.php: defines the listener to handle the authentication events.
* PreAuthenticatedWithSwitchUserListener.php: our special authentication logic. SwitchUserListener.php: handles the switch user event.
* PreAuthenticatedSwitchUserToken.php: token to store the logged in user as secondary data.
* WebserviceUser.php: our user data entity
* WebserviceUserProvider.php: queries for user data.