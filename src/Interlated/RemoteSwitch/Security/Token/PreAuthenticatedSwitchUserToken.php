<?php
/**
 * Created by IntelliJ IDEA.
 * User: johnrobens
 * Date: 24/06/15
 * Time: 8:19 AM
 */

namespace Interlated\RemoteSwitch\Security\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

class PreAuthenticatedSwitchUserToken extends AbstractToken {
  private $credentials;
  private $providerKey;
  private $original_username;

  /**
   * Constructor.
   */
  public function __construct($user, $credentials, $providerKey, array $roles = array(), $preAuthenticatedData)
  {
    parent::__construct($roles);

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

  /**
   * Returns the provider key.
   *
   * @return string The provider key
   */
  public function getProviderKey()
  {
    return $this->providerKey;
  }

  public function getOriginalUsername() {
    return $this->original_username;
  }

  /**
   * {@inheritdoc}
   */
  public function getCredentials()
  {
    return $this->credentials;
  }

  /**
   * {@inheritdoc}
   */
  public function eraseCredentials()
  {
    parent::eraseCredentials();

    $this->credentials = null;
  }

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


} 