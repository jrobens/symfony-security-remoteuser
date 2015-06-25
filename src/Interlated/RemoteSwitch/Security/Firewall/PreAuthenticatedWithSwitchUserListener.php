<?php

namespace Interlated\RemoteSwitch\Security\Firewall;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Role\SwitchUserRole;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Interlated\RemoteSwitch\Security\Token\PreAuthenticatedSwitchUserToken;
use Symfony\Component\Security\Core\Authentication\Token\PreAuthenticatedToken;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;
use Symfony\Component\Security\Http\SecurityEvents;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

/**
 * See AbstractPreAuthenticatedListener
 *
 * Created by IntelliJ IDEA.
 * User: johnrobens
 * Date: 23/06/15
 * Time: 9:01 AM
 */

class PreAuthenticatedWithSwitchUserListener implements ListenerInterface {
  protected $logger;
  private $securityContext;
  private $authenticationManager;
  private $providerKey;
  private $dispatcher;
  private $userKey;

  // Probably should be TokenInterface, but sticking to the existing AbstractPreAuthenticatedListener



  public function __construct(SecurityContextInterface $securityContext, AuthenticationManagerInterface $authenticationManager, $providerKey, $userKey = 'REMOTE_USER', LoggerInterface $logger = null, EventDispatcherInterface $dispatcher = null)
  {
    $this->securityContext = $securityContext;
    $this->authenticationManager = $authenticationManager;
    $this->providerKey = $providerKey;
    $this->logger = $logger;
    $this->dispatcher = $dispatcher;
    $this->userKey = $userKey;
  }

  /**
   * {@inheritdoc}
   */
  protected function getPreAuthenticatedData(Request $request)
  {
    if (!$request->server->has($this->userKey)) {
      throw new BadCredentialsException(sprintf('User key was not found: %s', $this->userKey));
    }

    return array($request->server->get($this->userKey), null);
  }

  /**
   * Handles pre-authentication.
   *
   * @param GetResponseEvent $event A GetResponseEvent instance
   */
  final public function handle(GetResponseEvent $event)
  {
    $request = $event->getRequest();

    if (null !== $this->logger) {
      $this->logger->debug(sprintf('Checking secure context token: %s', $this->securityContext->getToken()));
    }

    try {
      list($user, $credentials) = $this->getPreAuthenticatedData($request);
    } catch (BadCredentialsException $exception) {
      $this->clearToken($exception);

      return;
    }

    if (null !== $token = $this->securityContext->getToken()) {
      if ($token instanceof PreAuthenticatedToken && $this->providerKey == $token->getProviderKey() && $token->isAuthenticated() && $token->getUsername() === $user) {
        return;
      }
      // Switch user token. Check the original token.
      if ($token instanceof PreAuthenticatedSwitchUserToken && $this->providerKey == $token->getProviderKey() && $token->isAuthenticated() && $token->getOriginalUsername() === $user) {
        return;
      }
    }

    if (null !== $this->logger) {
      $this->logger->debug(sprintf('Trying to pre-authenticate user "%s"', $user));
    }

    try {
      $token = $this->authenticationManager->authenticate(new PreAuthenticatedToken($user, $credentials, $this->providerKey));

      if (null !== $this->logger) {
        $this->logger->info(sprintf('Authentication success: %s', $token));
      }
      $this->securityContext->setToken($token);

      if (null !== $this->dispatcher) {
        $loginEvent = new InteractiveLoginEvent($request, $token);
        $this->dispatcher->dispatch(SecurityEvents::INTERACTIVE_LOGIN, $loginEvent);
      }
    } catch (AuthenticationException $failed) {
      $this->clearToken($failed);
    }
  }

  /**
   * Clears a PreAuthenticatedToken for this provider (if present).
   *
   * @param AuthenticationException $exception
   */
  private function clearToken(AuthenticationException $exception)
  {
    $token = $this->securityContext->getToken();
    if ($token instanceof PreAuthenticatedToken && $this->providerKey === $token->getProviderKey()) {
      $this->securityContext->setToken(null);

      if (null !== $this->logger) {
        $this->logger->info(sprintf('Cleared security context due to exception: %s', $exception->getMessage()));
      }
    }
  }

  /**
   * Gets the original Token from a switched one.
   *
   * @param TokenInterface $token A switched TokenInterface instance
   *
   * @return TokenInterface|false The original TokenInterface instance, false if the current TokenInterface is not switched
   */
  private function getOriginalToken(TokenInterface $token) {
    foreach ($token->getRoles() as $role) {
      if ($role instanceof SwitchUserRole) {
        return $role->getSource();
      }
    }

    return FALSE;
  }

}