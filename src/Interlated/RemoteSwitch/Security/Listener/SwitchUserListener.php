<?php
/**
 * Created by IntelliJ IDEA.
 * User: johnrobens
 * Date: 19/06/15
 * Time: 3:49 PM
 */


/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Interlated\RemoteSwitch\Security\Listener;

use Symfony\Component\Security\Core\Authentication\Token\PreAuthenticatedToken;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Interlated\RemoteSwitch\Security\Token\PreAuthenticatedSwitchUserToken;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManagerInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Role\SwitchUserRole;
use Symfony\Component\Security\Core\Exception\AuthenticationCredentialsNotFoundException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Event\SwitchUserEvent;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\Security\Http\SecurityEvents;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

/**
 * SwitchUserListener allows a user to impersonate another one temporarily
 * (like the Unix su command).
 *
 * @author Fabien Potencier <fabien@symfony.com>
 */
class SwitchUserListener implements ListenerInterface {
  private $securityContext;
  private $provider;
  private $userChecker;
  private $providerKey;
  private $accessDecisionManager;
  private $usernameParameter;
  private $role;
  private $logger;
  private $dispatcher;

  private $userKey;

  /**
   * Constructor.
   */
  public function __construct(SecurityContextInterface $securityContext, UserProviderInterface $provider, UserCheckerInterface $userChecker, $providerKey, AccessDecisionManagerInterface $accessDecisionManager, LoggerInterface $logger = NULL, $usernameParameter = '_switch_user', $role = 'ROLE_ALLOWED_TO_SWITCH', EventDispatcherInterface $dispatcher = NULL) {
    if (empty($providerKey)) {
      throw new \InvalidArgumentException('$providerKey must not be empty.');
    }

    $this->securityContext = $securityContext;
    $this->provider = $provider;
    $this->userChecker = $userChecker;
    $this->providerKey = $providerKey;
    $this->accessDecisionManager = $accessDecisionManager;
    $this->usernameParameter = $usernameParameter;
    $this->role = $role;
    $this->logger = $logger;
    $this->dispatcher = $dispatcher;

    $this->userKey = 'REMOTE_USER';
  }

  /**
   * Handles the switch to another user.
   *
   * @param GetResponseEvent $event A GetResponseEvent instance
   *
   * @throws \LogicException if switching to a user failed
   */
  public function handle(GetResponseEvent $event) {
    $request = $event->getRequest();

    if (!$request->get($this->usernameParameter)) {
      return;
    }

    if ('_exit' === $request->get($this->usernameParameter)) {
      $this->securityContext->setToken($this->attemptExitUser($request));
    }
    else {
      try {
        $this->securityContext->setToken($this->attemptSwitchUser($request));
      } catch (AuthenticationException $e) {
        throw new \LogicException(sprintf('Switch User failed: "%s"', $e->getMessage()));
      }
    }

    $request->query->remove($this->usernameParameter);
    $request->server->set('QUERY_STRING', http_build_query($request->query->all()));

    $response = new RedirectResponse($request->getUri(), 302);

    $event->setResponse($response);
  }

  /**
   * Attempts to switch to another user.
   *
   * @param Request $request A Request instance
   *
   * @return TokenInterface|null The new TokenInterface if successfully switched, null otherwise
   *
   * @throws \LogicException
   * @throws AccessDeniedException
   */
  private function attemptSwitchUser(Request $request) {
    $token = $this->securityContext->getToken();
    if ($token == null) {
      throw new AccessDeniedException("Login token is null in switch user (attemptSwitchUser).");
    }
    $originalToken = $this->getOriginalToken($token);

    // Check to see if we are already masquerading. Deemed to be true if you have ROLE of type SwitchUserRole
    if (FALSE !== $originalToken) {
      if ($token->getUsername() === $request->get($this->usernameParameter)) {
        return $token;
      }
      else {
        throw new \LogicException(sprintf('You are already switched to "%s" user.', $token->getUsername()));
      }
    }

    // Does the person have the "can masquerade" role.
    if (FALSE === $this->accessDecisionManager->decide($token, array($this->role))) {
      if (NULL !== $this->logger) {
        $this->logger->alert("Switching user, permission denied: " . $token . ' role: ' . $this->role);
      }
      throw new AccessDeniedException();
    }

    $username = $request->get($this->usernameParameter);

    if (NULL !== $this->logger) {
      $this->logger->info(sprintf('Attempt to switch to user "%s"', $username));
    }

    $user = $this->provider->loadUserByUsername($username);
    $this->userChecker->checkPostAuth($user);

    $roles = $user->getRoles();
    $roles[] = new SwitchUserRole('ROLE_PREVIOUS_ADMIN', $this->securityContext->getToken());

    $credentials = null;

    // See PreAuthenticatedToken.php > checks roles
    $preAuthenticatedData = $this->getPreAuthenticatedData($request);
    $newToken = new PreAuthenticatedSwitchUserToken($user, $credentials, $this->providerKey, $roles, $preAuthenticatedData);

    if (NULL !== $this->dispatcher) {
      $switchEvent = new SwitchUserEvent($request, $newToken->getUser());
      $this->dispatcher->dispatch(SecurityEvents::SWITCH_USER, $switchEvent);
    }

    return $newToken;
  }

  /**
   * Attempts to exit from an already switched user.
   *
   * @param Request $request A Request instance
   *
   * @return TokenInterface The original TokenInterface instance
   *
   * @throws AuthenticationCredentialsNotFoundException
   */
  private function attemptExitUser(Request $request) {
    if (FALSE === $original = $this->getOriginalToken($this->securityContext->getToken())) {
      throw new AuthenticationCredentialsNotFoundException('Could not find original Token object.');
    }

    if (NULL !== $this->dispatcher) {
      $switchEvent = new SwitchUserEvent($request, $original->getUser());
      $this->dispatcher->dispatch(SecurityEvents::SWITCH_USER, $switchEvent);
    }

    return $original;
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
}
