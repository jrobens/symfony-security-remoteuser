<?php

namespace Interlated\RemoteSwitch\Listener;

use Doctrine\ORM\EntityManager;
use Exception;
use Symfony\Component\EventDispatcher\ContainerAwareEventDispatcher;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;
use Symfony\Component\Security\Http\Event\SwitchUserEvent;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\HttpKernel\Debug\TraceableEventDispatcher;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Event\AuthenticationFailureEvent;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;

/**
 * Class SecurityListener
 * @package Interlated\RemoteSwitch\Listener
 *
 * Sets the semester as a session variable.
 *
 * Bottom http://symfony.com/doc/2.5/best_practices/security.html No annotations in 2.3
 * http://symfony.com/doc/2.3/best_practices/security.html
 *
 * Security users the entity provider - chapter 86 of 2.3 manual.
 *
 * Chapter 98, using pre-authenticated security firewalls.
 *
 * LDAP with active directory - http://stackoverflow.com/questions/9818954/symfony2-authentication-with-active-directory
 *
 * When are user roles loaded - http://stackoverflow.com/questions/13798662/when-are-user-roles-refreshed-and-how-to-force-it
 *
 * Symfony2: use both LDAP (Active directory) and DB for user authentication
 * http://stackoverflow.com/questions/22501134/symfony2-use-both-ldap-active-directory-and-db-for-user-authentication
 *
 * If your company uses a user login method not supported by Symfony, you can develop your own user provider and your own authentication provider.
 * arguments: ['@security.authorization_checker', '@session', '@doctrine.orm.entity_manager', '@router', '@traceable_event_dispatcher']
 * arguments: ['@security.context', '@session', '@doctrine.orm.entity_manager', '@router', '@event_dispatcher']
 * "security.authentication.failure"
 *
 * 201412
 * @author John Robens <jrobens@interlated.com.au>
 */
class SecurityListener {
  protected $session;
  protected $security;
  protected $em;
  protected $router;
  protected $dispatcher;

  public function __construct(
      AuthorizationCheckerInterface $security, 
      Session $session, 
      EntityManager $em, 
      UrlGeneratorInterface $router,
      EventDispatcherInterface $dispatcher
     // TraceableEventDispatcher $dispatcher
     // ContainerAwareEventDispatcher $dispatcher
  ) {
    $this->security = $security;
    $this->session = $session;
    $this->em = $em;
    $this->router = $router;
    $this->dispatcher = $dispatcher;
  }

  /**
   * 
   * @param AuthenticationFailureEvent $event
   * @throws AuthenticationException
   */
  public function onAuthenticationFailure(AuthenticationFailureEvent $event) {
    throw new  AuthenticationException($event->getAuthenticationException());
  }
  
  /**
   * Set default current semester in session when logging in.
   * 
   * @param InteractiveLoginEvent $event
   */
  public function onSecurityInteractiveLogin(InteractiveLoginEvent $event) {
    // Set currentSemester variable on initial log in only.
    if (null === $this->session->get('currentSemester')) {
      // Load the current semester into the session as a default.   No logger and no redirect here.
      $currentSemester = $this->em->getRepository('InterlatedRemoteSwitch:Semester')->currentSemester();

      $this->session->set('currentSemester', $currentSemester->getId());
    }
  }

  /**
   * Fired on switch user (masquerade).
   * Forward users to a switch user response handler.
   * 
   * @param SwitchUserEvent $event
   */
  public function onSecuritySwitchUser(SwitchUserEvent $event) {
    $this->dispatcher->addListener(KernelEvents::RESPONSE, array($this, 'onSwitchUserResponse'));
  }

  /**
   * Route switch user events to default controller action.
   * 
   * @param FilterResponseEvent $event
   */
  public function onSwitchUserResponse(FilterResponseEvent $event) {
    $response = new RedirectResponse($this->router->generate('interlated_remoteswitch_default_index'));
    $event->setResponse($response);
  }

}
