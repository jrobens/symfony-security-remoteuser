<?php

// src/UnswCamsBundle/Security/User/WebserviceUserProvider.php

namespace Interlated\RemoteSwitch\Security\User;

use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Interlated\RemoteSwitch\Entity\Person;
use Doctrine\ORM\EntityManager;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;

class WebserviceUserProvider implements UserProviderInterface {
  protected $entityManager;
  protected $logger;

  /**
   * 
   * @param LoggerInterface $logger
   * @param EntityManager $em
   */
  public function setEntityManager(LoggerInterface $logger, EntityManager $em) {
    $this->logger = $logger;
    $this->entityManager = $em;
  }

  /**
   * 
   * @param string $zNumber
   * @return Person
   * @throws UsernameNotFoundException
   */
  public function loadUserByUsername($zNumber) {
    // Split off zyyy@AD..
    $person_parts = explode('@', $zNumber);

    // Made z part of the data.
    // Also take off the z bit.
    //$z_clean= ltrim ($person_parts[0], 'z');

    $this->logger->debug("Logging in using z-number " . $person_parts[0]);

    # Find the person
    $person = $this->entityManager->getRepository('InterlatedRemoteSwitch:Person')
        ->find($person_parts[0]);

    if ($person) {
      $this->logger->debug("Logged in, finding person: " . $person->getZNumber());
      return $person;
    }

    throw new UsernameNotFoundException(
      sprintf('Username "%s" does not exist.', $zNumber)
    );
  }

  /**
   *
   * @param \Symfony\Component\Security\Core\User\UserInterface $person
   * @throws \Symfony\Component\Security\Core\Exception\UnsupportedUserException
   * @internal param \Symfony\Component\Security\Core\User\UserInterface $user
   * @return Person
   */
  public function refreshUser(UserInterface $person) {
    if (!$person instanceof Person) {
      throw new UnsupportedUserException(
        sprintf('Instances of "%s" are not supported.', get_class($person))
      );
    }

    return $this->loadUserByUsername($person->getZNumber());
  }

  /**
   * 
   * @param type $class
   * @return type
   */
  public function supportsClass($class) {
    return $class === 'Interlated\RemoteSwitch\Entity\Person';
  }

}
