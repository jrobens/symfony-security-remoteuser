<?php
/**
 * Created by IntelliJ IDEA.
 * User: johnrobens
 * Date: 23/06/15
 * Time: 1:32 PM
 */

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Interlated\RemoteSwitch\Security\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\SecurityFactoryInterface;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\DefinitionDecorator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
* RemoteUserFactory creates services for REMOTE_USER based authentication.
 *
 * @author Fabien Potencier <fabien@symfony.com>
 * @author Maxime Douailin <maxime.douailin@gmail.com>
 */
class RemoteUserSwitchFactory implements SecurityFactoryInterface {


  public function create(ContainerBuilder $container, $id, $config, $userProvider, $defaultEntryPoint)
  {
    $providerId = 'security.authentication.provider.pre_authenticated.'.$id;
    $container
      ->setDefinition($providerId, new DefinitionDecorator('security.authentication.provider.pre_authenticated'))
      ->replaceArgument(0, new Reference($userProvider))
      ->addArgument($id)
    ;

    $listenerId = 'security.authentication.listener.remote_user_switch.'.$id;
    $listener = $container->setDefinition($listenerId, new DefinitionDecorator('security.authentication.listener.remote_user_switch'));
    $listener->replaceArgument(2, $id);
    $listener->replaceArgument(3, $config['user']);

    return array($providerId, $listenerId, $defaultEntryPoint);
  }

  public function getPosition()
  {
    return 'pre_auth';
  }

  public function getKey()
  {
    return 'remote_user_switch';
  }

  public function addConfiguration(NodeDefinition $node)
  {
    $node
      ->children()
      ->scalarNode('provider')->end()
      ->scalarNode('user')->defaultValue('REMOTE_USER')->end()
      ->end()
    ;
  }
}
