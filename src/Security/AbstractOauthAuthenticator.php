<?php

namespace App\Security;

use App\Entity\User;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use League\OAuth2\Client\Token\AccessToken;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Routing\RouterInterface;
use KnpU\OAuth2ClientBundle\Client\OAuth2Client;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use App\Security\Exception\UserAuthenticatedException;
use App\Security\Exception\UserOauthNotFoundException;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Security\Core\User\UserInterface;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use Symfony\Component\Security\Http\Util\TargetPathTrait;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use KnpU\OAuth2ClientBundle\Security\Authenticator\SocialAuthenticator;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

abstract class AbstractOauthAuthenticator extends SocialAuthenticator
{
    use TargetPathTrait;
    protected string $serviceName = '';
    private Security $security;
    private RouterInterface $router;
    private ClientRegistry $clientRegistry;
    private UserRepository $repository;
    protected EntityManagerInterface $em;


    public function __construct(Security $security, RouterInterface $router, ClientRegistry $clientRegistry, 
    EntityManagerInterface $em) {

        $this->security = $security;
        $this->clientRegistry = $clientRegistry;
        $this->router = $router;
        $this->em = $em;
        
    }

    /**
     * @param Request $request
     * @return void
     */
    public function supports(Request $request)
    {
        if('' === $this->serviceName){
            throw new \Exception("You must set a \$serviceName property (for instance 'github', 'facebook')");
        }
        return 'oauth_check' === $request->attributes->get('_route') && $request->get('service') === $this->serviceName;

    }

    /**
     * @param Request $request
     * @param AuthenticationException $authException
     * @return void
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        return new RedirectResponse($this->router->generate('app_login'));

    }

    /**
     * @param Request $request
     * @return void
     */
    public function getCredentials(Request $request)
    {
        return $this->fetchAccessToken($this->getClient());

    }

    /**
     * @param AccessToken $credentials
     * @throws AuthenticationException
     * @return UserInterface|null
     */
    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        $resourceOwner = $this->getResourceOwnerFromCredentials($credentials);
        $user = $this->security->getUser();
        if($user){
            throw new UserAuthenticatedException($user, $resourceOwner);
        }

        $repository = $this->em->getRepository(User::class);
        $user = $this->getUserFromResourceOwner($resourceOwner, $repository);
        if(null === $user){
            throw new UserOauthNotFoundException($resourceOwner);
        }
        
        return $user;
        
    }

    /**
     * @return Response|null
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        if($exception instanceof UserOauthNotFoundException){
            return new RedirectResponse($this->router->generate('app_login'));
        }

        if ($exception instanceof UserAuthenticatedException) {
            return new RedirectResponse($this->router->generate('home'));
        }

        if($request->hasSession()){
            $request->getSession()->set(Security::AUTHENTICATION_ERROR, $exception);
        }
        return new RedirectResponse($this->router->generate('app_login'));
    }

    /**
     * @return Response|null
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $providerKey)
    {
        
        if($targetPath = $this->getTargetPath($request->getSession(), $providerKey)){
            return new RedirectResponse($targetPath);
        }
        return new RedirectResponse($this->router->generate('home'));
    }

    /**
     * @param AccessToken $credentials
     * @return ResourceOwnerInterface
     */
    protected function getResourceOwnerFromCredentials(AccessToken $credentials): ResourceOwnerInterface
    {
        return $this->getClient()->fetchUserFromToken($credentials);
    }  

    /**
     * @param ResourceOwnerInterface $resourceOwner
     * @param UserRepository $repository
     * @return User|null
     */
    protected function getUserFromResourceOwner(ResourceOwnerInterface $resourceOwner, UserRepository $repository): ?User
    {
        return null;
    }

    /**
     * @return OAuth2Client
     */
    protected function getClient() :OAuth2Client
    {
       return $this->clientRegistry->getClient($this->serviceName);
    }
    
}