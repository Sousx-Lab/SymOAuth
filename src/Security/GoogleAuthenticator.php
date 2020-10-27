<?php
namespace App\Security;

use App\Entity\User;
use App\Repository\UserRepository;
use App\Security\AbstractOauthAuthenticator;
use App\Security\Exception\NotVerifiedEmailException;
use League\OAuth2\Client\Provider\GoogleUser;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;

class GoogleAuthenticator extends AbstractOauthAuthenticator
{
    
    protected string $serviceName = 'google';

    public function getUserFromResourceOwner(ResourceOwnerInterface $googleUser, UserRepository $repository): ?User
    {
        if(!($googleUser instanceof GoogleUser)){
            throw new \RuntimeException('Expecting GoogleUser as the first parameter');
        }

        if(true !== ($googleUser->toArray()['email_verified'] ?? null)){
            throw new NotVerifiedEmailException();
        }
        $user = $repository->findForOauth('google', $googleUser->getId(), $googleUser->getEmail());
        if($user && null === $user->getGoogleId()){
            $user->setGoogleId($googleUser->getId());
            $this->em->flush();
        }elseif(null === $user) {
            $user = new User();
            $user->setEmail($googleUser->getEmail());
            $user->setGoogleId($googleUser->getId());
            $user->setUsername($googleUser->getName() ?? $googleUser->getEmail());
            $this->em->persist($user);
            $this->em->flush();
        }

        return $user;
    }
}