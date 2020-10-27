<?php
namespace App\Security\Exception;

use App\Entity\User;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

class UserAuthenticatedException extends AuthenticationException
{
    private User $user;
    private ResourceOwnerInterface $resouceOwner;

    public function __construct(User $user, ResourceOwnerInterface $resourceOwner) {
        $this->user = $user;
        $this->resouceOwner = $resourceOwner;
    }

    public function getUser() :User 
    {
        return $this->user;
    }

    public function getResourceOwner() :ResourceOwnerInterface
    {
        return $this->resouceOwner;
    }
}