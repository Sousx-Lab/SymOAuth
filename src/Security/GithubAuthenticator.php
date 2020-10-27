<?php
namespace App\Security;

use App\Entity\User;
use App\Repository\UserRepository;
use App\Security\Exception\NotVerifiedEmailException;
use League\OAuth2\Client\Token\AccessToken;
use Symfony\Component\HttpClient\HttpClient;
use League\OAuth2\Client\Provider\GithubResourceOwner;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;

class GithubAuthenticator extends AbstractOauthAuthenticator
{
    protected string $serviceName = 'github';
    

    public function getUserFromResourceOwner(ResourceOwnerInterface $githubUser, UserRepository $repository): ?User
    {
        if(!($githubUser instanceof GithubResourceOwner))
        {
            throw new \RuntimeException("Expecting GithubResourceOwner as the first parameter");
        }

        $user = $repository->findForOauth('github', $githubUser->getId(), $githubUser->getEmail());
        if($user && null === $user->getGithubId()){
            $user->setGithubId($githubUser->getId());
            $this->em->flush();
        }elseif(null === $user) {
            $user = new User();
            $user->setEmail($githubUser->getEmail());
            $user->setGithubId($githubUser->getId());
            $user->setUsername($githubUser->getName() ?? $githubUser->getNickname());
            $this->em->persist($user);
            $this->em->flush();
        }

        return $user;
    }
    
    public function getResourceOwnerFromCredentials(AccessToken $credentials): GithubResourceOwner
    {
        $githubUser = parent::getResourceOwnerFromCredentials($credentials);
        $response = HttpClient::create()->request(
            'GET',
            'https://api.github.com/user/emails',
            [
                'headers' => [
                    'authorization' => "token {$credentials->getToken()}"
                ]
            ]
        );
        $emails = json_decode($response->getContent(), true);
        foreach($emails as $email){
            if(true === $email['primary']  && true === $email['verified']){
                $data = $githubUser->toArray();
                $data['email'] = $email['email'];
                return new GithubResourceOwner($data);
            }
        }
        throw new NotVerifiedEmailException();
    }
}