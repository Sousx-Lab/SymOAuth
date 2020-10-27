<?php
namespace App\Controller\Security;


use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

class SecurityController extends AbstractController
{
    private const SCOPES = [
        'github' => ['user:email'],
        'google' => [],
    ];

    /**
     * @Route("/login", name="app_login")
     */
    public function login(AuthenticationUtils $authenticationUtils): Response
    {
        // if ($this->getUser()) {
        //     return $this->redirectToRoute('target_path');
        // }

        // get the login error if there is one
        $error = $authenticationUtils->getLastAuthenticationError();
        // last username entered by the user
        $lastUsername = $authenticationUtils->getLastUsername();

        return $this->render('security/login.html.twig', ['last_username' => $lastUsername, 'error' => $error]);
    }
    
    /**
     * @param ClientRegistry $clientRegistry
     * @Route("oauth/{service}", name="oauth_connect", requirements={"service": "[a-z0-9\-]*"})
     * @return void
     */
    public function OauthConnect(ClientRegistry $clientRegistry, string $service): RedirectResponse
    {
        if(!in_array($service, array_keys(self::SCOPES))){
            throw new AccessDeniedException();
        }
        
        return $clientRegistry->getClient($service)->redirect(self::SCOPES[$service], ['a' => 1]);
    }

    /**
     * @Route("/oauth/check/{service}", name="oauth_check")
     */
    public function check(): Response
    {
        return new Response();
    }
    
    /**
     * @Route("/logout", name="app_logout")
     */
    public function logout()
    {
        throw new \LogicException('This method can be blank - it will be intercepted by the logout key on your firewall.');
    }
}
