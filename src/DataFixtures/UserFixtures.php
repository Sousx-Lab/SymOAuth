<?php

namespace App\DataFixtures;

use App\Entity\User;
use Doctrine\Persistence\ObjectManager;
use Doctrine\Bundle\FixturesBundle\Fixture;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;

class UserFixtures extends Fixture
{
    private UserPasswordEncoderInterface $passwordEncoder;

    public function __construct(UserPasswordEncoderInterface $passwordEncoder) {
        $this->passwordEncoder = $passwordEncoder;
    }

    public function load(ObjectManager $manager)
    {
        
        for($u = 0; $u <= 5; $u++){
            $user = new User();
            $user->setEmail("john". $u . "@doe.fr");
            $user->setPassword($this->passwordEncoder->encodePassword($user, "000". $u));
            $user->setUsername("John".$u);
        $manager->persist($user);
      }
        $manager->flush();
    }
}