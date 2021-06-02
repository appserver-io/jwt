<?php

/**
 * TechDivision\Project\Jwt\Security\JwtPrincipalDecorator
 *
 * @author    Tim Wagner <t.wagner@techdivision.com>
 * @copyright 2021 TechDivision GmbH <info@techdivision.com>
 * @link      https://www.techdivision.com
 */

namespace AppserverIo\Jwt\Security;

use AppserverIo\Lang\String;
use AppserverIo\Collections\ArrayList;
use AppserverIo\Psr\Security\PrincipalInterface;
use AppserverIo\Appserver\ServletEngine\Security\GenericPrincipal;

/**
 * JWT Docrator for a GenericPrincipal object.
 *
 * @author    Tim Wagner <t.wagner@techdivision.com>
 * @copyright 2021 TechDivision GmbH <info@techdivision.com>
 * @link      https://www.techdivision.com
 */
class JwtPrincipalDecorator implements PrincipalInterface, \JsonSerializable
{

    /**
     * The principal to be decorated.
     *
     * @var \AppserverIo\Appserver\ServletEngine\Security\GenericPrincipal
     */
    protected $principal;

    /**
     * Initialize the decorator with the principal to be decorated.
     *
     * @param \AppserverIo\Appserver\ServletEngine\Security\GenericPrincipal $principal The principal to be decorated
     */
    public function __construct(GenericPrincipal $principal)
    {
        $this->principal = $principal;
    }

    /**
     * Return's the decorated principal.
     *
     * @return \AppserverIo\Appserver\ServletEngine\Security\GenericPrincipal The decorated principal
     */
    public function getPrincipal()
    {
        return $this->principal;
    }
    /**
     * Compare this SimplePrincipal's name against another Principal.
     *
     * @param \AppserverIo\Psr\Security\PrincipalInterface $another The other principal to compare to
     *
     * @return boolean TRUE if name equals $another->getName();
     */
    public function equals(PrincipalInterface $another)
    {
        return $this->getPrincipal()->equals($another);
    }

    /**
     * Returns the principals name as string.
     *
     * @return string The principal's name
     */
    public function __toString()
    {
        return $this->getPrincipal()->__toString();
    }

    /**
     * Return's the principals name as String.
     *
     * @return \AppserverIo\Lang\String The principal's name
     */
    public function getName()
    {
        return $this->getPrincipal()->getName();
    }

    /**
     * Return's the principal's username.
     *
     * @return \AppserverIo\Lang\String The username
     */
    public function getUsername()
    {
        return $this->getPrincipal()->getUsername();
    }

    /**
     * Return's the principal's password.
     *
     * @return \AppserverIo\Lang\String The password
     */
    public function getPassword()
    {
        return $this->getPrincipal()->getPassword();
    }

    /**
     * Return's the principal's roles.
     *
     * @return \AppserverIo\Collections\ArrayList The roles
     */
    public function getRoles()
    {
        return $this->getPrincipal()->getRoles();
    }

    /**
     * Return's the user principal instance that will be returned from the request.
     *
     * @return \AppserverIo\Psr\Security\PrincipalInterface The user principal
     */
    public function getUserPrincipal()
    {
        return $this->getPrincipal()->getUserPrincipal();
    }

    /**
     * Return's the actual login context instance.
     *
     * @return \AppserverIo\Psr\Security\Auth\Login\LoginContextInterface The login context instance
     */
    public function getLoginContext()
    {
        return $this->getPrincipal()->getLoginContext();
    }

    /**
     * Serializes the object to a value that can be serialized natively by json_encode().
     *
     * @return mixed The data which can be serialized by json_encode(), which is a value of any type other than a resource
     * @link http://php.net/JsonSerializable
     * @link http://php.net/manual/en/jsonserializable.jsonserialize.php
     */
    public function jsonSerialize()
    {

        // load the roles
        $roles = array();
        foreach ($this->getRoles() as $role) {
            $roles[] = $role->__toString();
        }

        // return the principal data as JSON serializable array
        return array(
            'username' => $this->getUsername()->__toString(),
            'mail'     => $this->getUserPrincipal()->getMail(),
            'roles'    => $roles
        );
    }

    /**
     * Initializes and returns a new instance with the data
     * of the passed claim which is a \stdClass instance.
     *
     * @param \stdClass $stdClass The \stdClass with the data to initialize the principal with
     *
     * @return \TechDivision\Project\Jwt\Security\JwtPrincipalDecorator The initialized decorator instance
     */
    public static function fromClaim(\stdClass $stdClass)
    {

        // initialize the username
        $username = new String($stdClass->username);

        // initialize the roles
        $roles = new ArrayList();
        foreach ($stdClass->roles as $role) {
            $roles->add(new String($role));
        }

        // initialize the username
        $username = new String($stdClass->username);

        $userPrincipal = new SsoPrincipal($username);
        $userPrincipal->fromArray(array('mail' => $stdClass->mail));

        // restore and return the generic principal decorator instance
        return new JwtPrincipalDecorator(new GenericPrincipal($username, null, $roles, $userPrincipal));
    }

    /**
     * Magic method that'll be invoked when someone tries to load an extenden attribute with a getter name
     *
     * @param string $name      The name of the invoked method
     * @param array  $arguments The method arguemnts
     *
     * @return mixed The value of the extended attribute
     * @see \TechDivision\Project\Jwt\Security\SsoPrincipal::getAttribute()
     */
    public function __call($name, $arguments)
    {
        return $this->principal->__call($name, $arguments);
    }
}
