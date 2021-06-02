<?php

/**
 * TechDivision\Project\Jwt\Security\SsoPrincipal
 *
 * @author    Tim Wagner <t.wagner@techdivision.com>
 * @copyright 2018 TechDivision GmbH <info@techdivision.com>
 * @link      https://www.techdivision.com
 */

namespace AppserverIo\Jwt\Security;

use AppserverIo\Appserver\ServletEngine\Security\SimplePrincipal;

/**
 * This class provides a simple SSO principal implementation.
 *
 * @author    Tim Wagner <t.wagner@techdivision.com>
 * @copyright 2018 TechDivision GmbH <info@techdivision.com>
 * @link      https://www.techdivision.com
 */
class SsoPrincipal extends SimplePrincipal implements \JsonSerializable
{

    /**
     * The array with the principal attributes.
     *
     * @var array
     */
    protected $attributes = array();

    /**
     * Initializes the principal with the array with the extended LDAP attributes.
     *
     * @param array $attributes The extended LDAP attributes
     *
     * @return void
     */
    public function fromArray(array $attributes)
    {
        $this->attributes = array_merge($this->attributes, $attributes);
    }

    /**
     * Magic method that'll be invoked when someone tries to load an extenden attribute with a getter name
     *
     * @param string $name      The name of the invoked method
     * @param array  $arguments The method arguemnts
     *
     * @return mixed The value of the extended attribute
     * @see \TechDivision\Project\Jwt\Security\SsoPrincipal::geAttribute()
     */
    public function __call($name, $arguments)
    {

        // try to extract the name of the extended attribute from the method
        $propertyName = strtolower(str_replace(array('is', 'has', 'get'), null, $name));

        // try to load the attribute with the extracted name
        return $this->getAttribute($propertyName);
    }

    /**
     * Returns the extendend LDAP attribute with the passed name.
     *
     * @param string $name The LDAP attribute to return
     *
     * @return mixed The value of the extended attribute
     */
    public function getAttribute($name)
    {

        // query whether or not the extended property exists
        if (isset($this->attributes[$name])) {
            return $this->attributes[$name];
        }
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
        return $this->attributes;
    }
}
