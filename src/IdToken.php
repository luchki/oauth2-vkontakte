<?php

namespace Luchki\OAuth2\Client\Provider;

use League\OAuth2\Client\Token\AccessToken;

/**
 * @package Luchki\OAuth2\Client\Provider
 */
class IdToken {

    /**
     * @var array
     */
    private $_jwt = array();

    /**
     * IdToken constructor
     * @param AccessToken $token
     */
    public function __construct(AccessToken $token) {
        $values = $token->getValues();
        if (is_array($values) && array_key_exists('id_token', $values)) {
            $this->_jwt = self::_parse_jwt($values['id_token']);
        }
    }

    /**
     * Returns parsed payload of jwt
     * @param string $value Jwt
     * @return array|null
     */
    private static function _parse_jwt($value) {
        $result = array();
        $parts = explode('.', $value);
        if (count($parts) === 3) {
            $payload = base64_decode(strtr($parts[1], '-_', '+/'));
            $payload = json_decode($payload, true);
            if (is_array($payload )) { $result = $payload; }
        }
        return $result;
    }

    /**
     * Returns jwt field by key name
     * @param string $key Key name
     * @return mixed|null
     */
    private function _get_value($key) {
        return array_key_exists($key, $this->_jwt)
            ? $this->_jwt[$key] : null;
    }

    /**
     * Returns jwt field by keys in priority
     * @param string[] $keys Keys list
     * @return mixed|null
     */
    private function _get_value_by_keys($keys) {
        foreach ($keys as $key) {
            if ($value = $this->_get_value($key)) {
                return $value;
            }
        }
        return null;
    }

    /**
     * Returns user identifier
     * @return int|null
     */
    public function id() {
        return $this->_get_value_by_keys(array('sub', 'id', 'user_id'));
    }

    /**
     * Returns user's phone number
     * @return string|null
     */
    public function phone() {
        return $this->_get_value_by_keys(array('phone', 'phone_number'));
    }

    /**
     * Returns user's email
     * @return string|null
     */
    public function email() {
        return $this->_get_value('email');
    }

}
